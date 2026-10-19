import asyncio
import gc
import json
from contextlib import asynccontextmanager
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import anyio
import psycopg
import pytest
from PIL import Image
from psycopg import conninfo
from pydantic import ValidationError
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

import openai

from app import agent


def tool_call(call_id: str, name: str, arguments: dict) -> SimpleNamespace:
    function = SimpleNamespace(name=name, arguments=json.dumps(arguments))
    return SimpleNamespace(id=call_id, function=function,
                           model_dump=lambda: {"id": call_id, "type": "function",
                                               "function": {"name": name, "arguments": json.dumps(arguments)}})


class FakeLLM:
    """Scripted LLM. `turns` lists the tool calls per turn (an empty list = model finishes);
    with turns=None it asks for two tool calls per turn forever, so only the caps can stop it."""

    def __init__(self, logged: list, turns: list[list] | None = None, verdict: str = "inconclusive",
                 fail_on_turn: int | None = None, slow_on_turn: int | None = None,
                 unparsable_report: bool = False, slow_report: bool = False,
                 failure: BaseException | None = None, report_errors: list[Exception] | None = None,
                 turn_errors: list[Exception] | None = None, findings: list[dict] | None = None) -> None:
        self.logged = logged
        self.findings = findings
        self.turns = turns
        self.verdict = verdict
        self.fail_on_turn = fail_on_turn
        self.slow_on_turn = slow_on_turn
        self.unparsable_report = unparsable_report
        self.slow_report = slow_report
        self.failure = failure or openai.APITimeoutError(request=None)
        self.report_errors = list(report_errors or [])  # raised by successive report attempts, then success
        self.report_attempts = 0
        self.turn_errors = list(turn_errors or [])  # raised by successive LLM-turn attempts, then normal replies
        self.turn_attempts = 0
        self.client_options: dict | None = None
        self.report_options: dict | None = None
        self.turn = 0
        self.synthesis_input: dict | None = None
        self.models: list[str] = []  # the model named by every create and parse call
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create, parse=self.parse))

    async def create(self, model: str, messages: list[dict], tools: list[dict], max_tokens: int) -> SimpleNamespace:
        assert {t["function"]["name"] for t in tools} == {
            "analyze_file", "extract_text", "summarize_pcap", "lookup_indicator"}
        assert max_tokens == 2048
        self.models.append(model)
        # every tool result the LLM sees has already been logged
        assert len([m for m in messages if m["role"] == "tool"]) <= len(self.logged)
        self.turn_attempts += 1
        if self.turn_errors:
            raise self.turn_errors.pop(0)
        if self.turn + 1 == self.fail_on_turn:
            raise self.failure  # every attempt of this turn fails
        if self.turn + 1 == self.slow_on_turn:
            await asyncio.sleep(30)  # outlasts the test's time budget
        self.turn += 1
        if self.turns is None:
            calls = [
                tool_call(f"a{self.turn}", "analyze_file", {"path": "note.txt"}),
                tool_call(f"b{self.turn}", "no_such_tool", {}) if self.turn == 1
                else tool_call(f"b{self.turn}", "lookup_indicator", {"path_or_value": "../../etc/passwd"}),
            ]
        else:
            calls = self.turns[self.turn - 1] if self.turn <= len(self.turns) else []
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=calls or None))])

    def with_options(self, **options: object) -> "FakeLLM":
        self.report_options = options
        return self

    async def __aenter__(self) -> "FakeLLM":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def parse(self, model: str, messages: list[dict], response_format: type, max_tokens: int,
                    temperature: float) -> SimpleNamespace:
        assert (max_tokens, temperature) == (4096, 0.2)
        self.models.append(model)
        self.report_attempts += 1
        if self.report_errors:
            raise self.report_errors.pop(0)
        self.synthesis_input = json.loads(messages[1]["content"])
        if self.slow_report:
            await asyncio.sleep(30)  # outlasts the test's report budget
        if self.unparsable_report:
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(parsed=None, content="Here."))])
        findings = self.findings
        if findings is None:  # one grounded finding per tool that ran for real without error
            findings = [{"claim": f"{tool} returned a result", "source_tool": tool} for tool in dict.fromkeys(
                result["tool"] for result in self.synthesis_input["tool_results"]
                if result["call"] == agent.SERVER_TOOLS.get(result["tool"])
                and not result["output"].startswith("error:"))]
        report = response_format(findings=findings, verdict=self.verdict)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(parsed=report, content=None))])


class _Context:
    def __init__(self, value: object) -> None:
        self.value = value

    def __enter__(self) -> object:
        return self.value

    def __exit__(self, *exc: object) -> None:
        return None


def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, set_status: object = None,
        retry_delays: tuple[int, int] = (0, 0), submitted: tuple[str, str] = ("note.txt", "file"),
        extra_rows: list[tuple] = (), **fake_options: object) -> tuple[list, list, FakeLLM]:
    """Runs run_investigation(8) against the real MCP servers with a scripted LLM and a fake DB
    whose tool_calls table is whatever _log_tool_call recorded. Returns (statuses, logged, fake)."""
    (tmp_path / "note.txt").write_text("hello")
    Image.new("RGB", (8, 8), "white").save(tmp_path / "photo.png")
    monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
    for var in ("NVIDIA_BASE_URL", "NVIDIA_API_KEY", "NVIDIA_MODEL"):
        monkeypatch.setenv(var, "unused")
    logged: list[tuple] = list(extra_rows)  # extra_rows: rows a live model can't produce, already in tool_calls
    statuses: list[tuple] = []
    monkeypatch.setattr(agent, "_log_tool_call", lambda *args: logged.append(args))
    monkeypatch.setattr(agent, "_set_status", set_status or (lambda *args: statuses.append(args)))
    result = SimpleNamespace(fetchone=lambda: submitted,
                             fetchall=lambda: [(row[1], json.dumps(row[2]), row[3]) for row in logged])
    monkeypatch.setattr(agent, "get_connection", lambda: _Context(SimpleNamespace(execute=lambda *args: result)))
    monkeypatch.setattr(agent, "RETRY_DELAYS", retry_delays)
    fake = FakeLLM(logged, **fake_options)

    def make_client(**options: object) -> FakeLLM:
        fake.client_options = options
        return fake

    monkeypatch.setattr(agent, "AsyncOpenAI", make_client)
    agent.run_investigation(8)
    return statuses, logged, fake


def test_loop_caps_logs_and_feeds_errors_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "note.txt").write_text("hello")
    monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
    for var in ("NVIDIA_BASE_URL", "NVIDIA_API_KEY", "NVIDIA_MODEL"):
        monkeypatch.setenv(var, "unused")
    logged: list[tuple] = []
    monkeypatch.setattr(agent, "_log_tool_call", lambda *args: logged.append(args))
    fake = FakeLLM(logged)
    monkeypatch.setattr(agent, "AsyncOpenAI", lambda **kwargs: fake)

    report, decided_calls, cut_short = asyncio.run(agent.investigate(1, "note.txt", "file"))

    assert len(logged) == agent.MAX_TOOL_CALLS == 5
    assert [row[1] for row in logged] == ["sandbox", "no_such_tool", "sandbox", "threat_intel", "sandbox"]
    assert '"file_type": "unknown"' in logged[0][3]
    assert logged[1][3] == "error: unknown tool no_such_tool"
    assert logged[3][2]["arguments"] == {"path_or_value": "../../etc/passwd"}
    assert '"kind": "value"' in logged[3][3]  # path guard: treated as a literal, file never read
    assert len(fake.synthesis_input["tool_results"]) == 5
    assert report.verdict == "inconclusive"
    # turn 3 asked for 2 calls but the cap allowed 1: 6 decided, 5 logged
    assert len(decided_calls) == 6
    assert {row[2]["call_id"] for row in logged} == {call_id for call_id, _ in decided_calls} - {"b3"}
    assert cut_short == "tool-call cap (5) reached before the model finished"


def test_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, fake = run(tmp_path, monkeypatch, verdict="benign", turns=[
        [tool_call("c1", "analyze_file", {"path": "note.txt"})],
        [tool_call("c2", "lookup_indicator", {"path_or_value": "note.txt"})],
        [],
    ])

    [(investigation_id, status, report, error)] = statuses
    assert (investigation_id, status, error) == (8, "complete", None)
    assert [row[1] for row in logged] == ["sandbox", "threat_intel"]
    report = json.loads(report)
    assert report["verdict"] == "benign"  # untouched when the run was complete
    assert report["missing_evidence"] == []
    assert fake.report_options == {"timeout": 120}
    assert fake.client_options["max_retries"] == 0  # retries are app-level only, never multiplied by the SDK


def test_incomplete_time_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # the budget also covers starting the 4 MCP servers: ~2.5s on an idle machine, ~4.8s under CPU load
    monkeypatch.setattr(agent, "WALL_CLOCK_SECONDS", 10)
    statuses, logged, fake = run(tmp_path, monkeypatch, slow_on_turn=2,
                                 turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"})]])

    [(_, status, report, error)] = statuses
    assert status == "incomplete"
    assert error == ("time budget (10s) reached before the model finished; "
                     "required tools did not succeed: threat_intel")
    assert json.loads(report)["missing_evidence"] == error.split("; ")
    assert len(logged) == 1 and fake.synthesis_input is not None  # report still written from partial evidence


def test_incomplete_call_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, _ = run(tmp_path, monkeypatch)  # asks for 2 calls per turn forever

    [(_, status, report, error)] = statuses
    assert status == "incomplete"
    assert len(logged) == 5
    assert error == ("tool-call cap (5) reached before the model finished; "
                     "requested tool calls never run: lookup_indicator (call b3); "
                     "required tools did not succeed: threat_intel")  # its calls were on ../../etc/passwd
    assert json.loads(report)["missing_evidence"] == error.split("; ")


def test_incomplete_benign_becomes_inconclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign")

    [(_, status, report, _)] = statuses
    assert status == "incomplete"
    assert json.loads(report)["verdict"] == "inconclusive"


def test_failed_llm_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # turn 1 fails on every attempt: no tool rows yet, so there is nothing to write a report from
    statuses, logged, fake = run(tmp_path, monkeypatch, fail_on_turn=1)

    [(_, status, report, error)] = statuses
    assert (status, report) == ("failed", None)
    assert error == "APITimeoutError: Request timed out."  # unwrapped from MCP's ExceptionGroup
    assert logged == []
    assert fake.synthesis_input is None


def test_failed_parse_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, unparsable_report=True,
                         turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"})], []])

    [(_, status, report, error)] = statuses
    assert (status, report) == ("failed", None)
    assert error == "ValueError: model returned no parsable report: 'Here.'"


def test_failed_report_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert agent.REPORT_BUDGET_SECONDS == 250  # fits 3 fast-failing attempts, but only 2 that time out at 120s
    monkeypatch.setattr(agent, "REPORT_BUDGET_SECONDS", 1)
    statuses, _, _ = run(tmp_path, monkeypatch, slow_report=True, turns=[[]])

    [(_, status, report, error)] = statuses
    assert (status, report) == ("failed", None)
    assert error == "TimeoutError: report call exceeded 1s after 1 attempt(s)"


def test_set_status_writes_error_column(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[tuple] = []
    monkeypatch.setattr(agent, "get_connection",
                        lambda: _Context(SimpleNamespace(execute=lambda *args: executed.append(args))))

    agent._set_status(8, "failed", None, "APITimeoutError: Request timed out.")

    [(sql, params)] = executed
    assert "error = %s" in sql
    assert params == ("failed", None, "APITimeoutError: Request timed out.", 8)


def status_error(cls: type, code: int) -> openai.APIStatusError:
    response = SimpleNamespace(status_code=code, request=None, headers={})
    return cls(f"Error code: {code}", response=response, body=None)


def test_report_verdict_is_literal() -> None:
    assert agent.Report(findings=[], verdict="malicious").verdict == "malicious"
    with pytest.raises(ValidationError):
        agent.Report(findings=[], verdict="probably fine")


def mcp_child_processes() -> list[str]:
    """Command lines of this process's children that are MCP servers (read from /proc)."""
    children = []
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            if int(stat.read_text().rsplit(")", 1)[1].split()[1]) == os.getpid():
                children.append((stat.parent / "cmdline").read_bytes().replace(b"\0", b" ").decode())
        except (OSError, IndexError, ValueError):
            pass  # the process exited while being read
    return [cmdline for cmdline in children if "mcp_servers" in cmdline]


def is_interrupt(exc: BaseException) -> bool:
    return (isinstance(exc, KeyboardInterrupt)
            or (isinstance(exc, BaseExceptionGroup) and exc.subgroup(KeyboardInterrupt) is not None))


def test_interrupt_marks_failed_and_reraises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses: list[tuple] = []
    with pytest.raises(BaseException) as raised:
        run(tmp_path, monkeypatch, set_status=lambda *args: statuses.append(args),
            fail_on_turn=1, failure=KeyboardInterrupt())

    assert is_interrupt(raised.value)
    assert statuses == [(8, "failed", None, "interrupted")]


def test_interrupt_status_write_failure_does_not_mask(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_set_status(*args: object) -> None:
        raise psycopg.OperationalError("database is down")

    with pytest.raises(BaseException) as raised:
        run(tmp_path, monkeypatch, set_status=broken_set_status, fail_on_turn=1, failure=KeyboardInterrupt())

    assert is_interrupt(raised.value)  # the interruption propagates, not the DB error


def test_report_retries_5xx_then_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, fake = run(tmp_path, monkeypatch, turns=NOTE_COVERED, report_errors=[
        status_error(openai.InternalServerError, 503), openai.APITimeoutError(request=None)])

    assert fake.report_attempts == 3
    assert statuses[0][1] == "complete"


def test_report_gives_up_after_three_attempts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, fake = run(tmp_path, monkeypatch, turns=[[]],
                            report_errors=[status_error(openai.InternalServerError, 503)] * 4)

    assert fake.report_attempts == 3
    [(_, status, report, error)] = statuses
    assert (status, report) == ("failed", None)
    assert error == "RuntimeError: report call failed after 3 attempt(s): InternalServerError: Error code: 503"


def test_report_does_not_retry_4xx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, fake = run(tmp_path, monkeypatch, turns=[[]],
                            report_errors=[status_error(openai.BadRequestError, 400)])

    assert fake.report_attempts == 1
    assert statuses[0][3] == "RuntimeError: report call failed after 1 attempt(s): BadRequestError: Error code: 400"


def test_benign_withheld_without_threat_intel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", submitted=("photo.png", "file"), turns=[
        [tool_call("c1", "analyze_file", {"path": "photo.png"}), tool_call("c2", "extract_text", {"path": "photo.png"})],
        [],
    ])

    [(_, status, report, error)] = statuses
    assert (status, error) == ("incomplete", "required tools did not succeed: threat_intel; "
                                             "benign withheld: tools not run: threat_intel")
    assert json.loads(report)["verdict"] == "inconclusive"


def test_benign_image_requires_ocr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", submitted=("photo.png", "file"), turns=[
        [tool_call("c1", "analyze_file", {"path": "photo.png"}),
         tool_call("c2", "lookup_indicator", {"path_or_value": "photo.png"})],
        [],
    ])

    [(_, status, report, error)] = statuses
    assert (status, error) == ("incomplete", "required tools did not succeed: ocr; "
                                             "benign withheld: tools not run: ocr")
    assert json.loads(report)["verdict"] == "inconclusive"


def write_capture(tmp_path: Path, qname: str = "example.test") -> None:
    wrpcap(str(tmp_path / "capture.pcap"),
           [IP(src="10.0.0.5", dst="10.0.0.53") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))])


CAPTURE_COVERED = [
    [tool_call("c1", "analyze_file", {"path": "capture.pcap"}),
     tool_call("c2", "summarize_pcap", {"path": "capture.pcap"}),
     tool_call("c3", "lookup_indicator", {"path_or_value": "capture.pcap"})],
    [],
]


def test_benign_pcap_requires_traffic_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_capture(tmp_path)
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="benign", submitted=("capture.pcap", "file"), turns=[
        [tool_call("c1", "analyze_file", {"path": "capture.pcap"}),
         tool_call("c2", "lookup_indicator", {"path_or_value": "capture.pcap"})],
        [],
    ])

    assert json.loads(logged[0][3])["file_type"] == "unknown"  # the sandbox cannot identify a capture
    [(_, status, report, error)] = statuses
    assert (status, error) == ("incomplete", "required tools did not succeed: traffic_summary; "
                                             "benign withheld: tools not run: traffic_summary; "
                                             + agent.CAPTURE_UNCLEARED_REASON)
    assert json.loads(report)["verdict"] == "inconclusive"


@pytest.mark.parametrize("verdict", ["benign", "inconclusive"])
def test_fully_covered_pcap_cannot_end_benign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                              verdict: str) -> None:
    write_capture(tmp_path)
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict=verdict, submitted=("capture.pcap", "file"),
                              turns=CAPTURE_COVERED)

    assert [row[1] for row in logged] == ["sandbox", "traffic_summary", "threat_intel"]
    assert not any(row[3].startswith("error:") for row in logged)
    [(_, status, report, error)] = statuses
    assert (status, error) == ("incomplete", agent.CAPTURE_UNCLEARED_REASON)
    report = json.loads(report)
    assert report["verdict"] == "inconclusive"
    assert report["missing_evidence"] == [agent.CAPTURE_UNCLEARED_REASON]


def test_pcap_with_known_bad_host_keeps_malicious(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_capture(tmp_path, qname="fujeigroup.com")  # host of a URLhaus entry in indicators.csv
    turns = [CAPTURE_COVERED[0] + [tool_call("c4", "lookup_indicator", {"path_or_value": "fujeigroup.com"})], []]
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=("capture.pcap", "file"),
                              turns=turns)

    assert json.loads(logged[1][3])["dns_queries"] == {"fujeigroup.com": 1}
    assert json.loads(logged[3][3])["matches"][0]["match"] == "url_host"
    [(_, status, report, error)] = statuses
    assert (status, error) == ("complete", None)
    assert json.loads(report)["verdict"] == "malicious"


def test_capture_payload_limit_is_not_a_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_capture(tmp_path)
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="suspicious", submitted=("capture.pcap", "file"),
                         turns=CAPTURE_COVERED)

    [(_, status, report, _)] = statuses
    report = json.loads(report)
    assert status == "complete"
    assert report["scope_notes"] == [agent.CAPTURE_SCOPE_NOTE]
    assert not any(finding["source_tool"] == "traffic_summary" and "payload" in finding["claim"].lower()
                   for finding in report["findings"])


def test_real_database_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Builds a throwaway charon_test database from db/schema.sql on the same server, runs the real
    tool-call logging and status write against it, and drops it afterwards. Never touches `charon`."""
    from app.db import DATABASE_URL

    try:
        admin = psycopg.connect(DATABASE_URL, autocommit=True)
    except psycopg.OperationalError:
        pytest.skip("PostgreSQL not reachable")
    test_url = conninfo.make_conninfo(DATABASE_URL, dbname="charon_test")
    with admin:
        admin.execute("DROP DATABASE IF EXISTS charon_test WITH (FORCE)")
        admin.execute("CREATE DATABASE charon_test")
    try:
        with psycopg.connect(test_url) as conn:
            conn.execute((Path(__file__).resolve().parents[1] / "db" / "schema.sql").read_text())
            investigation_id = conn.execute(
                "INSERT INTO investigations (submitted_input, input_type) VALUES ('note.txt', 'file') RETURNING id"
            ).fetchone()[0]

        (tmp_path / "note.txt").write_text("hello")
        monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
        for var in ("NVIDIA_BASE_URL", "NVIDIA_API_KEY", "NVIDIA_MODEL"):
            monkeypatch.setenv(var, "unused")
        monkeypatch.setattr(agent, "get_connection", lambda: psycopg.connect(test_url))
        logged: list[tuple] = []  # FakeLLM only uses this for its "logged before seen" check
        monkeypatch.setattr(agent, "AsyncOpenAI", lambda **kwargs: FakeLLM(logged))
        real_log = agent._log_tool_call
        monkeypatch.setattr(agent, "_log_tool_call", lambda *args: (logged.append(args), real_log(*args)))

        agent.run_investigation(investigation_id)  # asks for 2 calls per turn forever: call cap skips b3

        with psycopg.connect(test_url) as conn:
            status, report, error = conn.execute(
                "SELECT status, report, error FROM investigations WHERE id = %s", (investigation_id,)).fetchone()
            call_ids = [row[0] for row in conn.execute(
                "SELECT input_payload::json->>'call_id' FROM tool_calls WHERE investigation_id = %s ORDER BY id",
                (investigation_id,))]
        assert status == "incomplete"
        assert error == ("tool-call cap (5) reached before the model finished; "
                         "requested tool calls never run: lookup_indicator (call b3); "
                         "required tools did not succeed: threat_intel")
        assert call_ids == ["a1", "b1", "a2", "b2", "a3"]  # b3 was decided but has no row
        assert json.loads(report)["missing_evidence"] == error.split("; ")
    finally:
        with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
            admin.execute("DROP DATABASE IF EXISTS charon_test WITH (FORCE)")


@pytest.mark.parametrize("llm_model, expected", [("llm/model", "llm/model"), (None, "unused")],
                         ids=["llm settings", "nvidia settings"])
def test_every_llm_call_uses_the_resolved_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                llm_model: str | None, expected: str) -> None:
    if llm_model is not None:
        monkeypatch.setenv("LLM_API_KEY", "llm-test-key-9876543210")
        monkeypatch.setenv("LLM_BASE_URL", "unused")
        monkeypatch.setenv("LLM_MODEL", llm_model)
    statuses, _, fake = run(tmp_path, monkeypatch, turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"})], []])

    assert statuses[0][1] != "failed"
    assert fake.models == [expected] * 3  # two turns and the report


@pytest.mark.parametrize("turns", [
    [[tool_call("", "analyze_file", {"path": "note.txt"})], []],
    [[tool_call("  ", "analyze_file", {"path": "note.txt"})], []],
    [[tool_call(None, "analyze_file", {"path": "note.txt"})], []],
    [[tool_call("c1", "analyze_file", {"path": "note.txt"}),
      tool_call("c1", "lookup_indicator", {"path_or_value": "note.txt"})], []],
    [[tool_call("c1", "analyze_file", {"path": "note.txt"})],
     [tool_call("c1", "lookup_indicator", {"path_or_value": "note.txt"})], []],
], ids=["empty", "blank", "missing", "duplicate in a turn", "duplicate across turns"])
def test_an_empty_or_duplicate_tool_call_id_fails_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                         turns: list[list]) -> None:
    """Call ids tie each requested call to its tool_calls row; without unique ids the coverage check cannot
    tell which requested calls ran."""
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", turns=turns)

    [(_, status, report, error)] = statuses
    assert (status, report) == ("failed", None)
    assert error == "ValueError: provider returned an empty or duplicate tool-call id"


def test_schema_upgrades_an_existing_database_and_new_rows_record_the_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Applies db/schema.sql twice to a throwaway charon_test_migration database that holds rows in an older
    shape (no error or model column), then submits an investigation through the API. Never touches `charon`."""
    from fastapi.testclient import TestClient

    from app import main
    from app.db import DATABASE_URL

    try:
        admin = psycopg.connect(DATABASE_URL, autocommit=True)
    except psycopg.OperationalError:
        pytest.skip("PostgreSQL not reachable")
    test_url = conninfo.make_conninfo(DATABASE_URL, dbname="charon_test_migration")
    with admin:
        admin.execute("DROP DATABASE IF EXISTS charon_test_migration WITH (FORCE)")
        admin.execute("CREATE DATABASE charon_test_migration")
    try:
        with psycopg.connect(test_url) as conn:
            conn.execute("CREATE TABLE investigations (id SERIAL PRIMARY KEY, submitted_input TEXT NOT NULL,"
                         " input_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running', report TEXT,"
                         " created_at TIMESTAMP DEFAULT now())")
            conn.execute("INSERT INTO investigations (submitted_input, input_type, status, report) VALUES"
                         " ('old.pdf', 'file', 'complete', '{}'), ('http://example.test/', 'url', 'failed', NULL)")
        schema = (Path(__file__).resolve().parents[1] / "db" / "schema.sql").read_text()
        for _ in range(2):
            with psycopg.connect(test_url) as conn:
                conn.execute(schema)

        for name, value in {"LLM_API_KEY": "llm-test-key-9876543210", "LLM_BASE_URL": "unused",
                            "LLM_MODEL": "llm/model", "NVIDIA_MODEL": "nvidia/model"}.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr(main, "get_connection", lambda: psycopg.connect(test_url))
        monkeypatch.setattr(main, "run_investigation", lambda investigation_id: None)
        response = TestClient(main.app).post("/investigations",
                                             json={"submitted_input": "new.png", "input_type": "file"})
        assert response.status_code == 200

        with psycopg.connect(test_url) as conn:
            rows = conn.execute("SELECT submitted_input, status, report, error, model FROM investigations"
                                " ORDER BY id").fetchall()
            model_type = conn.execute("SELECT data_type, is_nullable FROM information_schema.columns"
                                      " WHERE table_name = 'investigations' AND column_name = 'model'").fetchall()
    finally:
        with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
            admin.execute("DROP DATABASE IF EXISTS charon_test_migration WITH (FORCE)")

    assert model_type == [("text", "YES")]
    assert rows == [("old.pdf", "complete", "{}", None, None),  # older rows keep NULL: model unknown
                    ("http://example.test/", "failed", None, None, None),
                    ("new.png", "running", None, None, "llm/model")]


def test_system_prompt_requires_file_coverage() -> None:
    assert ("For every file input, always run analyze_file first, then lookup_indicator, plus\n"
            "extract_text when the file is an image, before you finish.") in agent.SYSTEM_PROMPT
    assert "verdict" not in agent.SYSTEM_PROMPT.lower()
    assert ("This includes a capture file (.pcap or .pcapng): run analyze_file on it first even though it is not a\n"
            "document or image, and also run summarize_pcap on the file before you finish.") in agent.SYSTEM_PROMPT


def test_report_prompt_requires_grounding() -> None:
    assert "Every factual statement must come from a tool result in this run." in agent.REPORT_PROMPT
    assert "background knowledge" in agent.REPORT_PROMPT
    assert "summarize_pcap does not parse application-layer protocols such as HTTP" in agent.REPORT_PROMPT
    assert "Never report what a tool cannot do as a finding" in agent.REPORT_PROMPT
    assert ("If a tool failed, never report that as a finding: tool failures are recorded separately."
            in agent.REPORT_PROMPT)
    assert "you may report that as a finding" not in agent.REPORT_PROMPT


def test_loop_turn_retries_5xx_and_timeouts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, fake = run(tmp_path, monkeypatch, turns=NOTE_COVERED,
        turn_errors=[status_error(openai.InternalServerError, 503), openai.APITimeoutError(request=None)])

    assert fake.turn_attempts == 4  # turn 1: 503, timeout, success; turn 2: success (model finishes)
    assert statuses[0][1] == "complete"
    assert len(logged) == 2


def test_loop_turn_does_not_retry_4xx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, fake = run(tmp_path, monkeypatch, turns=[[]],
                            turn_errors=[status_error(openai.BadRequestError, 400)])

    assert fake.turn_attempts == 1
    assert statuses == [(8, "failed", None, "BadRequestError: Error code: 400")]


def test_loop_retry_never_waits_past_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # the 15s budget leaves room for starting the 4 MCP servers (~2.4s on an idle machine)
    monkeypatch.setattr(agent, "WALL_CLOCK_SECONDS", 15)
    started = time.monotonic()
    statuses, _, fake = run(tmp_path, monkeypatch, retry_delays=(30, 60), turns=[[]],
                            turn_errors=[status_error(openai.InternalServerError, 503)])

    assert fake.turn_attempts == 1  # the 30s wait would cross the 15s deadline, so no retry
    # treated like the time budget running out: a report from the evidence so far, marked incomplete
    [(_, status, report, error)] = statuses
    assert status == "incomplete" and report is not None
    assert error.startswith("time budget (15s) reached before the model finished")
    assert time.monotonic() - started < 15 + 5  # never slept the 30s


NOTE_COVERED = [
    [tool_call("c1", "analyze_file", {"path": "note.txt"}),
     tool_call("c2", "lookup_indicator", {"path_or_value": "note.txt"})],
    [],
]

PHOTO_COVERED = [
    [tool_call("c1", "analyze_file", {"path": "photo.png"}), tool_call("c2", "extract_text", {"path": "photo.png"}),
     tool_call("c3", "lookup_indicator", {"path_or_value": "photo.png"})],
    [],
]


def test_invented_sandbox_tool_does_not_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="benign", turns=[
        [tool_call("c1", "sandbox", {"path": "note.txt"}),  # not a real tool; logged under the name "sandbox"
         tool_call("c2", "lookup_indicator", {"path_or_value": "note.txt"})],
        [],
    ])

    assert [row[1] for row in logged] == ["sandbox", "threat_intel"]
    [(_, status, report, error)] = statuses
    assert status == "incomplete"
    assert json.loads(report)["verdict"] == "inconclusive"
    assert "required tools did not succeed: sandbox" in error


def test_error_output_rows_do_not_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing_tool(*args: object) -> tuple[str, bool]:
        return "error: tool crashed", False

    monkeypatch.setattr(agent, "_call_tool_once", failing_tool)
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=("photo.png", "file"),
                              turns=PHOTO_COVERED)

    assert len(logged) == 3 and all(row[3].startswith("error:") for row in logged)
    [(_, status, report, error)] = statuses
    assert status == "incomplete"  # whatever the verdict
    assert json.loads(report)["verdict"] == "inconclusive"  # no tool succeeded, so no finding supports malicious
    # sandbox errored, so the file type is unknown and ocr (which also errored) stays required
    assert error == ("malicious withheld: verdict has no supporting findings; "
                     "required tools did not succeed: sandbox, threat_intel, ocr")


def test_wrong_file_analysed_does_not_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", submitted=("photo.png", "file"), turns=[
        [tool_call("c1", "analyze_file", {"path": "note.txt"}), tool_call("c2", "extract_text", {"path": "note.txt"}),
         tool_call("c3", "lookup_indicator", {"path_or_value": "note.txt"})],
        [],
    ])

    [(_, status, report, error)] = statuses
    assert status == "incomplete"
    assert json.loads(report)["verdict"] == "inconclusive"
    assert error.startswith("required tools did not succeed: sandbox, threat_intel")


def test_fully_covered_image_run_is_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", submitted=("photo.png", "file"),
                         turns=PHOTO_COVERED)

    [(_, status, report, error)] = statuses
    assert (status, error) == ("complete", None)
    assert json.loads(report)["verdict"] == "benign"


NOTE_FINDINGS = [{"claim": "note.txt is plain text", "source_tool": "sandbox"},
                 {"claim": "note.txt has no threat-intel match", "source_tool": "threat_intel"}]


@pytest.mark.parametrize("verdict", ["malicious", "benign"])
def test_finding_citing_uncalled_tool_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                 verdict: str) -> None:
    uncited = {"claim": "the image text asks for a password", "source_tool": "ocr"}
    statuses, _, _ = run(tmp_path, monkeypatch, verdict=verdict, turns=NOTE_COVERED,
                         findings=NOTE_FINDINGS + [uncited])

    [(_, status, report, error)] = statuses
    reason = 'findings dropped, cited tool has no successful call: ocr: "the image text asks for a password"'
    assert (status, error) == ("incomplete", reason)
    report = json.loads(report)
    assert report["findings"] == NOTE_FINDINGS
    assert report["missing_evidence"] == [reason]
    # existing verdict rules: benign is withheld on any limitation, malicious is kept
    assert report["verdict"] == ("malicious" if verdict == "malicious" else "inconclusive")


@pytest.mark.parametrize("verdict", ["malicious", "benign"])
def test_findings_citing_called_tools_are_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                               verdict: str) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict=verdict, turns=NOTE_COVERED, findings=NOTE_FINDINGS)

    [(_, status, report, error)] = statuses
    assert (status, error) == ("complete", None)
    report = json.loads(report)
    assert (report["findings"], report["verdict"], report["missing_evidence"]) == (NOTE_FINDINGS, verdict, [])


@pytest.mark.parametrize("verdict", ["malicious", "suspicious"])
def test_all_findings_dropped_downgrades_verdict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                 verdict: str) -> None:
    uncited = {"claim": "the image text asks for a password", "source_tool": "ocr"}
    statuses, _, _ = run(tmp_path, monkeypatch, verdict=verdict, turns=NOTE_COVERED, findings=[uncited])

    [(_, status, report, error)] = statuses
    reasons = ['findings dropped, cited tool has no successful call: ocr: "the image text asks for a password"',
               f"{verdict} withheld: verdict has no supporting findings"]
    assert (status, error) == ("incomplete", "; ".join(reasons))
    report = json.loads(report)
    assert (report["findings"], report["verdict"], report["missing_evidence"]) == ([], "inconclusive", reasons)


@pytest.mark.parametrize("verdict", ["malicious", "suspicious"])
def test_concerning_verdict_without_findings_is_withheld(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                         verdict: str) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict=verdict, turns=NOTE_COVERED, findings=[])

    [(_, status, report, error)] = statuses
    reason = f"{verdict} withheld: verdict has no supporting findings"
    assert (status, error) == ("incomplete", reason)
    report = json.loads(report)
    assert (report["findings"], report["verdict"], report["missing_evidence"]) == ([], "inconclusive", [reason])


def test_benign_without_findings_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", turns=NOTE_COVERED, findings=[])

    [(_, status, report, error)] = statuses
    assert (status, error, json.loads(report)["verdict"]) == ("complete", None, "benign")


def fail_calls(monkeypatch: pytest.MonkeyPatch, tool: str, times: int) -> None:
    """The first `times` calls to `tool` time out (so the agent retries once); later calls reach the server."""
    real_call = agent._call_tool_once
    remaining = [times]

    async def call(session: object, name: str, arguments: dict, timeout: float) -> tuple[str, bool]:
        if name == tool and remaining[0]:
            remaining[0] -= 1
            return "error: timed out", True
        return await real_call(session, name, arguments, timeout)

    monkeypatch.setattr(agent, "_call_tool_once", call)


KNOWN_BAD_URL = "http://115.50.105.81:59352/i"  # a URLhaus entry in indicators.csv
URL_LOOKUP = [[tool_call("c1", "lookup_indicator", {"path_or_value": KNOWN_BAD_URL})], []]


def test_url_tool_that_never_succeeded_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fail_calls(monkeypatch, "lookup_indicator", 2)
    claim = {"claim": "the URL is a known malware download site", "source_tool": "threat_intel"}
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=(KNOWN_BAD_URL, "url"),
                              turns=URL_LOOKUP, findings=[claim])

    assert [row[3] for row in logged] == ["error: timed out", "error: timed out"]
    [(_, status, report, error)] = statuses
    reasons = ['findings dropped, cited tool has no successful call: threat_intel: '
               '"the URL is a known malware download site"',
               "malicious withheld: verdict has no supporting findings",
               "tool failed: threat_intel"]
    assert (status, error) == ("incomplete", "; ".join(reasons))
    report = json.loads(report)
    assert (report["findings"], report["verdict"], report["missing_evidence"]) == ([], "inconclusive", reasons)


def test_url_tool_that_succeeded_on_retry_is_not_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fail_calls(monkeypatch, "lookup_indicator", 1)
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=(KNOWN_BAD_URL, "url"),
                              turns=URL_LOOKUP)

    assert logged[0][3] == "error: timed out" and '"matches": [' in logged[1][3]
    [(_, status, report, error)] = statuses
    assert (status, error, json.loads(report)["verdict"]) == ("complete", None, "malicious")


def test_optional_file_tool_failure_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fail_calls(monkeypatch, "extract_text", 2)
    turns = [NOTE_COVERED[0] + [tool_call("c3", "extract_text", {"path": "note.txt"})], []]
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", turns=turns)

    [(_, status, report, error)] = statuses
    assert (status, error) == ("incomplete", "tool failed: ocr")  # ocr is not required for a text file
    assert json.loads(report)["verdict"] == "malicious"


def test_required_tool_failure_is_reported_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fail_calls(monkeypatch, "lookup_indicator", 2)
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", turns=NOTE_COVERED)

    [(_, status, _, error)] = statuses
    assert (status, error) == ("incomplete", "required tools did not succeed: threat_intel")


# Already in tool_calls: an ocr row that errored, and an ocr row made through a tool name the model invented.
OCR_ERROR_ROW = (8, "ocr", {"tool": "extract_text", "call_id": "x1", "arguments": {"path": "note.txt"}},
                 "error: tesseract crashed")
OCR_INVENTED_ROW = (8, "ocr", {"tool": "read_image_text", "call_id": "x1", "arguments": {"path": "note.txt"}},
                    json.dumps({"path": "note.txt", "text": "enter your password"}))


@pytest.mark.parametrize(("row", "also"), [(OCR_ERROR_ROW, ["tool failed: ocr"]), (OCR_INVENTED_ROW, [])],
                         ids=["error_output", "invented_tool"])
def test_finding_citing_unsuccessful_row_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    row: tuple, also: list[str]) -> None:
    uncited = {"claim": "the image text asks for a password", "source_tool": "ocr"}
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", turns=NOTE_COVERED, extra_rows=[row],
                         findings=NOTE_FINDINGS + [uncited])

    [(_, status, report, error)] = statuses
    dropped = 'findings dropped, cited tool has no successful call: ocr: "the image text asks for a password"'
    assert (status, error) == ("incomplete", "; ".join([dropped] + also))
    assert json.loads(report)["findings"] == NOTE_FINDINGS


def test_invalid_json_arguments_do_not_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad_args = SimpleNamespace(id="c1", function=SimpleNamespace(name="analyze_file", arguments="{not json"),
                               model_dump=lambda: {"id": "c1", "type": "function",
                                                   "function": {"name": "analyze_file", "arguments": "{not json"}})
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="benign", turns=[
        [bad_args, tool_call("c2", "lookup_indicator", {"path_or_value": "note.txt"})], [],
    ])

    assert logged[0][1] == "sandbox" and logged[0][3].startswith("error: arguments are not valid JSON")
    [(_, status, report, error)] = statuses
    assert status == "incomplete"
    assert json.loads(report)["verdict"] == "inconclusive"
    assert "required tools did not succeed: sandbox" in error


def test_startup_hang_fails_instead_of_hanging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class HangingSession(agent.ClientSession):
        async def initialize(self) -> object:
            await asyncio.sleep(3600)

    monkeypatch.setattr(agent, "ClientSession", HangingSession)
    monkeypatch.setattr(agent, "WALL_CLOCK_SECONDS", 2)
    statuses: list[tuple] = []
    worker = threading.Thread(target=run, daemon=True, args=(tmp_path, monkeypatch),
                              kwargs={"set_status": lambda *args: statuses.append(args)})
    worker.start()
    worker.join(timeout=20)

    assert not worker.is_alive(), "investigation still running: MCP startup was not bounded"
    assert mcp_child_processes() == []  # the exit stack closed every MCP server it had started
    [(_, status, report, error)] = statuses
    assert (status, report) == ("failed", None)
    assert error == "TimeoutError: MCP tool servers did not start within 2s"


@pytest.mark.parametrize(("path", "covered"), [
    ("./photo.png", True),
    ("sub/../photo.png", True),
    ("../photo.png", False),
    ("note.txt", False),
])
def test_coverage_compares_normalised_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str,
                                            covered: bool) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", submitted=("photo.png", "file"), turns=[
        [tool_call("c1", "analyze_file", {"path": path}), tool_call("c2", "extract_text", {"path": path}),
         tool_call("c3", "lookup_indicator", {"path_or_value": path})],
        [],
    ])

    [(_, status, report, error)] = statuses
    if covered:
        assert (status, error, json.loads(report)["verdict"]) == ("complete", None, "benign")
    elif path == "../photo.png":
        assert status == "incomplete"
        assert error == ("required tools did not succeed: sandbox, threat_intel, ocr; "
                         "benign withheld: tools not run: sandbox, threat_intel, ocr")
        assert json.loads(report)["verdict"] == "inconclusive"
    else:
        assert status == "incomplete" and error.startswith("required tools did not succeed: sandbox")
        assert json.loads(report)["verdict"] == "inconclusive"



def test_extra_argument_keys_do_not_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=("photo.png", "file"), turns=[
        [tool_call("c1", "analyze_file", {"path": "note.txt", "path_or_value": "photo.png"}),
         tool_call("c2", "lookup_indicator", {"path_or_value": "8.8.8.8", "path": "photo.png"})],
        [],
    ])

    [(_, status, _, error)] = statuses
    assert status == "incomplete"
    # sandbox never examined photo.png, so its type is unknown and ocr stays required
    assert error == "required tools did not succeed: sandbox, threat_intel, ocr"


def test_url_benign_becomes_inconclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="benign", turns=[[]],
                              submitted=("http://secure-verify.example/login", "url"))

    assert logged == []
    [(_, status, report, error)] = statuses
    assert (status, error) == ("incomplete", "benign not supported for url input: no content analysis available")
    assert json.loads(report)["verdict"] == "inconclusive"


def test_url_malicious_is_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = "http://secure-verify.example/login"
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=(url, "url"),
                         turns=[[tool_call("c1", "lookup_indicator", {"path_or_value": url})], []])

    [(_, status, report, error)] = statuses
    assert (status, error, json.loads(report)["verdict"]) == ("complete", None, "malicious")


def test_non_dict_arguments_row_keeps_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    odd_row = (8, "sandbox", {"tool": "analyze_file", "call_id": "x1", "arguments": [1, 2]}, "{}")
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", turns=NOTE_COVERED, extra_rows=[odd_row])

    [(_, status, report, error)] = statuses
    assert (status, error, json.loads(report)["verdict"]) == ("complete", None, "malicious")


def test_known_tool_with_non_dict_json_arguments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    list_args = SimpleNamespace(id="c1", function=SimpleNamespace(name="analyze_file", arguments="[1, 2]"),
                                model_dump=lambda: {"id": "c1", "type": "function",
                                                    "function": {"name": "analyze_file", "arguments": "[1, 2]"}})
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="malicious", turns=[
        [list_args, tool_call("c2", "lookup_indicator", {"path_or_value": "note.txt"})], [],
    ])

    assert logged[0][1] == "sandbox" and logged[0][3].startswith("error:")
    [(_, status, report, error)] = statuses
    assert status == "incomplete" and report is not None  # the run is not thrown away
    assert error == "required tools did not succeed: sandbox, ocr"


def test_mismatched_payload_tool_does_not_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # successful image output, logged under "sandbox" but produced by a different tool
    forged = (8, "sandbox", {"tool": "extract_text", "call_id": "x1", "arguments": {"path": "photo.png"}},
              json.dumps({"path": "photo.png", "file_type": "image"}))
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=("photo.png", "file"),
                         extra_rows=[forged], turns=[
        [tool_call("c1", "extract_text", {"path": "photo.png"}),
         tool_call("c2", "lookup_indicator", {"path_or_value": "photo.png"})],
        [],
    ])

    [(_, status, _, error)] = statuses
    assert (status, error) == ("incomplete", "required tools did not succeed: sandbox")


def test_threat_intel_value_fallback_does_not_cover(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # gone.png is not in the intake dir, so lookup_indicator falls back to a literal-value lookup
    statuses, logged, _ = run(tmp_path, monkeypatch, verdict="malicious", submitted=("gone.png", "file"), turns=[
        [tool_call("c1", "lookup_indicator", {"path_or_value": "gone.png"})], [],
    ])

    assert '"kind": "value"' in logged[0][3] and not logged[0][3].startswith("error:")
    [(_, status, _, error)] = statuses
    assert (status, error) == ("incomplete", "required tools did not succeed: sandbox, threat_intel, ocr")



def test_turn_failure_after_evidence_writes_partial_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, fake = run(tmp_path, monkeypatch, verdict="malicious", fail_on_turn=2,
                                 failure=status_error(openai.InternalServerError, 500),
                                 turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"})]])

    assert len(logged) == 1  # turn 1's tool row stays logged
    assert fake.turn_attempts == 1 + 3  # turn 1, then 3 failed attempts at turn 2
    [(_, status, report, error)] = statuses
    assert status == "incomplete" and json.loads(report)["verdict"] == "malicious"
    assert error == ("llm turn failed after 3 attempts: InternalServerError 500; report written from partial evidence; "
                     "required tools did not succeed: threat_intel")
    assert len(fake.synthesis_input["tool_results"]) == 1


def test_turn_failure_after_evidence_benign_becomes_inconclusive(tmp_path: Path,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, _ = run(tmp_path, monkeypatch, verdict="benign", fail_on_turn=2,
                         failure=status_error(openai.InternalServerError, 500), turns=NOTE_COVERED)

    [(_, status, report, error)] = statuses
    assert status == "incomplete"
    assert json.loads(report)["verdict"] == "inconclusive"
    assert error == "llm turn failed after 3 attempts: InternalServerError 500; report written from partial evidence"


def test_turn_failure_without_evidence_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, fake = run(tmp_path, monkeypatch, fail_on_turn=1,
                                 failure=status_error(openai.InternalServerError, 500))

    assert logged == [] and fake.synthesis_input is None
    assert statuses == [(8, "failed", None, "InternalServerError: Error code: 500")]


def test_report_failure_after_turn_failure_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, _, fake = run(tmp_path, monkeypatch, fail_on_turn=2, failure=status_error(openai.InternalServerError, 500),
                            turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"})]],
                            report_errors=[status_error(openai.InternalServerError, 500)] * 3)

    assert fake.report_attempts == 3
    assert statuses == [(8, "failed", None,
                         "RuntimeError: report call failed after 3 attempt(s): InternalServerError: Error code: 500")]


def test_turn_4xx_after_evidence_still_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statuses, logged, fake = run(tmp_path, monkeypatch, fail_on_turn=2, failure=status_error(openai.BadRequestError, 400),
                                 turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"})]])

    assert len(logged) == 1 and fake.turn_attempts == 2  # no retry of a 4xx
    assert fake.synthesis_input is None
    assert statuses == [(8, "failed", None, "BadRequestError: Error code: 400")]



def test_startup_error_after_deadline_reports_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Under load the MCP client can turn the startup cancellation into BrokenResourceError; once the deadline
    has passed that must still be reported as the startup timeout."""
    real_stdio_client = agent.stdio_client

    @asynccontextmanager
    async def stdio_client(params: object) -> object:
        if "mcp_servers.ocr.server" not in params.args:
            async with real_stdio_client(params) as streams:  # sandbox really starts before ocr hangs
                yield streams
            return
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            raise anyio.BrokenResourceError
        yield

    monkeypatch.setattr(agent, "stdio_client", stdio_client)
    monkeypatch.setattr(agent, "WALL_CLOCK_SECONDS", 5)
    statuses, _, _ = run(tmp_path, monkeypatch)

    assert statuses == [(8, "failed", None, "TimeoutError: MCP tool servers did not start within 5s")]
    assert mcp_child_processes() == []


def test_startup_error_before_deadline_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def stdio_client(params: object) -> object:
        raise anyio.BrokenResourceError("server crashed on import")
        yield

    monkeypatch.setattr(agent, "stdio_client", stdio_client)
    statuses, _, _ = run(tmp_path, monkeypatch)  # default 240s budget: the deadline is far away

    assert statuses == [(8, "failed", None, "BrokenResourceError: server crashed on import")]
    assert mcp_child_processes() == []



def test_startup_cleanup_error_after_deadline_reports_timeout(tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure that occurs under load: startup times out, then closing the MCP clients that did start raises
    BrokenResourceError. The timeout must still be the reported error. Uses real servers, so the orphan
    check covers real processes."""
    real_stdio_client = agent.stdio_client

    @asynccontextmanager
    async def stdio_client(params: object) -> object:
        try:
            async with real_stdio_client(params) as streams:
                yield streams
        finally:
            raise anyio.BrokenResourceError  # cleanup fails, as it can under CPU load

    class HangingSession(agent.ClientSession):
        async def initialize(self) -> object:
            await asyncio.sleep(3600)

    monkeypatch.setattr(agent, "stdio_client", stdio_client)
    monkeypatch.setattr(agent, "ClientSession", HangingSession)
    monkeypatch.setattr(agent, "WALL_CLOCK_SECONDS", 5)
    statuses, _, _ = run(tmp_path, monkeypatch)

    assert statuses == [(8, "failed", None, "TimeoutError: MCP tool servers did not start within 5s")]
    assert mcp_child_processes() == []


@pytest.mark.parametrize("http_status, expected_status", [(200, "incomplete"), (400, "failed")],
                         ids=["run finishes", "provider error"])
def test_provider_client_is_closed_on_the_investigation_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                            http_status: int, expected_status: str) -> None:
    """The real SDK client, against a keep-alive localhost provider, holds a pooled connection bound to the
    investigation's event loop. Left open, the SDK closes it on garbage collection by scheduling aclose() on
    whatever loop is running then, and that task fails with "Event loop is closed"."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # keeps the connection open in the client's pool

        def log_message(self, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            content = json.dumps({"findings": [], "verdict": "inconclusive"}) if "response_format" in body else "done"
            payload = ({"id": "x", "object": "chat.completion", "created": 0, "model": body["model"],
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": content}}]}
                       if http_status == 200 else {"error": {"message": "bad request"}})
            data = json.dumps(payload).encode()
            self.send_response(http_status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    (tmp_path / "note.txt").write_text("hello")
    monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
    monkeypatch.setenv("NVIDIA_BASE_URL", f"http://127.0.0.1:{server.server_address[1]}/v1")
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key-0123456789")
    monkeypatch.setenv("NVIDIA_MODEL", "fake/model")
    monkeypatch.setenv("PYTHONASYNCIODEBUG", "1")  # the loop then raises on a close from another thread
    statuses: list[tuple] = []
    monkeypatch.setattr(agent, "_log_tool_call", lambda *args: None)
    monkeypatch.setattr(agent, "_set_status", lambda *args: statuses.append(args))
    result = SimpleNamespace(fetchone=lambda: ("note.txt", "file"), fetchall=lambda: [])
    monkeypatch.setattr(agent, "get_connection", lambda: _Context(SimpleNamespace(execute=lambda *args: result)))
    clients: list[openai.AsyncOpenAI] = []

    def make_client(**options: object) -> openai.AsyncOpenAI:
        clients.append(openai.AsyncOpenAI(**options))
        return clients[-1]

    monkeypatch.setattr(agent, "AsyncOpenAI", make_client)
    gc.collect()
    try:
        agent.run_investigation(8)
    finally:
        server.shutdown()
        server.server_close()

    assert [status for _, status, _, _ in statuses] == [expected_status]
    assert len(clients) == 1 and clients[0].is_closed()
    clients.clear()
    contexts: list[dict] = []

    async def collect_on_a_later_loop() -> None:
        asyncio.get_running_loop().set_exception_handler(lambda loop, context: contexts.append(context))
        gc.collect()
        await asyncio.sleep(0.2)  # lets any close task scheduled during collection run and fail
        gc.collect()  # a failed task reports "Task exception was never retrieved" when it is collected

    asyncio.run(collect_on_a_later_loop())
    assert [context["message"] for context in contexts] == []
