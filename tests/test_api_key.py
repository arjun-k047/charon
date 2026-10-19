import asyncio
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, ErrorData, TextContent
from psycopg import conninfo

from app import agent, main
from test_agent import FakeLLM, tool_call
from test_redteam_preflight import OPENAI_ENVIRONMENT, FakeModel

NVIDIA_KEY = "fake-nim-key-0123456789"
LLM_KEY = "llm-test-key-9876543210"
OPENAI_KEY = "sk-openai-dummy-must-not-be-sent"


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeModel]:
    model = FakeModel("ok")
    monkeypatch.setenv("NVIDIA_BASE_URL", model.url)
    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
    yield model
    model.close()


def no_database(*args: object, **kwargs: object) -> None:
    raise AssertionError("startup touched the database before its environment checks")


MISSING_KEY = ("NVIDIA_API_KEY is unset or empty; set it, or set all of LLM_API_KEY, LLM_BASE_URL and LLM_MODEL,"
               " in .env")
LLM_NAMES = ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL")


def llm_incomplete(*missing: str) -> str:
    return (f"not set or blank: {', '.join(missing)}; all of LLM_API_KEY, LLM_BASE_URL and LLM_MODEL are required"
            " once any of them is set")


@pytest.mark.parametrize("value", [None, "", "   \t\n"], ids=["unset", "empty", "whitespace"])
def test_missing_key_refuses_client_and_startup(monkeypatch: pytest.MonkeyPatch, fake: FakeModel,
                                                value: str | None) -> None:
    if value is None:
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NVIDIA_API_KEY", value)
    with pytest.raises(RuntimeError) as excinfo:
        agent.build_client()
    assert str(excinfo.value) == MISSING_KEY

    monkeypatch.setattr(main, "get_connection", no_database)
    with pytest.raises(RuntimeError) as excinfo:
        with TestClient(main.app):
            pass
    assert str(excinfo.value) == MISSING_KEY
    assert fake.requests == []


# Partial or blank LLM_* settings, with every NVIDIA_* setting valid: (LLM_* values set, variables reported).
# None leaves a variable unset; "url" stands for the LLM fake's base URL.
INCOMPLETE_LLM = {
    "base url only": ({"LLM_BASE_URL": "url"}, ("LLM_API_KEY", "LLM_MODEL")),
    "key only": ({"LLM_API_KEY": LLM_KEY}, ("LLM_BASE_URL", "LLM_MODEL")),
    "model only": ({"LLM_MODEL": "llm/model"}, ("LLM_API_KEY", "LLM_BASE_URL")),
    "no key": ({"LLM_BASE_URL": "url", "LLM_MODEL": "llm/model"}, ("LLM_API_KEY",)),
    "no base url": ({"LLM_API_KEY": LLM_KEY, "LLM_MODEL": "llm/model"}, ("LLM_BASE_URL",)),
    "no model": ({"LLM_API_KEY": LLM_KEY, "LLM_BASE_URL": "url"}, ("LLM_MODEL",)),
    "empty key alone": ({"LLM_API_KEY": ""}, LLM_NAMES),  # set though empty, so NVIDIA_* is still ignored
    "whitespace model alone": ({"LLM_MODEL": " "}, LLM_NAMES),
    **{f"{name} {label}": ({**{"LLM_API_KEY": LLM_KEY, "LLM_BASE_URL": "url", "LLM_MODEL": "llm/model"}, name: blank},
                           (name,))
       for name in LLM_NAMES for label, blank in (("empty", ""), ("whitespace", " \t\n"))},
}


@pytest.mark.parametrize("case", INCOMPLETE_LLM)
def test_incomplete_llm_settings_are_refused_without_falling_back(monkeypatch: pytest.MonkeyPatch,
                                                                  case: str) -> None:
    """Once any LLM_* variable is set, all three must be set and non-blank; NVIDIA_* never fills a gap, so a
    leftover NVIDIA_API_KEY cannot reach the provider named by LLM_BASE_URL."""
    llm, nvidia = FakeModel("ok"), FakeModel("ok")
    values, missing = INCOMPLETE_LLM[case]
    for name, value in {"NVIDIA_API_KEY": NVIDIA_KEY, "NVIDIA_BASE_URL": nvidia.url,
                        "NVIDIA_MODEL": "nvidia/model"}.items():
        monkeypatch.setenv(name, value)
    for name, value in values.items():
        monkeypatch.setenv(name, llm.url if value == "url" else value)
    monkeypatch.setattr(main, "get_connection", no_database)
    try:
        with pytest.raises(RuntimeError) as client_error:
            agent.build_client()
        with pytest.raises(RuntimeError) as startup_error:
            with TestClient(main.app):
                pass
    finally:
        llm.close()
        nvidia.close()

    assert str(client_error.value) == str(startup_error.value) == llm_incomplete(*missing)
    assert llm.requests == [] and nvidia.requests == []
    assert [value for value in (LLM_KEY, NVIDIA_KEY, llm.url, nvidia.url) if value in str(client_error.value)] == []


def test_complete_llm_settings_replace_every_nvidia_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    llm, nvidia = FakeModel("ok"), FakeModel("ok")
    for name, value in {"NVIDIA_API_KEY": NVIDIA_KEY, "NVIDIA_BASE_URL": nvidia.url, "NVIDIA_MODEL": "nvidia/model",
                        "LLM_API_KEY": f" {LLM_KEY}\n", "LLM_BASE_URL": llm.url, "LLM_MODEL": "llm/model"}.items():
        monkeypatch.setenv(name, value)
    try:
        client = agent.build_client()
        asyncio.run(client.chat.completions.create(model=agent.provider_setting("MODEL"),
                                                   messages=[{"role": "user", "content": "x"}]))
    finally:
        llm.close()
        nvidia.close()

    assert agent.provider_api_key() == LLM_KEY
    assert nvidia.requests == []
    [request] = llm.requests
    assert request["auth"] == f"Bearer {LLM_KEY}"
    assert request["body"]["model"] == "llm/model"
    assert NVIDIA_KEY[:8] not in "\n".join(request["headers"].values()) + json.dumps(request["body"])


def test_nvidia_settings_apply_when_no_llm_variable_is_set(monkeypatch: pytest.MonkeyPatch, fake: FakeModel) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)
    monkeypatch.setenv("NVIDIA_MODEL", "nvidia/model")
    client = agent.build_client()
    asyncio.run(client.chat.completions.create(model=agent.provider_setting("MODEL"),
                                               messages=[{"role": "user", "content": "x"}]))

    [request] = fake.requests
    assert request["auth"] == f"Bearer {NVIDIA_KEY}"
    assert request["body"]["model"] == "nvidia/model"


def test_missing_base_url_is_refused_rather_than_read_from_openai_base_url(monkeypatch: pytest.MonkeyPatch,
                                                                           fake: FakeModel) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", fake.url)
    monkeypatch.delenv("NVIDIA_BASE_URL")
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)
    with pytest.raises(RuntimeError) as excinfo:
        agent.build_client()
    assert str(excinfo.value) == "NVIDIA_BASE_URL is unset or blank; set it in .env"
    assert fake.requests == []


def test_client_uses_nvidia_key(monkeypatch: pytest.MonkeyPatch, fake: FakeModel) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)
    client = agent.build_client()
    assert client.api_key == NVIDIA_KEY

    asyncio.run(client.chat.completions.create(model="fake/model", messages=[{"role": "user", "content": "x"}]))
    assert [request["auth"] for request in fake.requests] == [f"Bearer {NVIDIA_KEY}"]


def test_key_is_stripped(monkeypatch: pytest.MonkeyPatch, fake: FakeModel) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", f"  {NVIDIA_KEY} \n")
    assert agent.provider_api_key() == NVIDIA_KEY
    client = agent.build_client()
    assert client.api_key == NVIDIA_KEY

    asyncio.run(client.chat.completions.create(model="fake/model", messages=[{"role": "user", "content": "x"}]))
    assert [request["auth"] for request in fake.requests] == [f"Bearer {NVIDIA_KEY}"]


def test_openai_environment_does_not_reach_the_provider(monkeypatch: pytest.MonkeyPatch, fake: FakeModel) -> None:
    for name, value in OPENAI_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)

    client = agent.build_client()
    asyncio.run(client.chat.completions.create(model="fake/model", messages=[{"role": "user", "content": "x"}]))
    [request] = fake.requests
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == f"Bearer {NVIDIA_KEY}"
    assert not {"openai-organization", "openai-project"} & {name.lower() for name in request["headers"]}
    sent = request["path"] + "\n".join(request["headers"].values())
    assert [value for value in OPENAI_ENVIRONMENT.values() if value in sent] == []


def test_openai_environment_does_not_reach_the_provider_under_llm_settings(monkeypatch: pytest.MonkeyPatch,
                                                                         fake: FakeModel) -> None:
    for name, value in OPENAI_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    poisoned = FakeModel("ok")  # what NVIDIA_BASE_URL points at; LLM_BASE_URL wins, so it is never asked
    monkeypatch.setenv("NVIDIA_BASE_URL", poisoned.url)
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)
    monkeypatch.setenv("LLM_BASE_URL", fake.url)
    monkeypatch.setenv("LLM_API_KEY", f" {LLM_KEY}\n")
    monkeypatch.setenv("LLM_MODEL", "llm/model")
    try:
        client = agent.build_client()
        asyncio.run(client.chat.completions.create(model="fake/model", messages=[{"role": "user", "content": "x"}]))
    finally:
        poisoned.close()

    assert poisoned.requests == []
    [request] = fake.requests
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == f"Bearer {LLM_KEY}"
    assert not {"openai-organization", "openai-project"} & {name.lower() for name in request["headers"]}
    sent = request["path"] + "\n".join(request["headers"].values())
    assert [value for value in [*OPENAI_ENVIRONMENT.values(), NVIDIA_KEY] if value in sent] == []
    assert NVIDIA_KEY not in json.dumps(request["body"])


CUSTOM_HEADERS = ["Authorization: Bearer sk-custom-dummy\nX-Dummy: custom-dummy", "", "   \t\n"]


CUSTOM_HEADERS_REFUSAL = ("OPENAI_CUSTOM_HEADERS is set; the OpenAI SDK would send its headers, Authorization"
                          " included, to the provider. Unset it.")
KEY_SETTINGS = [{"NVIDIA_API_KEY": NVIDIA_KEY},
                {"LLM_API_KEY": LLM_KEY, "LLM_BASE_URL": "http://127.0.0.1:9/v1", "LLM_MODEL": "llm/model",
                 "NVIDIA_API_KEY": NVIDIA_KEY}]


@pytest.mark.parametrize("keys", KEY_SETTINGS, ids=["nvidia", "llm"])
@pytest.mark.parametrize("custom_headers", CUSTOM_HEADERS, ids=["headers", "empty", "whitespace"])
def test_openai_custom_headers_are_refused(monkeypatch: pytest.MonkeyPatch, fake: FakeModel,
                                           custom_headers: str, keys: dict[str, str]) -> None:
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", custom_headers)
    for name, value in keys.items():
        monkeypatch.setenv(name, value)
    if "LLM_API_KEY" in keys:
        monkeypatch.setenv("LLM_BASE_URL", fake.url)
    with pytest.raises(RuntimeError) as excinfo:
        agent.build_client()
    assert str(excinfo.value) == CUSTOM_HEADERS_REFUSAL
    assert fake.requests == []


@pytest.mark.parametrize("keys", KEY_SETTINGS, ids=["nvidia", "llm"])
@pytest.mark.parametrize("custom_headers", CUSTOM_HEADERS, ids=["headers", "empty", "whitespace"])
def test_startup_refuses_openai_custom_headers(monkeypatch: pytest.MonkeyPatch, custom_headers: str,
                                               keys: dict[str, str]) -> None:
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", custom_headers)
    for name, value in keys.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("NVIDIA_BASE_URL", raising=False)
    monkeypatch.setattr(main, "get_connection", no_database)
    with pytest.raises(RuntimeError) as excinfo:
        with TestClient(main.app):
            pass
    assert str(excinfo.value) == CUSTOM_HEADERS_REFUSAL


def test_startup_without_openai_custom_headers_runs_the_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_CUSTOM_HEADERS", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)
    monkeypatch.delenv("NVIDIA_BASE_URL", raising=False)
    sweeps: list[str] = []

    @contextmanager
    def fake_connection() -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(execute=lambda sql: sweeps.append(sql) or SimpleNamespace(rowcount=0))

    monkeypatch.setattr(main, "get_connection", fake_connection)
    with TestClient(main.app):
        pass
    assert len(sweeps) == 1 and "status = 'running'" in sweeps[0]


def echo(status: int, text: str) -> tuple[int, str, bytes]:
    return status, "application/json", json.dumps({"error": {"message": f"Incorrect API key provided: {text}"}}).encode()


def failed_investigation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, modes: list,
                         keys: dict[str, str] | None = None) -> tuple[str, str]:
    """run_investigation(8) with the real client against FakeModel(modes), the real MCP servers and a fake
    database, with the key variables in `keys` set (default NVIDIA_API_KEY only) and the other one unset.
    Returns the error column it wrote and the body of GET /investigations/8 for that row."""
    model = FakeModel(modes)
    monkeypatch.setenv("NVIDIA_BASE_URL", model.url)
    keys = {"NVIDIA_API_KEY": NVIDIA_KEY} if keys is None else keys
    for name in ("LLM_API_KEY", "NVIDIA_API_KEY"):
        if name in keys:
            monkeypatch.setenv(name, keys[name])
        else:
            monkeypatch.delenv(name, raising=False)
    if "LLM_API_KEY" in keys:
        monkeypatch.setenv("LLM_BASE_URL", model.url)
        monkeypatch.setenv("LLM_MODEL", "fake/model")
    monkeypatch.setenv("NVIDIA_MODEL", "fake/model")
    (tmp_path / "note.txt").write_text("hello")
    monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
    monkeypatch.setattr(agent, "RETRY_DELAYS", (0, 0))
    executed: list[tuple] = []
    result = SimpleNamespace(fetchone=lambda: ("note.txt", "file"), fetchall=lambda: [])

    @contextmanager
    def agent_connection() -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(execute=lambda *args: executed.append(args) or result)

    monkeypatch.setattr(agent, "get_connection", agent_connection)
    try:
        agent.run_investigation(8)
    finally:
        model.close()

    [(status, report, error, _)] = [params for sql, *params in executed if sql.startswith("UPDATE investigations")
                                    for params in params]
    assert (status, report) == ("failed", None)
    cursor = SimpleNamespace(execute=lambda *args: None, fetchone=lambda: (8, "note.txt", "file", status, report, error))

    @contextmanager
    def main_connection() -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(cursor=lambda: nullcontext(cursor))

    monkeypatch.setattr(main, "get_connection", main_connection)
    return error, TestClient(main.app).get("/investigations/8").text


@pytest.mark.parametrize("modes", [
    [echo(401, NVIDIA_KEY)],
    [echo(500, NVIDIA_KEY[:12])],
    ["ok", echo(400, NVIDIA_KEY[:12])],
    ["ok", echo(500, NVIDIA_KEY)],
], ids=["turn 4xx key", "turn 5xx prefix", "report 4xx prefix", "report 5xx key"])
def test_provider_error_text_is_redacted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                                         caplog: pytest.LogCaptureFixture, modes: list) -> None:
    caplog.set_level(logging.DEBUG)
    error, body = failed_investigation(monkeypatch, tmp_path, modes)

    assert "[key]" in error and "[key]" in caplog.text
    for text in (error, body, caplog.text, *(record.getMessage() for record in caplog.records)):
        assert NVIDIA_KEY[:8] not in text


REDACTION_KEYS = [{"LLM_API_KEY": LLM_KEY}, {"LLM_API_KEY": LLM_KEY, "NVIDIA_API_KEY": NVIDIA_KEY}]


@pytest.mark.parametrize("keys", REDACTION_KEYS, ids=["llm", "both"])
@pytest.mark.parametrize("phase", ["turn", "report"])
def test_provider_error_text_is_redacted_for_every_key_variable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                                                                caplog: pytest.LogCaptureFixture, phase: str,
                                                                keys: dict[str, str]) -> None:
    echoed = echo(401, " ".join(f"{key} and {key[:12]}" for key in keys.values()))
    caplog.set_level(logging.DEBUG)
    error, body = failed_investigation(monkeypatch, tmp_path, [echoed] if phase == "turn" else ["ok", echoed], keys)

    assert error.count("[key]") == 2 * len(keys) and "[key]" in caplog.text
    for text in (error, body, caplog.text, *(record.getMessage() for record in caplog.records)):
        assert [key for key in keys.values() if key[:8] in text] == []


def test_extra_content_on_a_tool_call_is_sent_back_unchanged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Fields a provider adds to a tool call (here a thought signature) must reach it again in the next request."""
    extra = {"google": {"thought_signature": "c2lnbmF0dXJl"}}
    turn = {"id": "x", "object": "chat.completion", "created": 0, "model": "fake/model",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [{
                    "id": "c1", "type": "function", "extra_content": extra,
                    "function": {"name": "analyze_file", "arguments": json.dumps({"path": "note.txt"})}}]}}]}
    models: list[FakeModel] = []
    real_fake_model = FakeModel
    monkeypatch.setitem(globals(), "FakeModel", lambda modes: models.append(real_fake_model(modes)) or models[-1])
    # the report call gets "o", not JSON, so the run fails after the second request
    failed_investigation(monkeypatch, tmp_path, [(200, "application/json", json.dumps(turn).encode()), "ok"])
    requests = models[0].requests

    assert len(requests) >= 2
    [assistant] = [message for message in requests[1]["body"]["messages"] if message["role"] == "assistant"]
    assert assistant["tool_calls"][0]["extra_content"] == extra
    assert assistant["tool_calls"][0]["id"] == "c1"


def test_exception_text_is_redacted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                                    caplog: pytest.LogCaptureFixture) -> None:
    async def failing_call(*args: object) -> None:
        raise RuntimeError(f"unexpected failure for\n  {NVIDIA_KEY}")

    monkeypatch.setattr(agent, "_call_with_retries", failing_call)
    caplog.set_level(logging.DEBUG)
    error, body = failed_investigation(monkeypatch, tmp_path, ["ok"])

    assert error == "RuntimeError: unexpected failure for [key]"
    assert "[key]" in caplog.text
    for text in (error, body, caplog.text, *(record.getMessage() for record in caplog.records)):
        assert NVIDIA_KEY[:8] not in text


@pytest.mark.parametrize("keys", [{"NVIDIA_API_KEY": NVIDIA_KEY}, *REDACTION_KEYS], ids=["nvidia", "llm", "both"])
def test_tool_output_and_report_are_redacted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                                             keys: dict[str, str]) -> None:
    """A tool that returns, and one that raises, text holding every configured key; the model quotes them in
    its findings. Runs against a throwaway charon_test_redaction database, dropped afterwards."""
    secrets = list(keys.values())
    from app.db import DATABASE_URL

    try:
        admin = psycopg.connect(DATABASE_URL, autocommit=True)
    except psycopg.OperationalError:
        pytest.skip("PostgreSQL not reachable")
    test_url = conninfo.make_conninfo(DATABASE_URL, dbname="charon_test_redaction")
    with admin:
        admin.execute("DROP DATABASE IF EXISTS charon_test_redaction WITH (FORCE)")
        admin.execute("CREATE DATABASE charon_test_redaction")
    try:
        with psycopg.connect(test_url) as conn:
            conn.execute((Path(__file__).resolve().parents[1] / "db" / "schema.sql").read_text())
            investigation_id = conn.execute(
                "INSERT INTO investigations (submitted_input, input_type) VALUES ('note.txt', 'file') RETURNING id"
            ).fetchone()[0]

        async def call_tool(self: object, name: str, arguments: dict, **kwargs: object) -> CallToolResult:
            if name == "lookup_indicator":
                raise McpError(ErrorData(code=-32000, message="lookup failed for "
                                         + " ".join(key[:12] for key in secrets)))
            text = json.dumps({"path": "note.txt", "comment": " ".join(f"holds {key} and {key[:10]}"
                                                                      for key in secrets)})
            return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)

        (tmp_path / "note.txt").write_text("hello")
        monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
        monkeypatch.setenv("NVIDIA_BASE_URL", "unused")
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        for name, value in keys.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("NVIDIA_MODEL", "unused")
        if "LLM_API_KEY" in keys:
            monkeypatch.setenv("LLM_BASE_URL", "unused")
            monkeypatch.setenv("LLM_MODEL", "unused")
        monkeypatch.setattr(agent.ClientSession, "call_tool", call_tool)
        monkeypatch.setattr(agent, "get_connection", lambda: psycopg.connect(test_url))
        monkeypatch.setattr(main, "get_connection", lambda: psycopg.connect(test_url))
        logged: list[tuple] = []  # FakeLLM only uses this for its "logged before seen" check
        real_log = agent._log_tool_call
        monkeypatch.setattr(agent, "_log_tool_call", lambda *args: (logged.append(args), real_log(*args)))
        fake_llm = FakeLLM(logged, turns=[[tool_call("c1", "analyze_file", {"path": "note.txt"}),
                                           tool_call("c2", "lookup_indicator", {"path_or_value": "note.txt"})], []],
                           findings=[{"claim": "the comment holds " + " ".join(secrets), "source_tool": "sandbox"},
                                     {"claim": "intel names " + " ".join(key[:9] for key in secrets),
                                      "source_tool": "threat_intel"}])
        monkeypatch.setattr(agent, "AsyncOpenAI", lambda **kwargs: fake_llm)

        agent.run_investigation(investigation_id)

        with psycopg.connect(test_url) as conn:
            report, error = conn.execute("SELECT report, error FROM investigations WHERE id = %s",
                                         (investigation_id,)).fetchone()
            outputs = dict(conn.execute("SELECT tool_name, output_payload FROM tool_calls WHERE investigation_id = %s",
                                        (investigation_id,)).fetchall())
        body = TestClient(main.app).get(f"/investigations/{investigation_id}").text
    finally:
        with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
            admin.execute("DROP DATABASE IF EXISTS charon_test_redaction WITH (FORCE)")

    assert "[key]" in outputs["sandbox"] and "[key]" in outputs["threat_intel"] and "[key]" in report
    assert json.loads(outputs["sandbox"])["comment"] == " ".join(["holds [key] and [key]"] * len(secrets))
    assert outputs["threat_intel"] == "error: lookup failed for " + " ".join(["[key]"] * len(secrets))
    assert json.loads(report)["findings"] == [{"claim": "the comment holds " + " ".join(["[key]"] * len(secrets)),
                                               "source_tool": "sandbox"}]
    for text in (*outputs.values(), report, error, body):
        assert [key for key in secrets if key[:8] in text] == []


@pytest.mark.parametrize("variable", ["NVIDIA_API_KEY", "LLM_API_KEY"])
@pytest.mark.parametrize("offset", range(488, 500))
def test_stored_error_is_redacted_before_the_cut(monkeypatch: pytest.MonkeyPatch, offset: int, variable: str) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", NVIDIA_KEY)
    monkeypatch.setenv("LLM_API_KEY", LLM_KEY)
    key = {"NVIDIA_API_KEY": NVIDIA_KEY, "LLM_API_KEY": LLM_KEY}[variable]
    executed: list[tuple] = []

    @contextmanager
    def connection() -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(execute=lambda *args: executed.append(args))

    monkeypatch.setattr(agent, "get_connection", connection)
    agent._set_status(8, "failed", None, "x" * offset + key + " tail")

    [(_, (_, _, error, _))] = executed
    assert len(error) <= 500
    assert [key[i:i + 5] for i in range(len(key) - 4) if key[i:i + 5] in error] == []
