import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redteam import run as harness

API_KEY = "sk-preflight-test-key-" + "0123456789" * 5  # about as long as a real key, so it can straddle a cut
MODEL = "fake/model"
DEV_URL = "postgresql://charon:secret@localhost:5432/charon"


class FakeModel:
    """An OpenAI-compatible /chat/completions endpoint on a random localhost port. Given a list of modes,
    it answers the nth request with the nth mode, and every later request with the last one."""

    def __init__(self, mode: str | tuple[int, str, bytes] | list[str | tuple[int, str, bytes]]) -> None:
        self.requests: list[dict] = []
        fake = self
        modes = mode if isinstance(mode, list) else [mode]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append({"path": self.path, "auth": self.headers["Authorization"], "body": body,
                                      "headers": dict(self.headers)})
                mode = modes[min(len(fake.requests), len(modes)) - 1]
                if mode == "hang":
                    time.sleep(3)
                    return
                if mode == "redirect_loop":
                    self.send_response(307)
                    self.send_header("Location", self.path)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if mode == "trickle":  # a header line every 0.5 s: no single read times out, the response never ends
                    try:
                        self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                        for _ in range(16):
                            self.wfile.flush()
                            time.sleep(0.5)
                            self.wfile.write(b"X-Pad: a\r\n")
                    except OSError:
                        pass
                    return
                if isinstance(mode, tuple):  # (status, content type, raw body)
                    status, content_type, data = mode
                else:
                    status, payload = {
                        "ok": (200, {"id": "x", "object": "chat.completion", "created": 0, "model": MODEL,
                                     "choices": [{"index": 0, "finish_reason": "length",
                                                  "message": {"role": "assistant", "content": "o"}}]}),
                        "500": (500, {"error": {"message": "upstream exploded"}}),
                        "400": (400, {"error": {"message": "model fake/model does not exist"}}),
                    }[mode]
                    content_type, data = "application/json", json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def refused_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}/v1"


class StopAfterPreflight(Exception):
    pass


def run_main(monkeypatch: pytest.MonkeyPatch, base_url: str, *args: str, key: str | None = API_KEY,
             llm_key: str | None = None, overrides: dict[str, str | None] | None = None) -> dict[str, list]:
    """main() with the model settings pointed at `base_url` and the database, file generation and server
    replaced by recorders; the first database step raises StopAfterPreflight. touched["raised"] holds the
    SystemExit or StopAfterPreflight raised, or None if main() returned. A `key` of None unsets NVIDIA_API_KEY.
    An `llm_key` also sets LLM_API_KEY to it, with LLM_BASE_URL and LLM_MODEL equal to the NVIDIA_* values.
    `overrides` sets variables last; None unsets one."""
    touched: dict[str, list] = {"database": [], "server": [], "files": [], "cases": []}

    def fake_connect(*connect_args: object, **kwargs: object) -> None:
        touched["database"].append(connect_args)
        raise StopAfterPreflight

    monkeypatch.setenv("NVIDIA_BASE_URL", base_url)
    if key is None:
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NVIDIA_API_KEY", key)
    monkeypatch.setenv("NVIDIA_MODEL", MODEL)
    if llm_key is not None:
        monkeypatch.setenv("LLM_API_KEY", llm_key)
        monkeypatch.setenv("LLM_BASE_URL", base_url)
        monkeypatch.setenv("LLM_MODEL", MODEL)
    for name, value in (overrides or {}).items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.setattr("app.db.DATABASE_URL", DEV_URL)
    monkeypatch.setattr(harness.psycopg, "connect", fake_connect)
    monkeypatch.setattr(harness, "make_files", lambda: touched["files"].append(True))
    select_cases = harness.select_cases
    monkeypatch.setattr(harness, "select_cases", lambda names: touched["cases"].append(names) or select_cases(names))
    popen = harness.subprocess.Popen

    def fake_popen(command: list[str], *popen_args: object, **kwargs: object) -> object:
        if "uvicorn" not in command:  # the OpenAI client's platform lookup runs uname
            return popen(command, *popen_args, **kwargs)
        touched["server"].append(command)

    monkeypatch.setattr(harness.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(harness.sys, "argv", ["run", "--runs", "1", *args])
    try:
        harness.main()
    except (SystemExit, StopAfterPreflight) as exc:
        touched["raised"] = [exc]
    else:
        touched["raised"] = [None]
    return touched


def test_successful_preflight_prints_one_line_and_continues(monkeypatch: pytest.MonkeyPatch,
                                                           capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url)
    finally:
        fake.close()

    out = capsys.readouterr()
    assert isinstance(touched["raised"][0], StopAfterPreflight)  # reached the database step
    assert len(touched["database"]) == 1
    assert len(fake.requests) == 1
    request = fake.requests[0]
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == f"Bearer {API_KEY}"
    assert request["body"]["model"] == MODEL and "tools" not in request["body"]
    assert request["body"]["max_tokens"] == 1
    lines = out.out.splitlines()
    assert len(lines) == 1 and lines[0].startswith(f"preflight: {MODEL} answered in ") and lines[0].endswith(" s")
    assert API_KEY not in out.out + out.err


@pytest.mark.parametrize("mode, message", [
    ("500", f"preflight failed for {MODEL}: HTTP 500: upstream exploded"),
    ("400", f"preflight failed for {MODEL}: HTTP 400: model fake/model does not exist"),
    ("hang", f"preflight failed for {MODEL}: no response within 1 s"),
    ("refused", f"preflight failed for {MODEL}: connection failed: "),
])
def test_failed_preflight_exits_before_the_database_and_server(monkeypatch: pytest.MonkeyPatch,
                                                              capsys: pytest.CaptureFixture[str], mode: str,
                                                              message: str) -> None:
    fake = None if mode == "refused" else FakeModel(mode)
    started = time.monotonic()
    try:
        touched = run_main(monkeypatch, fake.url if fake else refused_url(), "--preflight-timeout", "1")
    finally:
        if fake:
            fake.close()

    elapsed = time.monotonic() - started
    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit) and exit_code.code not in (None, 0)
    assert str(exit_code.code).startswith(message) and "\n" not in str(exit_code.code)
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == []
    assert out.out == ""  # no success line and no outcome table
    assert API_KEY not in str(exit_code.code) + out.out + out.err
    assert elapsed < 2.5  # the 1 s preflight timeout bounds the hang, with no retries


def failed_preflight(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
                     mode: str | tuple[int, str, bytes], llm_key: str | None = None) -> tuple[str, str]:
    """The exit message of a preflight against FakeModel(mode) that must fail, and everything printed."""
    fake = FakeModel(mode)
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-timeout", "1", llm_key=llm_key)
    finally:
        fake.close()
    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit) and exit_code.code not in (None, 0)
    assert touched["database"] == [] and out.out == ""
    return str(exit_code.code), out.out + out.err


def text_body(status: int, text: str) -> tuple[int, str, bytes]:
    return status, "text/plain", text.encode()


def json_message(status: int, message: str) -> tuple[int, str, bytes]:
    return status, "application/json", json.dumps({"error": {"message": message}}).encode()


@pytest.mark.parametrize("offset", [0, 250, 252, 270, 280, 285, 290, 295, 299, 300, 305])
def test_key_in_a_text_body_is_redacted_at_any_offset(monkeypatch: pytest.MonkeyPatch,
                                                      capsys: pytest.CaptureFixture[str], offset: int) -> None:
    message, printed = failed_preflight(monkeypatch, capsys, text_body(401, "x" * offset + API_KEY + " tail"))

    assert message.startswith(f"preflight failed for {MODEL}: HTTP 401: ")
    assert API_KEY[:8] not in message + printed
    assert not any(message.endswith(API_KEY[:length]) for length in range(1, 8))  # redacted before the cut


def test_key_at_the_end_of_a_252_character_text_body_is_redacted(monkeypatch: pytest.MonkeyPatch,
                                                                 capsys: pytest.CaptureFixture[str]) -> None:
    message, printed = failed_preflight(monkeypatch, capsys, text_body(401, "x" * 252 + API_KEY))

    assert message == f"preflight failed for {MODEL}: HTTP 401: {'x' * 252}[key]"
    assert API_KEY[:8] not in message + printed


@pytest.mark.parametrize("echoed", [API_KEY, API_KEY[:8], API_KEY[:12] + "****"])
def test_key_or_its_prefix_in_a_json_message_is_redacted(monkeypatch: pytest.MonkeyPatch,
                                                        capsys: pytest.CaptureFixture[str], echoed: str) -> None:
    message, printed = failed_preflight(monkeypatch, capsys, json_message(401, f"Incorrect API key: {echoed}."))

    assert message.startswith(f"preflight failed for {MODEL}: HTTP 401: Incorrect API key: [key]")
    assert API_KEY[:8] not in message + printed


def test_a_long_json_message_is_truncated(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    message, printed = failed_preflight(monkeypatch, capsys, json_message(400, "E" * 100_000 + API_KEY))

    assert message == f"preflight failed for {MODEL}: " + ("HTTP 400: " + "E" * 100_000)[:harness.EVIDENCE_CHARS]
    assert API_KEY[:8] not in message + printed


@pytest.mark.parametrize("key", [None, "", " ", " \t\n"], ids=["unset", "empty", "space", "whitespace"])
def test_a_missing_key_fails_the_preflight_without_a_request(monkeypatch: pytest.MonkeyPatch,
                                                             capsys: pytest.CaptureFixture[str], key: str | None) -> None:
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only", key=key)
    finally:
        fake.close()

    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit)
    assert exit_code.code == (f"preflight failed for {MODEL}: NVIDIA_API_KEY is unset or empty; set it, or set all"
                              " of LLM_API_KEY, LLM_BASE_URL and LLM_MODEL, in .env")
    assert fake.requests == [] and out.out == "" and "Traceback" not in out.err
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == []


OPENAI_ENVIRONMENT = {
    "OPENAI_API_KEY": "sk-openai-dummy",
    "OPENAI_ADMIN_KEY": "sk-admin-dummy",
    "OPENAI_ORG_ID": "org-dummy",
    "OPENAI_PROJECT_ID": "proj-dummy",
    "OPENAI_WEBHOOK_SECRET": "whsec-dummy",
    "OPENAI_BASE_URL": "http://127.0.0.1:9/openai-base-dummy",
    "OPENAI_API_VERSION": "api-version-dummy",
    "OPENAI_API_TYPE": "azure",
    "AZURE_OPENAI_ENDPOINT": "http://127.0.0.1:9/azure-endpoint-dummy",
    "AZURE_OPENAI_API_KEY": "azure-key-dummy",
    "AZURE_OPENAI_AD_TOKEN": "azure-token-dummy",
}


def test_preflight_sends_only_the_stripped_nvidia_key(monkeypatch: pytest.MonkeyPatch,
                                                      capsys: pytest.CaptureFixture[str]) -> None:
    for name, value in OPENAI_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only", key=f"  {API_KEY} \n")
    finally:
        fake.close()

    assert touched["raised"] == [None]
    [request] = fake.requests
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == f"Bearer {API_KEY}"
    assert not {"openai-organization", "openai-project"} & {name.lower() for name in request["headers"]}
    sent = request["path"] + "\n".join(request["headers"].values())
    assert [value for value in OPENAI_ENVIRONMENT.values() if value in sent] == []


LLM_KEY = "llm-preflight-test-key-" + "9876543210" * 5
LLM_MODEL = "llm/model"


@pytest.mark.parametrize("value", [None, " \t\n"], ids=["unset", "whitespace"])
@pytest.mark.parametrize("variable, model", [("NVIDIA_MODEL", "(model not set)"), ("NVIDIA_BASE_URL", MODEL)])
def test_a_missing_nvidia_model_or_base_url_fails_the_preflight_without_a_request(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], variable: str, model: str,
        value: str | None) -> None:
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only", overrides={variable: value})
    finally:
        fake.close()

    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit) and isinstance(exit_code.code, str)  # a message exits with status 1
    assert exit_code.code == f"preflight failed for {model}: {variable} is unset or blank; set it in .env"
    assert fake.requests == []
    assert out.out == "" and "Traceback" not in out.err
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == []


def llm_incomplete(*missing: str) -> str:
    return (f"not set or blank: {', '.join(missing)}; all of LLM_API_KEY, LLM_BASE_URL and LLM_MODEL are required"
            " once any of them is set")


@pytest.mark.parametrize("values, missing, model", [
    ({"LLM_BASE_URL": "url"}, ("LLM_API_KEY", "LLM_MODEL"), "(model not set)"),
    ({"LLM_BASE_URL": "url", "LLM_MODEL": LLM_MODEL}, ("LLM_API_KEY",), LLM_MODEL),
    ({"LLM_API_KEY": LLM_KEY, "LLM_MODEL": LLM_MODEL}, ("LLM_BASE_URL",), LLM_MODEL),
    ({"LLM_API_KEY": LLM_KEY, "LLM_BASE_URL": "url"}, ("LLM_MODEL",), "(model not set)"),
    ({"LLM_API_KEY": "", "LLM_BASE_URL": "url", "LLM_MODEL": LLM_MODEL}, ("LLM_API_KEY",), LLM_MODEL),
    ({"LLM_API_KEY": LLM_KEY, "LLM_BASE_URL": " \t", "LLM_MODEL": LLM_MODEL}, ("LLM_BASE_URL",), LLM_MODEL),
    ({"LLM_API_KEY": LLM_KEY, "LLM_BASE_URL": "url", "LLM_MODEL": " "}, ("LLM_MODEL",), "(model not set)"),
    ({"LLM_API_KEY": ""}, ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"), "(model not set)"),
], ids=["base url only", "no key", "no base url", "no model", "empty key", "blank base url", "blank model",
        "empty key alone"])
def test_incomplete_llm_settings_fail_the_preflight_without_a_request(monkeypatch: pytest.MonkeyPatch,
                                                                      capsys: pytest.CaptureFixture[str],
                                                                      values: dict[str, str], missing: tuple[str, ...],
                                                                      model: str) -> None:
    """NVIDIA_* is fully set; once any LLM_* variable is set it is ignored, so nothing fills the gap."""
    nvidia, llm = FakeModel("ok"), FakeModel("ok")
    for name, value in values.items():
        monkeypatch.setenv(name, llm.url if value == "url" else value)
    try:
        touched = run_main(monkeypatch, nvidia.url, "--preflight-only")
    finally:
        nvidia.close()
        llm.close()

    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit)
    assert exit_code.code == f"preflight failed for {model}: {llm_incomplete(*missing)}"
    assert nvidia.requests == [] and llm.requests == []
    assert out.out == "" and "Traceback" not in out.err
    assert [key for key in (API_KEY, LLM_KEY) if key[:8] in str(exit_code.code) + out.err] == []
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == []


def test_preflight_uses_the_llm_settings_over_nvidia(monkeypatch: pytest.MonkeyPatch,
                                                     capsys: pytest.CaptureFixture[str]) -> None:
    for name, value in OPENAI_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    poisoned, fake = FakeModel("ok"), FakeModel("ok")
    monkeypatch.setenv("LLM_BASE_URL", fake.url)
    monkeypatch.setenv("LLM_API_KEY", f" {LLM_KEY}\n")
    monkeypatch.setenv("LLM_MODEL", LLM_MODEL)
    try:
        touched = run_main(monkeypatch, poisoned.url, "--preflight-only")
    finally:
        poisoned.close()
        fake.close()

    assert touched["raised"] == [None]
    assert poisoned.requests == []
    [request] = fake.requests
    assert request["auth"] == f"Bearer {LLM_KEY}"
    assert request["body"]["model"] == LLM_MODEL
    assert not {"openai-organization", "openai-project"} & {name.lower() for name in request["headers"]}
    sent = request["path"] + "\n".join(request["headers"].values())
    assert [value for value in [*OPENAI_ENVIRONMENT.values(), API_KEY] if value in sent] == []
    assert API_KEY[:8] not in json.dumps(request["body"])
    assert capsys.readouterr().out.startswith(f"preflight: {LLM_MODEL} answered in ")


def test_preflight_failure_names_the_llm_model(monkeypatch: pytest.MonkeyPatch,
                                               capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeModel("500")
    monkeypatch.setenv("LLM_API_KEY", LLM_KEY)
    monkeypatch.setenv("LLM_BASE_URL", fake.url)
    monkeypatch.setenv("LLM_MODEL", LLM_MODEL)
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only")
    finally:
        fake.close()

    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit)
    assert exit_code.code == f"preflight failed for {LLM_MODEL}: HTTP 500: upstream exploded"
    [request] = fake.requests
    assert request["body"]["model"] == LLM_MODEL


@pytest.mark.parametrize("llm_key", [None, LLM_KEY], ids=["nvidia only", "both"])
def test_preflight_redacts_every_configured_key(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
                                                llm_key: str | None) -> None:
    keys = [key for key in (API_KEY, llm_key) if key]
    message, printed = failed_preflight(monkeypatch, capsys, text_body(401, " ".join(f"{key[:20]} {key}" for key in keys)),
                                        llm_key=llm_key)

    assert message == f"preflight failed for {MODEL}: HTTP 401: " + " ".join(["[key] [key]"] * len(keys))
    assert [key for key in keys if key[:8] in message + printed] == []


def test_preflight_refuses_openai_custom_headers(monkeypatch: pytest.MonkeyPatch,
                                                 capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", "Authorization: Bearer sk-custom-dummy\nX-Dummy: custom-dummy")
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only")
    finally:
        fake.close()

    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit)
    assert exit_code.code == (f"preflight failed for {MODEL}: OPENAI_CUSTOM_HEADERS is set; the OpenAI SDK would"
                              " send its headers, Authorization included, to the provider. Unset it.")
    assert "dummy" not in str(exit_code.code) + out.out + out.err
    assert fake.requests == [] and "Traceback" not in out.err


def completion(choices: object) -> tuple[int, str, bytes]:
    return 200, "application/json", json.dumps({"id": "x", "object": "chat.completion", "created": 0, "model": MODEL,
                                                "choices": choices}).encode()


@pytest.mark.parametrize("content", [None, ""])
def test_a_choice_without_content_counts_as_answered(monkeypatch: pytest.MonkeyPatch,
                                                     capsys: pytest.CaptureFixture[str], content: str | None) -> None:
    fake = FakeModel(completion([{"index": 0, "finish_reason": "length",
                                  "message": {"role": "assistant", "content": content}}]))
    try:
        touched = run_main(monkeypatch, fake.url)
    finally:
        fake.close()

    assert isinstance(touched["raised"][0], StopAfterPreflight)
    assert capsys.readouterr().out.startswith(f"preflight: {MODEL} answered in ")


@pytest.mark.parametrize("response", [
    completion([]),
    completion(None),
    completion(["o"]),
    (200, "application/json", b"[]"),
    (200, "application/json", b'"o"'),
    (200, "application/json", b"{not json"),
    (200, "text/html", b"<html><body>gateway login</body></html>"),
    (200, "application/json", b""),
], ids=["empty choices", "null choices", "string choice", "json list", "json string", "malformed json", "html",
        "empty body"])
def test_a_200_that_is_not_a_chat_completion_fails(monkeypatch: pytest.MonkeyPatch,
                                                   capsys: pytest.CaptureFixture[str],
                                                   response: tuple[int, str, bytes]) -> None:
    message, printed = failed_preflight(monkeypatch, capsys, response)

    assert message == f"preflight failed for {MODEL}: unexpected response (not a chat completion)"
    assert "Traceback" not in printed


def test_total_deadline_bounds_a_trickling_response(monkeypatch: pytest.MonkeyPatch,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    started = time.monotonic()
    message, _ = failed_preflight(monkeypatch, capsys, "trickle")

    assert message == f"preflight failed for {MODEL}: no response within 1 s"
    assert time.monotonic() - started < 2.5


def test_long_text_is_collapsed_and_truncated(monkeypatch: pytest.MonkeyPatch,
                                              capsys: pytest.CaptureFixture[str]) -> None:
    message, _ = failed_preflight(monkeypatch, capsys, text_body(400, "bad \n\t  request\r\n" + "T" * 1000))

    assert message == f"preflight failed for {MODEL}: " + ("HTTP 400: bad request " + "T" * 1000)[:harness.EVIDENCE_CHARS]


def test_redirect_loop_ends_within_the_deadline(monkeypatch: pytest.MonkeyPatch,
                                                capsys: pytest.CaptureFixture[str]) -> None:
    started = time.monotonic()
    message, _ = failed_preflight(monkeypatch, capsys, "redirect_loop")

    assert message.startswith(f"preflight failed for {MODEL}: ")
    assert time.monotonic() - started < 2.5


def test_default_preflight_timeout_is_30_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []
    monkeypatch.setattr(harness, "preflight", lambda timeout: timeouts.append(timeout))
    run_main(monkeypatch, refused_url())

    assert timeouts == [30]


def test_preflight_only_exits_0_after_the_success_line(monkeypatch: pytest.MonkeyPatch,
                                                        capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only")
    finally:
        fake.close()

    out = capsys.readouterr()
    assert touched["raised"] == [None]  # main() returned, so python -m exits 0
    assert len(fake.requests) == 1
    lines = out.out.splitlines()
    assert len(lines) == 1 and lines[0].startswith(f"preflight: {MODEL} answered in ") and lines[0].endswith(" s")
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == [] and touched["cases"] == []
    assert API_KEY not in out.out + out.err


@pytest.mark.parametrize("mode, message", [
    ("500", f"preflight failed for {MODEL}: HTTP 500: upstream exploded"),
    ("hang", f"preflight failed for {MODEL}: no response within 1 s"),
    ((200, "application/json", b"{not json"), f"preflight failed for {MODEL}: unexpected response (not a chat completion)"),
], ids=["500", "hang", "malformed 200"])
def test_preflight_only_exits_non_zero_after_the_failure_line(monkeypatch: pytest.MonkeyPatch,
                                                              capsys: pytest.CaptureFixture[str],
                                                              mode: str | tuple[int, str, bytes], message: str) -> None:
    fake = FakeModel(mode)
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only", "--preflight-timeout", "1")
    finally:
        fake.close()

    out = capsys.readouterr()
    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit) and exit_code.code not in (None, 0)
    assert str(exit_code.code) == message
    assert out.out == ""
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == [] and touched["cases"] == []


def test_preflight_only_cannot_be_combined_with_skip_preflight(monkeypatch: pytest.MonkeyPatch,
                                                               capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeModel("ok")
    try:
        touched = run_main(monkeypatch, fake.url, "--preflight-only", "--skip-preflight")
    finally:
        fake.close()

    exit_code = touched["raised"][0]
    assert isinstance(exit_code, SystemExit) and exit_code.code == 2  # argparse usage error
    assert "--skip-preflight: not allowed with argument --preflight-only" in capsys.readouterr().err
    assert fake.requests == []
    assert touched["database"] == [] and touched["server"] == [] and touched["files"] == [] and touched["cases"] == []


def test_skip_preflight_sends_no_request(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeModel("500")
    try:
        touched = run_main(monkeypatch, fake.url, "--skip-preflight")
    finally:
        fake.close()

    assert isinstance(touched["raised"][0], StopAfterPreflight)
    assert fake.requests == []
    assert "preflight" not in capsys.readouterr().out


def test_guard_refuses_a_non_localhost_host(localhost_only: list[object]) -> None:
    with pytest.raises(OSError, match="test guard"):
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    assert localhost_only.pop() == ("192.0.2.1", 443)
