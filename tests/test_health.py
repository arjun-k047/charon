import socket
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import main

from app.main import app

client = TestClient(app)


def test_network_guard_applies_without_being_imported(request: pytest.FixtureRequest) -> None:
    """The localhost-only guard comes from tests/conftest.py, so it covers this file, which never imports it."""
    assert "localhost_only" in request.fixturenames
    attempts = request.getfixturevalue("localhost_only")
    with pytest.raises(OSError, match="test guard"):
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    assert attempts.pop() == ("192.0.2.1", 443)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


class _Context:
    def __init__(self, value: object) -> None:
        self.value = value

    def __enter__(self) -> object:
        return self.value

    def __exit__(self, *exc: object) -> None:
        return None


def test_get_investigation_includes_error(monkeypatch: pytest.MonkeyPatch) -> None:
    row = (17, "sample_phish.png", "file", "failed", None, "InternalServerError: Error code: 500")
    cursor = SimpleNamespace(execute=lambda *args: None, fetchone=lambda: row)
    monkeypatch.setattr(main, "get_connection", lambda: _Context(SimpleNamespace(cursor=lambda: _Context(cursor))))

    resp = client.get("/investigations/17")

    assert resp.status_code == 200
    assert resp.json() == {"id": 17, "submitted_input": "sample_phish.png", "input_type": "file",
                           "status": "failed", "report": None, "error": "InternalServerError: Error code: 500"}


def test_startup_marks_orphaned_running_investigations_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []

    def execute(sql: str, *args: object) -> SimpleNamespace:
        executed.append(sql)
        return SimpleNamespace(rowcount=2)

    monkeypatch.setenv("NVIDIA_API_KEY", "fake-nim-key-0123456789")
    monkeypatch.setattr(main, "get_connection", lambda: _Context(SimpleNamespace(execute=execute)))

    with TestClient(main.app):  # entering the client runs the lifespan startup
        pass

    [sql] = executed
    assert "SET status = 'failed', error = 'server restarted before completion'" in sql
    assert "WHERE status = 'running'" in sql
