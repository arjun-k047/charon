import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

import app.db  # noqa: F401 (loads .env now, so a later first import cannot refill variables a test has unset)

LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture(autouse=True)
def localhost_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[object]]:
    """Refuses, and fails the test on, any Python socket connection to a host other than localhost. libpq opens
    its own sockets, so database connections are not affected."""
    attempts: list[object] = []
    connect = socket.socket.connect

    def guarded_connect(sock: socket.socket, address: object) -> None:
        if not (isinstance(address, tuple) and address[0] in LOCAL_HOSTS):
            attempts.append(address)
            raise OSError(f"test guard: {address} is not localhost")
        connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield attempts
    assert attempts == [], f"tests tried to reach a non-localhost host: {attempts}"


@pytest.fixture(autouse=True)
def no_llm_settings_from_dotenv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unsets the LLM_* provider settings that app/db.py may load from .env. They win over NVIDIA_*, so a test
    that configures NVIDIA_* would otherwise send its requests, with the real key, to the real provider."""
    for name in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def intake_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Points CHARON_INTAKE_DIR at the test's own tmp_path. The tool server tests apply it to every test with
    `pytestmark`."""
    monkeypatch.setenv("CHARON_INTAKE_DIR", str(tmp_path))
    return tmp_path
