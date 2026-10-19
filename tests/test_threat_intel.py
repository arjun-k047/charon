from pathlib import Path

import pytest

from mcp_servers.threat_intel.server import lookup_indicator

# Built from two halves so this source file itself isn't flagged by AV scanners.
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


pytestmark = pytest.mark.usefixtures("intake_dir")


def test_eicar_file_matches_all_three_hashes(intake_dir: Path) -> None:
    (intake_dir / "eicar.com").write_bytes(EICAR)

    result = lookup_indicator("eicar.com")

    assert result["kind"] == "file"
    assert result["hashes"]["sha256"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert sorted(m["type"] for m in result["matches"]) == ["md5", "sha1", "sha256"]
    assert all("EICAR" in m["threat"] for m in result["matches"])


def test_clean_file_no_matches(intake_dir: Path) -> None:
    (intake_dir / "clean.txt").write_text("hello")
    assert lookup_indicator("clean.txt")["matches"] == []


def test_literal_values() -> None:
    url = lookup_indicator("http://115.50.105.81:59352/i")
    assert url["kind"] == "value"
    assert url["matches"][0]["match"] == "exact"
    assert url["matches"][0]["source"] == "https://urlhaus.abuse.ch/url/3925437/"

    ip = lookup_indicator("115.50.105.81")
    assert ip["matches"][0]["match"] == "url_host"

    assert lookup_indicator("  44D88612FEA8A8F36DE82E1278ABB02F ")["matches"][0]["type"] == "md5"
    assert lookup_indicator("example.com")["matches"] == []


def test_paths_outside_intake_are_never_read(intake_dir: Path) -> None:
    (intake_dir / "link").symlink_to("/etc/passwd")
    for value in ["/etc/passwd", "../../etc/passwd", "link"]:
        result = lookup_indicator(value)
        assert result["kind"] == "value"
        assert "hashes" not in result
        assert result["matches"] == []
