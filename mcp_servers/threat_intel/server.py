"""
threat_intel MCP tool server - lookup against a local, static indicator list.

indicators.csv is a small stale-by-design snapshot (EICAR + a few verbatim
abuse.ch URLhaus entries), not a live feed. No network calls are made:
nothing submitted to this tool leaves the machine.
"""

import csv
import hashlib
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from mcp_servers.sandbox.server import resolve_intake_path

mcp = FastMCP("threat_intel")

INDICATORS_FILE = Path(__file__).with_name("indicators.csv")


def _load_indicators() -> list[dict[str, str]]:
    with open(INDICATORS_FILE, newline="") as f:
        return list(csv.DictReader(line for line in f if not line.startswith("#")))


INDICATORS = _load_indicators()


def _matches(value: str) -> list[dict[str, str]]:
    value = value.strip().lower()
    found = []
    for row in INDICATORS:
        indicator = row["indicator"].lower()
        if value == indicator:
            found.append({**row, "match": "exact"})
        elif row["type"] == "url" and value == (urlsplit(indicator).hostname or ""):
            # a bare IP/domain (e.g. from traffic_summary) matches a URL hosted on it
            found.append({**row, "match": "url_host"})
    return found


@mcp.tool()
def lookup_indicator(path_or_value: str) -> dict:
    """Look up an indicator in the local threat-intel list. If the argument
    names a file in the intake directory, its MD5/SHA-1/SHA-256 are looked
    up; otherwise it is treated as a literal hash, URL, IP, or domain."""
    try:
        resolved = resolve_intake_path(path_or_value)
    except (OSError, ValueError):
        # Not an intake file (or outside the intake dir): never read it, treat as a literal value.
        return {"input": path_or_value, "kind": "value", "matches": _matches(path_or_value)}

    data = resolved.read_bytes()
    hashes = {name: hashlib.new(name, data).hexdigest() for name in ("md5", "sha1", "sha256")}
    return {
        "input": path_or_value,
        "kind": "file",
        "hashes": hashes,
        "matches": [m for digest in hashes.values() for m in _matches(digest)],
    }


if __name__ == "__main__":
    mcp.run()
