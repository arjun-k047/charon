# MCP tool servers

What each tool does is listed in the tool table in the
[design notes](../docs/design.md#tool-servers). This file covers how the servers are
launched and what they accept and return.

Each `<name>/server.py` is a standalone FastMCP server over stdio, started
with `python -m mcp_servers.<name>.server` and tested on its own in
`tests/test_<name>.py`. The agent starts all four as subprocesses for each
investigation.

The file tools resolve their path argument against the intake directory
(`CHARON_INTAKE_DIR`, default `samples/`), symlinks and `..` included. A
path that lands outside it raises `PermissionError`; a path that is not a
regular file raises `ValueError`.

- `sandbox/` exposes `analyze_file(path)`. Page text is kept for the first
  10 pages, at most 2,000 characters per page and 6,000 in total; a page
  whose content streams exceed 100,000 bytes is skipped. Hidden-text
  findings are capped at 20, 300 characters each. Every cap that applies
  is reported as `truncated` or `skipped` in the output.
- `ocr/` exposes `extract_text(path)`. An image is OCR'd directly; for a
  PDF, only images already embedded in its pages are OCR'd. A file that is
  neither returns empty text, and a PDF that fails to parse returns the
  images read so far plus `parse_error`.
- `traffic_summary/` exposes `summarize_pcap(path)`. Every packet is read,
  with no packet cap; each top-N list holds at most 10 entries. A file that
  is not a readable capture raises `ValueError`.
- `threat_intel/` exposes `lookup_indicator(path_or_value)`. An intake file
  is hashed (MD5, SHA-1, SHA-256); any other argument is matched as a
  literal value against `indicators.csv`. It makes no network calls.
