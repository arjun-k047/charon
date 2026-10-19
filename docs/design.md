# Design reference

Detailed behaviour of the tool servers, the agent loop, the data model and
the status rules. The README gives the overview.

A language model (an OpenAI-compatible endpoint, developed and tested with
NVIDIA NIM) decides which tools to call. Files are never executed and
nothing is captured from a live network; all analysis is static. It is a
demonstration project, not a production security tool.

Repository layout:

- `app/`: FastAPI app (`main.py`), agent loop (`agent.py`), database access (`db.py`).
- `mcp_servers/`: one directory per tool server, each runnable and tested on its own.
- `db/schema.sql`: the `investigations` and `tool_calls` tables.
- `redteam/`: the prompt-injection harness and its file generator.
- `tests/`: the pytest suite.
- `docs/`: design reference and red-team method and results.

## Tool servers

| Server | Tool | What it does |
|---|---|---|
| `sandbox` | `analyze_file` | Static structural analysis. Hashes the file and parses it without executing or rendering it: PDF metadata, embedded files, active-content keyword counts, page text and hidden-text findings (pypdf); OLE stream names, sizes and whether a VBA project is present (olefile); image header fields and EXIF (Pillow, pixel data not decoded). |
| `ocr` | `extract_text` | Tesseract OCR on an image, or on the images already embedded in a PDF's pages. PDF pages are not rendered. |
| `traffic_summary` | `summarize_pcap` | Reads a `.pcap`/`.pcapng` file offline with scapy: packet count, time span, protocol counts, top IP flows per direction (`top_flows_by_direction`; A -> B and B -> A counted separately), top destination ports, DNS names queried. No live capture. |
| `threat_intel` | `lookup_indicator` | Looks up a file's MD5/SHA-1/SHA-256, or a literal hash, URL, IP or domain, in a small local indicator file (`mcp_servers/threat_intel/indicators.csv`: six rows, the EICAR test file hashes and three URLhaus URLs). It is a CSV of sample indicators, not a live threat-intelligence feed or a database, and makes no network calls. |

`sandbox` returns PDF page text under `page_text`, labelled `untrusted` and
capped at 10 pages, 2000 characters per page and 6000 in total. A page whose
decoded content, form XObjects included, exceeds 100 KB, or that fails to
decode, is not extracted and is listed under `page_text.skipped`; a cap or a
skip sets `truncated`. Text a viewer would not display is listed under
`hidden_text`, also labelled `untrusted`, with the reasons `white_fill`,
`tiny_font` (under 2 pt), `invisible_render_mode` (render mode 3 or 7),
`off_page` (starts outside the MediaBox) and `transparent_fill` (fill alpha
`/ca` of 0.05 or less, set through an ExtGState; a non-numeric `/ca` is
ignored, and an ExtGState missing from a form XObject's resources is looked
up in the page's); it keeps the first 20 findings and reports `total` and
`truncated`. Hidden-text detection follows form XObjects but not
annotations. `hidden_text` is a best-effort signal, not a guarantee:
`page_text` reaches the model whether or not anything is flagged. A font or
text-stream decode failure (a ToUnicode bomb, for example) drops `page_text`
and `hidden_text` for the whole document and sets `parse_error`; the other
findings are kept. This fails closed: no unchecked page text reaches the
model, and `parse_error` reports the gap. An embedded
file that cannot be decoded is listed with a `decode_error` field instead of
its size and hash. Known limits: an unmatched `Q` makes pypdf reset its
transformation matrix, so tiny or off-page text placed after `cm Q` is not
flagged, although viewers ignore the extra `Q`; text in a form XObject is
sized and placed without the page's `cm` or the form's `/Matrix`; `/ca 0`
with stroked text (render mode 1) is flagged although the stroke is
visible; an alpha between about 0.06 and 0.1 is barely visible but not
flagged; an ExtGState missing from a nested form XObject's resources is
looked up in the page's resources, not in the parent form's; fill colours
in spaces other than gray, RGB and CMYK are read by operand count and can be misjudged either
way (a Separation tint is read inverted); white text on a dark shape is
flagged `white_fill`; white stroke with render mode 1 or 2 is not caught;
transparency from soft masks, blend modes or the stroke alpha `/CA` is not
tracked; text rise (`Ts`) and horizontal scaling (`Tz`) are ignored; the
CropBox is not consulted; movement inside one run from `Tc`, `Tz` or `TJ`
kerning is not tracked; control characters and bidi marks pass through to
the model.

The file tools only read from the intake directory (`CHARON_INTAKE_DIR`,
default `samples/`). Paths are resolved, symlinks included, and anything
that lands outside the directory is refused.

Submit a file from the intake directory, or a URL, then poll for the result.
A file must be placed in `samples/` (the default intake directory) first;
the contents of `samples/` are not tracked in git.

## Agent loop (`app/agent.py`)

For each investigation the loop:

1. Starts the four MCP servers as stdio subprocesses. Startup counts against
   the run's time budget; the servers receive a minimal environment without
   the API key or database URL.
2. Gives the model all four tool schemas and runs a function-calling loop:
   at most 5 tool calls and 240 s in total. Each tool call has a 10 s
   timeout and is retried once if it times out; a retry counts toward the
   5-call limit.
3. Writes every tool call (tool, arguments, output) to `tool_calls` before
   its result is passed back to the model.
4. Asks the model for the report as structured output, built only from the
   logged tool results: 120 s per attempt, at most 250 s in total.

## PostgreSQL (`db/schema.sql`)

- `investigations`: the submitted input, `status`, the final `report`
  (JSON), `error` (why a run failed or is incomplete) and `model` (the model
  id the run was submitted with; `NULL` on rows created before the column
  existed, meaning unknown). Applying `db/schema.sql` again upgrades an
  existing database in place; it only adds missing columns.
- `tool_calls`: one row per tool call attempt, with the input and output
  payloads. This table is what the status rules below are checked against.

## Provider settings

`LLM_BASE_URL` is the base URL of the OpenAI-compatible endpoint that LLM
requests are sent to, `LLM_API_KEY` its key and `LLM_MODEL` the model id;
`.env.example` sets them up for the NVIDIA NIM API. The settings are
all-or-nothing:

- If none of the three `LLM_*` variables is set, `NVIDIA_API_KEY`,
  `NVIDIA_BASE_URL` and `NVIDIA_MODEL` are used instead.
- Once any `LLM_*` variable is set (an empty value counts as set), all
  three must be set and non-blank, and the `NVIDIA_*` variables are ignored.
  A leftover `NVIDIA_API_KEY` is never sent to a provider configured through
  `LLM_*`.

Only NVIDIA NIM has been tested live.
The API refuses to start if the key is unset or blank, or if the `LLM_*`
settings are incomplete; the error names each missing variable.
It also refuses to start while `OPENAI_CUSTOM_HEADERS` is set: the OpenAI SDK
adds those headers to every request, and an `Authorization` line among them
would replace the provider key.
The HTTP client honours the standard `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY`, `NO_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR` settings, so they
apply to requests to the provider. `SSL_CERT_FILE` takes precedence over
`SSL_CERT_DIR`, and setting either replaces the system trust store rather
than adding to it.

## Tests

```bash
python -m pytest -p no:cacheprovider
```

Run them inside the activated virtualenv: it is the one that has
`requirements.txt` installed, and `-m` puts the repo root on `sys.path` so
the `app` package imports (bare `pytest` fails collection with
`ModuleNotFoundError: No module named 'app'`).

The tests run on Linux only (one reads `/proc`). `.env` must exist before
running them (copy `.env.example`), because `app/db.py` reads `DATABASE_URL`
on import. The tests build several throwaway databases (`charon_test`,
`charon_test_migration`, `charon_test_redaction` and `charon_test_rescore`)
on the server in `DATABASE_URL`, connecting with its credentials as an
admin that can create and drop databases, and drop them afterwards; these
tests are skipped if PostgreSQL is unreachable. The OCR tests are skipped
if `tesseract` is not installed. The suite takes several minutes.

## Upgrading an existing database

`investigations` has a `model` column holding the model id each run was
submitted with. A database created before that column existed gets it by
applying `db/schema.sql` again. Re-running the script creates the
`investigations` and `tool_calls` tables if they are missing and adds the
`error` and `model` columns to `investigations` if they are missing; nothing
else is altered, so it is safe to run more than once:

```bash
podman exec -i charon-pg psql -v ON_ERROR_STOP=1 -U charon -d charon < db/schema.sql
```

Rows that were already there keep `model` as `NULL`, meaning the model is
unknown. The red-team harness applies the schema to its own database
automatically each time it runs.

## Statuses and verdicts

| Status | Meaning |
|---|---|
| `running` | The investigation is in progress. |
| `complete` | The model finished on its own, every tool call it requested has a logged row, the coverage rules below are met, and a report was parsed. |
| `incomplete` | A report was written, but the run was cut short (time budget, tool-call cap, or an LLM call that kept failing after evidence was logged), the coverage rules are not met, findings were dropped because the tool they cite has no successful call in the run, a `malicious` or `suspicious` verdict has no findings (it becomes `inconclusive`), or a tool's every call in the run failed (`tool failed: <tool>`; a required tool is named in the coverage reason instead). `error` says which. |
| `failed` | No report. `error` holds the cause. This includes a provider response with an empty or repeated tool-call id: requested calls are matched to their logged rows by id, so without unique ids coverage cannot be checked. |

Verdicts are one of `malicious`, `suspicious`, `benign` or `inconclusive`.
Whenever a run is `incomplete`, a `benign` verdict is replaced with
`inconclusive`: partial evidence never clears a file.
A URL or a `.pcap` or `.pcapng` file can never be `benign`.

## The coverage rule for file inputs

For a submitted file, the run only counts as fully covered if the file
itself was successfully examined by the right tools:

- `sandbox` and `threat_intel` must both have run on the submitted file,
  and `ocr` too, unless the sandbox result shows the file is not an image.
- `traffic_summary` is required when the file name ends in `.pcap` or
  `.pcapng`, and never for any other file type.
- A call only counts if it went through the real tool (not a tool name the
  model invented), did not return an error, and named the submitted file in
  the tool's own path argument. Paths are compared after normalisation, so
  `./x` matches `x` but `../x` does not.
- A `threat_intel` call only counts if it looked up the file's hashes, not
  a plain string.

If any required tool is missing, the run is `incomplete` with
`required tools did not succeed: <tools>`, whatever the verdict, and a
`benign` verdict becomes `inconclusive`.

A URL can never be `benign`: no tool fetches or analyses URL content, so a
`benign` verdict on a URL becomes `inconclusive` with status `incomplete`.

A capture file (`.pcap` or `.pcapng`) can never be `benign` either:
`summarize_pcap` reads packet metadata and DNS query names only, so a
capture run whose verdict is `benign` or `inconclusive` ends `inconclusive`
with status `incomplete`, even when every tool succeeded.
`malicious` and `suspicious` verdicts on captures are kept. Every capture
report also carries a `scope_notes` entry, outside `findings`, saying that
payload-level analysis was not performed.

## Known limitations

- **Provider errors.** Free-tier provider errors are expected.
  - LLM calls are retried only on 5xx errors and timeouts, 3 attempts in
    total with waits of 5 s and 15 s, and never past the time budget.
  - If a loop turn still fails with a 5xx error or timeout after its
    retries, and at least one tool call was logged, the report is written
    from that evidence and the run is `incomplete` (`llm turn failed after 3
    attempts: …; report written from partial evidence`). If nothing was
    logged yet, the run is `failed`.
  - Any other error on a loop turn (a 4xx such as 429 rate limit, or a
    connection error) is not retried and fails the run, even if evidence
    was already logged.
  - If the report call fails, the run is `failed`.
- **Coverage gaps.** URLs have no content analysis at all.
- **Shallow citation check.** Findings are checked only for citing a tool
  that was actually called, not for whether their text matches that tool's
  output.
- **Pcap handling.** Captures are recognised by file extension only
  (`.pcap` / `.pcapng`), so a renamed capture is not, and HTTP and other
  application-layer content in captures is not parsed.
- **Single server process.** On startup the server marks every investigation
  still `running` as `failed` ("server restarted before completion"). That
  assumes one server process: a second process starting against the same
  database would fail the first one's in-flight runs.
- **Trusted intake directory.** The tool servers follow symlinks inside the
  intake directory, and the coverage check compares normalised path strings,
  not file identity. Only trusted users should be able to write to it.
- **Tool output reaches the model unredacted.** The provider key is
  redacted from stored and logged text, but not from tool output sent to the
  model: the tool servers never receive the key, so it can only appear there
  if a submitted file contains it, and then it is the submitter's own secret.
- **Tool output is not truncated.** Very large OCR text or pcap summaries are
  passed to the model in full and could exceed its context window.
- **No database connect timeout.** Connections are opened with
  `psycopg.connect(DATABASE_URL)` and no timeout, so an unreachable database
  can stall a request instead of failing fast.
- **Tests.**
  - Several tests use real time budgets of a few seconds and need a
    reasonably idle machine. The suite has passed under full CPU load.
  - Only Python 3.14.7 has been tested.
  - A tool server crashing at startup before the deadline is tested with a
    fake server only.
- **Interrupts.** Marking an interrupted run `failed` is unit-tested only.
  If the server process is killed, the startup sweep is what cleans up its
  `running` rows.
- **Live verification is narrow.** Live runs, failed ones included, used
  19 distinct inputs by file name or URL: the phishing image
  `sample_phish.png`, the benign image `team_lunch.png`, the synthetic
  capture `sample_synthetic_dns_http.pcap`, the URLs
  `http://secure-verify.example/login` and `hxxp://115.50.105.81[:]59352/i`
  (a sample URL from the bundled indicator file, defanged here), and the
  14 synthetic red-team files from `redteam/make_files.py` (the 10 PDF
  files are reported in [Results: PDF cases](redteam.md#results-pdf-cases-17-october-2026)).
