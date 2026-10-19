"""
Re-score stored red-team runs, read-only.

Reads the investigations with ids in an inclusive range, and their tool_calls
rows, from the charon_redteam database, and recomputes every run's injection
class, verdict comparison and changed reasons with the current rules in
redteam/run.py. The control baseline is rebuilt from the control runs in the
range. Prints, per case: N, runs changed, runs with a verdict below the
control, the injection classes (obeyed, quoted, ambiguous, unaffected, and
unclear for a run without a report), and the control baseline (modal verdict
and tool set); then the reasons and the ambiguous clauses behind each flagged
run. Like the harness, it refuses rows from more than one model.

Every stored investigation is one run: rescoring cannot tell a provider retry
from a new run, so a failed attempt that the harness retried counts as an
unclear run of its case.

It never writes. The connection sets default_transaction_read_only=on for the
session and marks psycopg transactions read-only, checks that
current_database() is charon_redteam (so it refuses the development
database), and rolls back before it closes.

Usage: python -m redteam.rescore --runs FIRST-LAST
"""

import argparse
import json
import sys

import psycopg

from redteam.run import (
    CASES,
    HARNESS_DB_NAME,
    ambiguous_clauses,
    behaviour_changed,
    classify_injection,
    control_baseline,
    harness_database_url,
    single_model,
    verdict_vs_control,
)

SUMMARY_COLUMNS = ["case", "N", "changed", "verdict-down", "obeyed", "quoted", "ambiguous", "unaffected", "unclear",
                   "control_verdict", "control_tools"]
INJECTION_CLASSES = {"obeyed": "obeyed", "quoted": "quoted", "ambiguous": "ambiguous", "unaffected": "unaffected",
                     "unclear": None}


def parse_runs(value: str) -> tuple[int, int]:
    """FIRST-LAST, an inclusive range of investigation ids with FIRST <= LAST."""
    first, separator, last = value.partition("-")
    if not (separator and first.isdigit() and last.isdigit() and int(first) <= int(last)):
        raise ValueError(f"expected FIRST-LAST, got {value!r}")
    return int(first), int(last)


def read_only_connection(url: str, database: str) -> psycopg.Connection:
    """A connection whose session and transactions are read-only. Exits unless it reached `database`."""
    conn = psycopg.connect(url, options="-c default_transaction_read_only=on")
    conn.read_only = True
    [name] = conn.execute("SELECT current_database()").fetchone()
    if name != database:
        conn.close()
        sys.exit(f"connected to {name}, not {database}; refusing to read")
    return conn


def score(investigations: list[tuple], tool_rows: dict[int, list[tuple[str, str]]]) -> list[dict]:
    """One scored row per investigation (id, file name, status, report text, model), controls first, in CASES
    order, then by id. `tool_rows` maps an investigation id to its (tool name, output) rows in call order."""
    by_file = {file_name: (index, case, control) for index, (case, _, file_name, control) in enumerate(CASES)}
    for investigation_id, file_name, *_ in investigations:
        if file_name not in by_file:
            sys.exit(f"investigation {investigation_id}: {file_name} is not a red-team case file")
    rows: list[dict] = []
    for investigation_id, file_name, status, report_text, model in sorted(
            investigations, key=lambda investigation: (by_file[investigation[1]][0], investigation[0])):
        _, case, control = by_file[file_name]
        control_verdict, control_tools = control_baseline([row for row in rows if row["case"] == control])
        report = json.loads(report_text) if report_text else None
        verdict = report["verdict"] if report else None
        stored = [(name, output or "") for name, output in tool_rows.get(investigation_id, [])]
        tools = [name for name, _ in stored]
        injection = classify_injection(report)
        rows.append({
            "id": investigation_id, "case": case, "control": control, "status": status, "verdict": verdict,
            "report": report, "tools": tools, "tool_rows": stored, "model": model, "injection": injection,
            "verdict_vs_control": verdict_vs_control(verdict, control_verdict),
            "control_verdict": control_verdict, "control_tools": control_tools,
            "changed": behaviour_changed(injection, verdict, tools, control_verdict, control_tools),
        })
    return rows


def format_summary(rows: list[dict]) -> str:
    """One line per case: run counts and the control baseline (for a control case, its own)."""
    cells = [SUMMARY_COLUMNS]
    for case in dict.fromkeys(row["case"] for row in rows):
        runs = [row for row in rows if row["case"] == case]
        if runs[0]["control"] is None:
            control_verdict, control_tools = control_baseline(runs)
            changed = verdict_down = "-"
        else:
            control_verdict, control_tools = runs[0]["control_verdict"], runs[0]["control_tools"]
            changed = str(sum(bool(row["changed"]) for row in runs))
            verdict_down = str(sum(row["verdict_vs_control"] == "down" for row in runs))
        counts = [str(sum(row["injection"] == injection for row in runs)) for injection in INJECTION_CLASSES.values()]
        cells.append([case, str(len(runs)), changed, verdict_down, *counts, control_verdict or "-",
                      ">".join(sorted(control_tools)) or "-"])
    widths = [max(len(line[index]) for line in cells) for index in range(len(SUMMARY_COLUMNS))]
    lines = ["  ".join(value.ljust(width) for value, width in zip(line, widths)).rstrip() for line in cells]
    lines.insert(1, "  ".join("-" * width for width in widths))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--runs", type=parse_runs, required=True, metavar="FIRST-LAST",
                        help="inclusive range of investigation ids to re-score")
    first, last = parser.parse_args().runs

    from app.db import DATABASE_URL as dev_url  # reads .env; kept out of import time for offline tests

    conn = read_only_connection(harness_database_url(dev_url, HARNESS_DB_NAME), HARNESS_DB_NAME)
    try:
        investigations = conn.execute("SELECT id, submitted_input, status, report, model FROM investigations"
                                      " WHERE id BETWEEN %s AND %s ORDER BY id", (first, last)).fetchall()
        tool_rows: dict[int, list[tuple[str, str]]] = {}
        for investigation_id, name, output in conn.execute(
                "SELECT investigation_id, tool_name, output_payload FROM tool_calls"
                " WHERE investigation_id BETWEEN %s AND %s ORDER BY id", (first, last)):
            tool_rows.setdefault(investigation_id, []).append((name, output))
    finally:
        conn.rollback()
        conn.close()

    rows = score(investigations, tool_rows)
    print(f"model: {single_model(rows)}; investigations {first}-{last}: {len(rows)} rows")
    print(format_summary(rows))
    for row in rows:
        if row["changed"]:
            print(f"investigation {row['id']} ({row['case']}): {'; '.join(row['changed'])}")
        if row["injection"] == "ambiguous":
            print(f"investigation {row['id']} ({row['case']}): ambiguous: {' | '.join(ambiguous_clauses(row['report']))}")


if __name__ == "__main__":
    main()
