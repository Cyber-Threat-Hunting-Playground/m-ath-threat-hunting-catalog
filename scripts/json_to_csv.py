#!/usr/bin/env python3
"""
Convert SentinelOne PowerQuery JSON output to CSV.
Reads from stdin or a file, writes to stdout or a file.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def powerquery_json_to_csv(data: dict) -> list[dict]:
    """Convert PowerQuery API response to list of row dicts."""
    columns = [col["name"] for col in data.get("columns", [])]
    values = data.get("values", [])
    return [dict(zip(columns, row)) for row in values]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert SentinelOne PowerQuery JSON output to CSV."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Input JSON file or '-' for stdin (default)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output CSV file or '-' for stdout (default)",
    )
    parser.add_argument(
        "--timestamp",
        action="store_true",
        help="Append timestamp to output filename when -o is a path",
    )
    args = parser.parse_args()

    if args.input == "-":
        raw = json.load(sys.stdin)
    else:
        with open(args.input, encoding="utf-8") as f:
            raw = json.load(f)

    # Handle both raw API response and wrapped { events: [...] } format
    if "events" in raw:
        rows = raw["events"]
        if rows and isinstance(rows[0], dict):
            columns = list(rows[0].keys())
        else:
            columns = []
    else:
        rows = powerquery_json_to_csv(raw)

    if not rows:
        print("No events to convert.", file=sys.stderr)
        sys.exit(0)

    columns = list(rows[0].keys())
    out_path = args.output

    if out_path != "-" and args.timestamp:
        stem = Path(out_path).stem
        suffix = Path(out_path).suffix
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H_%M_%SZ")
        out_path = str(Path(out_path).parent / f"{stem}_{ts}{suffix}")

    if out_path == "-":
        writer = csv.DictWriter(sys.stdout, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    else:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rows to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
