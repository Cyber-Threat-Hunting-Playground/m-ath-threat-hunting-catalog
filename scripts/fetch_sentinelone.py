#!/usr/bin/env python3
"""
Fetch SentinelOne PowerQuery data and save as CSV to scenarios/dns_url_anomaly_analysis/input/.
Designed for GitHub Actions; uses env vars for credentials.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# Project root (parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_DIR = PROJECT_ROOT / "scenarios" / "dns_url_anomaly_analysis" / "input" / "sentinelone"
SENTINELONE_DIR = PROJECT_ROOT / "data_grabber" / "sentinelone-powerquery"

# Default PowerQuery: DNS events with columns matching the analysis notebook
# Adjust SENTINELONE_POWERQUERY env var to customize
DEFAULT_QUERY = """
event.dns.request = *
| columns src.process.parent.image.path, src.process.parent.displayName, src.process.parent.name, src.process.dnsCount, src.process.image.path, src.process.name, event.dns.request, event.dns.response, account.name, site.name, endpoint.os, endpoint.type, agent.uuid, endpoint.name
"""


def main() -> int:
    url = os.environ.get("SENTINELONE_URL", "").strip()
    token = os.environ.get("SENTINELONE_TOKEN", "").strip()
    team_emails = os.environ.get("SENTINELONE_TEAM_EMAILS", "[]")
    query = os.environ.get("SENTINELONE_POWERQUERY", DEFAULT_QUERY).strip()
    start = os.environ.get("SENTINELONE_START", "24h")
    stop = os.environ.get("SENTINELONE_STOP", "1min")

    if not url or not token:
        print(
            "SENTINELONE_URL and SENTINELONE_TOKEN are required. "
            "Set them as repository secrets for GitHub Actions.",
            file=sys.stderr,
        )
        return 1

    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Run sentinelone_query.py and capture JSON
    cmd = [
        sys.executable,
        str(SENTINELONE_DIR / "sentinelone_query.py"),
        "--query", query,
        "--start", start,
        "--stop", stop,
    ]
    env = os.environ.copy()
    env["SENTINELONE_URL"] = url
    env["SENTINELONE_TOKEN"] = token
    env["SENTINELONE_TEAM_EMAILS"] = team_emails

    result = subprocess.run(
        cmd,
        cwd=str(SENTINELONE_DIR),
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )

    if result.returncode != 0:
        print(f"SentinelOne query failed: {result.stderr}", file=sys.stderr)
        return 1

    # Parse JSON and convert to CSV
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON from SentinelOne: {e}", file=sys.stderr)
        return 1

    events = data.get("events", [])
    if not events:
        print("No events returned from SentinelOne.", file=sys.stderr)
        return 0

    columns = list(events[0].keys())
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H_%M_%SZ")
    out_path = INPUT_DIR / f"power-query-results_{ts}.csv"

    import csv
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)

    print(f"Saved {len(events)} events to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
