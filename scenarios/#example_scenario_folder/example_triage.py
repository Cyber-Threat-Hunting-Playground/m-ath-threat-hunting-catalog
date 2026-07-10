#!/usr/bin/env python3
"""
Example Threat Hunting M-ATH analysis and triage script.
Demonstrates:
1. Resolving repository paths.
2. Loading inputs from the input/ directory.
3. Scoring anomalies.
4. Calling detection logics and SentinelOne LLM Triage to explain findings and filter false positives.
"""
from __future__ import annotations

import os
import sys
import pandas as pd
from pathlib import Path

# 1. Resolve paths and add project root to sys.path
def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "detection_logics").exists() and (cur / "scenarios").exists():
            return cur
        cur = cur.parent
    raise RuntimeError("Unable to locate repository root.")

# Setup imports
REPO_ROOT = find_repo_root(Path(__file__).resolve().parent)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Import shared detection logics and triage
from detection_logics import apply_dns_logics, apply_url_logics, apply_s1_triage

SCENARIO_NAME = "#example_scenario_folder"

def main():
    print(f"--- Starting M-ATH Hunting Pipeline: {SCENARIO_NAME} ---")
    
    # 2. Simulate raw telemetry leads
    print("Generating simulated telemetry leads...")
    leads = [
        {
            "risk_score": 10,
            "agent.uuid": "agent-uuid-1234",
            "src.process.name": "powershell.exe",
            "src.process.pid": 4096,
            "src.process.cmdline": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\update.ps1",
            "src.process.uniqueId": "s1-proc-unique-id-5555"
        },
        {
            "risk_score": 2,
            "agent.uuid": "agent-uuid-5678",
            "src.process.name": "explorer.exe",
            "src.process.pid": 1200,
            "src.process.cmdline": "C:\\Windows\\explorer.exe",
            "src.process.uniqueId": "s1-proc-unique-id-6666"
        }
    ]
    
    print(f"Initial leads count: {len(leads)}")
    for l in leads:
        print(f"  - Process: {l['src.process.name']} | Initial Score: {l['risk_score']}")

    # 3. Apply SentinelOne AI SIEM + LLM Triage to explain findings and reduce FPs
    print("\nApplying SentinelOne & LLM Triage context verification...")
    # NOTE: This runs only if scenarios/#example_scenario_folder/config/.env exists!
    triaged_leads = apply_s1_triage(
        leads=leads,
        scenario_name=SCENARIO_NAME,
        score_column="risk_score",
        threshold=5,
        top_n=10
    )
    
    print("\n--- Final Results ---")
    for l in triaged_leads:
        print(f"Process: {l['src.process.name']} | Final Score: {l['risk_score']}")
        if "s1_triage_verdict" in l:
            print(f"  Verdict: {l['s1_triage_verdict']}")
            print(f"  Confidence: {l['s1_triage_fp_confidence']}%")
            print(f"  Explanation: {l['s1_triage_explanation']}")
        else:
            print("  (Triage skipped or disabled: config/.env is missing or score below threshold)")

if __name__ == "__main__":
    main()
