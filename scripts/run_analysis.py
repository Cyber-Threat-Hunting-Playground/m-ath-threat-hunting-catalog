#!/usr/bin/env python3
"""
Execute the DNS & URL anomaly analysis notebook non-interactively.
Designed for GitHub Actions; runs from project root.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = PROJECT_ROOT / "scenarios" / "dns_url_anomaly_analysis"
NOTEBOOK = SCENARIO_DIR / "dns_url_anomaly_analysis.ipynb"
TIMEOUT = 600  # 10 minutes


def main() -> int:
    if not NOTEBOOK.exists():
        print(f"Notebook not found: {NOTEBOOK}", file=sys.stderr)
        return 1

    output_dir = SCENARIO_DIR / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_name = "dns_url_anomaly_analysis_executed.ipynb"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "jupyter",
            "nbconvert",
            "--to",
            "notebook",
            "--execute",
            "--output-dir",
            str(output_dir),
            "--output",
            output_name,
            "--ExecutePreprocessor.timeout=600",
            str(NOTEBOOK),
        ],
        cwd=str(SCENARIO_DIR),
        timeout=TIMEOUT + 60,
    )

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
