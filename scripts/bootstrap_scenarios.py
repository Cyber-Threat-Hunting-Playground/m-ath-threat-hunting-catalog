#!/usr/bin/env python3
"""
Bootstrap scenario folders from catalog.csv.
Adds Folder column, creates input/output/README.md for each scenario.
"""
import csv
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CATALOG = PROJECT_ROOT / "scenarios" / "catalog.csv"
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"

PS_WRAPPER_CONTENT = """$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& "$scriptDir/../../../install/bootstrap_scenario_venv.ps1" -ScenarioPath "$scriptDir/.."
"""

SH_WRAPPER_CONTENT = """#!/usr/bin/env bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bash "$SCRIPT_DIR/../../../install/bootstrap_scenario_venv.sh" "$SCRIPT_DIR/.."
"""

REQUIREMENTS_CONTENT = """# Scenario-specific dependencies
# Add packages required ONLY for this scenario here.
"""


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def read_catalog():
    with open(CATALOG, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    fieldnames = [c.strip() for c in fieldnames if c]
    return rows, fieldnames


def write_catalog(rows, fieldnames):
    if "Folder" in fieldnames:
        return
    idx = next((i for i, c in enumerate(fieldnames) if c.strip() == "Ref"), -1)
    if idx >= 0:
        fieldnames = fieldnames[: idx + 1] + ["Folder"] + fieldnames[idx + 1 :]
    else:
        fieldnames = ["Folder"] + fieldnames
    for row in rows:
        if "Folder" not in row or not row["Folder"]:
            row["Folder"] = slugify(row.get("Use case", ""))
    with open(CATALOG, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def readme_template(row: dict) -> str:
    use_case = row.get("Use case", "Threat Hunt Scenario")
    ref = row.get("Ref", "")
    desc = (row.get("Description", "") or "").split("\n")[0][:300]
    data = row.get("Data needed", "")
    source = row.get("Source", "")
    return f"""# {use_case}

**Ref:** {ref}

## Description

{desc}

## Data needed

{data or "(See catalog)"}

## Source

{source or "(See catalog)"}

## Inputs

Place input data (CSV, JSON, etc.) in `input/`.

## Outputs

Results are written to `output/`.

## How to run

1. Add input data to `input/`
2. Run the scenario notebook or script
3. Review outputs in `output/`
"""


def main():
    rows, fieldnames = read_catalog()
    try:
        write_catalog(rows, fieldnames)
        print("Updated catalog.csv with Folder column")
    except PermissionError:
        print("Note: Could not write catalog.csv (file may be open). Run update_catalog_folders.py later.")

    for row in rows:
        folder = row.get("Folder", "").strip() or slugify(row.get("Use case", ""))
        if not folder:
            continue
        scenario_path = SCENARIOS_DIR / folder
        (scenario_path / "input").mkdir(parents=True, exist_ok=True)
        (scenario_path / "output").mkdir(parents=True, exist_ok=True)
        (scenario_path / "input" / ".gitkeep").touch()
        (scenario_path / "output" / ".gitkeep").touch()
        
        # Bootstrap scenario-local install directory and scripts
        install_dir = scenario_path / "install"
        install_dir.mkdir(exist_ok=True)
        
        req_file = install_dir / "requirements.txt"
        if not req_file.exists():
            req_file.write_text(REQUIREMENTS_CONTENT, encoding="utf-8")
            
        ps_file = install_dir / "install_dependencies.ps1"
        if not ps_file.exists():
            ps_file.write_text(PS_WRAPPER_CONTENT, encoding="utf-8")
            
        sh_file = install_dir / "install_dependencies.sh"
        if not sh_file.exists():
            sh_file.write_text(SH_WRAPPER_CONTENT, encoding="utf-8")
            try:
                sh_file.chmod(0o755)
            except Exception:
                pass

        readme_path = scenario_path / "README.md"
        if not readme_path.exists():
            readme_path.write_text(readme_template(row), encoding="utf-8")
        print(f"  {folder}/")

    print("Done.")


if __name__ == "__main__":
    main()
