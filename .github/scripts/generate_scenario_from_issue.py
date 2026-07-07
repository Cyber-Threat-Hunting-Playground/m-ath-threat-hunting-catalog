#!/usr/bin/env python3
"""
Parse a GitHub Issue containing a Threat Hunting M-ATH scenario proposal,
update scenarios/catalog.csv, and bootstrap the scenario directory.
"""
import argparse
import csv
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# Paths relative to project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = PROJECT_ROOT / "scenarios" / "catalog.csv"
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
    """Generate a filesystem-friendly directory name from a string."""
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def clean_value(val: str) -> str:
    """Clean standard markdown formatting and GitHub Issue Form default values."""
    if not val:
        return ""
    val = val.strip()
    if val.lower() in ("_no response_", "none", "n/a"):
        return ""
    return val


def parse_checkboxes(section_text: str) -> list[str]:
    """Parse checkboxes in a GitHub Issue Form markdown output."""
    checked = []
    for line in section_text.splitlines():
        line = line.strip()
        if line.startswith("- [x]") or line.startswith("- [X]"):
            option = line[5:].strip()
            checked.append(option)
    return checked


def parse_issue_body(body: str) -> dict:
    """Parse a GitHub Issue Form markdown body into sections."""
    sections = {}
    current_header = None
    current_content = []

    for line in body.splitlines():
        if line.startswith("### "):
            if current_header:
                sections[current_header] = "\n".join(current_content).strip()
            current_header = line[4:].strip()
            current_content = []
        elif current_header is not None:
            current_content.append(line)

    if current_header:
        sections[current_header] = "\n".join(current_content).strip()

    return sections


def get_next_ref(catalog_path: Path) -> str:
    """Find the next Reference ID from catalog.csv (e.g. M25 -> M26)."""
    max_num = 0
    if not catalog_path.exists():
        return "M01"
    
    with open(catalog_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ref = row.get("Ref", "").strip()
            if ref.startswith("M"):
                try:
                    num = int(ref[1:])
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass
    next_num = max_num + 1
    return f"M{next_num:02d}"


def get_github_issue(repo: str, issue_number: str, token: str) -> tuple[str, str, str]:
    """Fetch issue title, body, and user from GitHub API."""
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            body = data.get("body") or ""
            title = data.get("title") or ""
            user = data.get("user", {}).get("login") or "unknown"
            return title, body, user
    except Exception as e:
        print(f"Error fetching issue from GitHub API: {e}", file=sys.stderr)
        sys.exit(1)


def readme_template(row: dict, math_explanation: str) -> str:
    """Generate README.md content for the new scenario."""
    use_case = row.get("Use case", "Threat Hunt Scenario")
    ref = row.get("Ref", "")
    desc = row.get("Description", "")
    data = row.get("Data needed", "")
    source = row.get("Source", "")
    
    return f"""# {use_case}

**Ref:** {ref}

## Description

{desc}

## Why M-ATH Applies

{math_explanation or "This scenario uses statistical/model-assisted methods to detect threat activity that cannot be easily caught with static signatures."}

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Threat Hunting issue proposal and generate scenario.")
    parser.add_argument("--issue-number", help="GitHub Issue number to retrieve")
    parser.add_argument("--body-file", help="Local file containing issue body markdown (for testing)")
    parser.add_argument("--submitter", help="Submitter username (for testing with --body-file)", default="testuser")

    args = parser.parse_args()

    if args.body_file:
        body_path = Path(args.body_file)
        if not body_path.exists():
            print(f"Error: Body file {args.body_file} not found.", file=sys.stderr)
            return 1
        body = body_path.read_text(encoding="utf-8")
        submitter = args.submitter
    elif args.issue_number:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not token:
            print("Error: GH_TOKEN or GITHUB_TOKEN environment variable required.", file=sys.stderr)
            return 1
        if not repo:
            print("Error: GITHUB_REPOSITORY environment variable required.", file=sys.stderr)
            return 1
        _, body, submitter = get_github_issue(repo, args.issue_number, token)
    else:
        print("Error: Either --issue-number or --body-file is required.", file=sys.stderr)
        return 1

    sections = parse_issue_body(body)

    # Extract use case title
    use_case = clean_value(sections.get("Scenario Title / Use Case", ""))
    if not use_case:
        print("Error: 'Scenario Title / Use Case' is empty or missing.", file=sys.stderr)
        return 1

    description = clean_value(sections.get("Scenario Description", ""))
    if not description:
        print("Error: 'Scenario Description' is empty or missing.", file=sys.stderr)
        return 1

    math_explanation = clean_value(sections.get("Why does M-ATH apply?", ""))
    if not math_explanation:
        print("Error: 'Why does M-ATH apply?' is empty or missing.", file=sys.stderr)
        return 1

    # Extract model used (combine checklist + details)
    models_checked = parse_checkboxes(sections.get("Model or Statistical Method", ""))
    model_details = clean_value(sections.get("Model Details / Specifics", ""))
    
    cleaned_models = []
    has_other = False
    for m in models_checked:
        if "other" in m.lower():
            has_other = True
        else:
            cleaned_models.append(m)
            
    if has_other and model_details:
        cleaned_models.append(model_details)
    elif not cleaned_models and model_details:
        cleaned_models.append(model_details)
        
    model_used = ", ".join(cleaned_models)
    if not model_used:
        model_used = model_details

    # Extract data needed
    data_checked = parse_checkboxes(sections.get("Telemetry & Data Sources Needed", ""))
    other_data = clean_value(sections.get("Other Data Sources", ""))
    if other_data:
        data_checked.append(other_data)
    data_needed = ", ".join(data_checked)

    # Extract source
    source = clean_value(sections.get("References / Source", ""))

    # Prepare row information
    ref = get_next_ref(CATALOG_PATH)
    folder = slugify(use_case)

    # Create scenario folder and files
    scenario_path = SCENARIOS_DIR / folder
    (scenario_path / "input").mkdir(parents=True, exist_ok=True)
    (scenario_path / "output").mkdir(parents=True, exist_ok=True)
    (scenario_path / "input" / ".gitkeep").touch()
    (scenario_path / "output" / ".gitkeep").touch()

    install_dir = scenario_path / "install"
    install_dir.mkdir(exist_ok=True)

    (install_dir / "requirements.txt").write_text(REQUIREMENTS_CONTENT, encoding="utf-8")
    
    ps_wrapper = install_dir / "install_dependencies.ps1"
    ps_wrapper.write_text(PS_WRAPPER_CONTENT, encoding="utf-8")

    sh_wrapper = install_dir / "install_dependencies.sh"
    sh_wrapper.write_text(SH_WRAPPER_CONTENT, encoding="utf-8")
    try:
        sh_wrapper.chmod(0o755)
    except Exception:
        pass

    row = {
        "Ref": ref,
        "Folder": folder,
        "Use case": use_case,
        "Description": description,
        "Model used": model_used,
        "Data needed": data_needed,
        "Source": source
    }

    (scenario_path / "README.md").write_text(readme_template(row, math_explanation), encoding="utf-8")

    # Update scenarios/catalog.csv
    # Read current lines to make sure headers match
    fieldnames = ["Ref", "Folder", "Use case", "Description", "Model used", "Data needed", "Source"]
    
    rows = []
    if CATALOG_PATH.exists():
        with open(CATALOG_PATH, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or fieldnames)
            rows = list(reader)

    # Check if this Ref already exists (safety check)
    existing_idx = next((i for i, r in enumerate(rows) if r.get("Ref") == ref), None)
    if existing_idx is not None:
        rows[existing_idx] = row
    else:
        rows.append(row)

    with open(CATALOG_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"Successfully generated scenario {ref} in scenarios/{folder}/")
    print(f"Updated scenarios/catalog.csv")

    # Write GITHUB_OUTPUT variables
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"ref={ref}\n")
            f.write(f"use_case={use_case}\n")
            f.write(f"folder={folder}\n")
            f.write(f"submitter={submitter}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
