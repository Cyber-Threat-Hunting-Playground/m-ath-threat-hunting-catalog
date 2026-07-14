#!/usr/bin/env python3
"""
CLI helper to propose a new Threat Hunting scenario.
Supports parsing a markdown file or interactive command-line questionnaire.
"""
import argparse
import csv
import os
import re
import sys
from pathlib import Path

# Setup sys.path to import generate_scenario_from_issue helper from .github/scripts
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT / ".github" / "scripts"))

from generate_scenario_from_issue import (
    slugify, clean_value, parse_issue_body, get_next_ref, readme_template, notebook_template,
    CATALOG_PATH, SCENARIOS_DIR, PS_WRAPPER_CONTENT, SH_WRAPPER_CONTENT, REQUIREMENTS_CONTENT
)

PEAK_SUBPROCESSES = [
    "Forecasting and Anomaly Detection",
    "Clustering",
    "Model-Assisted Methods"
]

MODEL_METHODS = [
    "Supervised Classification (e.g. XGBoost, Random Forest)",
    "Unsupervised Clustering (e.g. K-Means, DBSCAN)",
    "Anomaly Detection (e.g. Isolation Forest, Autoencoders)",
    "Time-Series / Periodicity Analysis",
    "Natural Language Processing (NLP) / LLM",
    "Graph / Network Analysis",
    "Composite / Risk Scoring",
    "Other (Specify details in the next section)"
]

DATA_SOURCES = [
    "Active Directory (AD) logs",
    "Endpoint Detection & Response (EDR) logs",
    "Windows Event logs",
    "DNS query logs",
    "Web server / WAF logs",
    "Database (DB) logs",
    "NetFlow / Network traffic logs",
    "VPN / Remote access logs",
    "Threat Intelligence telemetry (e.g. VirusTotal)"
]


def prompt_input(prompt_text: str, required: bool = False) -> str:
    """Prompt the user for a text input with optional validation."""
    while True:
        val = input(prompt_text).strip()
        if required and not val:
            print("  Error: This field is required.")
            continue
        return val


def prompt_menu(prompt_text: str, options: list[str], multi: bool = False, required: bool = False) -> list[str]:
    """Display a numbered option list and return the chosen option(s)."""
    print(f"\n{prompt_text}")
    for idx, opt in enumerate(options, 1):
        print(f"  [{idx}] {opt}")
        
    while True:
        if multi:
            val = input("Enter option number(s) (comma-separated, e.g. 1,3): ").strip()
        else:
            val = input("Enter option number: ").strip()
            
        if required and not val:
            print("  Error: Selection is required.")
            continue
        if not val:
            return []
            
        selected = []
        try:
            parts = [p.strip() for p in val.split(",") if p.strip()]
            for p in parts:
                idx = int(p)
                if 1 <= idx <= len(options):
                    selected.append(options[idx - 1])
                else:
                    print(f"  Error: Invalid option number {idx}.")
                    break
            else:
                if multi:
                    return selected
                else:
                    if len(selected) == 1:
                        return selected
                    print("  Error: Please select exactly one option.")
        except ValueError:
            print("  Error: Please enter valid numbers.")


def run_interactive() -> str:
    """Collect inputs via CLI questionnaire and construct markdown body."""
    print("==================================================")
    print("   Threat Hunting Scenario Proposal Questionnaire ")
    print("==================================================")

    use_case = prompt_input("Scenario Title / Use Case (e.g. Compromised Account Detection): ", required=True)
    description = prompt_input("Scenario Description (explain threat and search lead): ", required=True)
    
    subprocesses = prompt_menu("PEAK M-ATH Sub-process:", PEAK_SUBPROCESSES, multi=False, required=True)
    peak_subprocess = subprocesses[0]

    selected_models = prompt_menu("Model or Statistical Method (select all that apply):", MODEL_METHODS, multi=True, required=True)
    model_details = prompt_input("Model Details / Specifics (optional): ")
    math_explanation = prompt_input("Why does M-ATH apply? (required explanation): ", required=True)
    
    selected_data = prompt_menu("Telemetry & Data Sources Needed (select all that apply):", DATA_SOURCES, multi=True, required=False)
    other_data = prompt_input("Other Data Sources (optional): ")
    source = prompt_input("References / Source (optional): ")

    # Construct standard GitHub Issue Markdown body
    lines = []
    lines.append("### Scenario Title / Use Case\n")
    lines.append(use_case + "\n")
    lines.append("### Scenario Description\n")
    lines.append(description + "\n")
    lines.append("### PEAK M-ATH Sub-process\n")
    lines.append(peak_subprocess + "\n")
    
    lines.append("### Model or Statistical Method\n")
    for m in MODEL_METHODS:
        checked = "x" if m in selected_models else " "
        lines.append(f"- [{checked}] {m}")
    lines.append("")
    
    lines.append("### Model Details / Specifics\n")
    lines.append((model_details or "_No response_") + "\n")
    lines.append("### Why does M-ATH apply?\n")
    lines.append(math_explanation + "\n")
    
    lines.append("### Telemetry & Data Sources Needed\n")
    for d in DATA_SOURCES:
        checked = "x" if d in selected_data else " "
        lines.append(f"- [{checked}] {d}")
    lines.append("")
    
    lines.append("### Other Data Sources\n")
    lines.append((other_data or "_No response_") + "\n")
    lines.append("### References / Source\n")
    lines.append((source or "_No response_") + "\n")

    return "\n".join(lines)


def bootstrap_scenario_from_body(body: str) -> None:
    """Parse body, update catalog.csv, and bootstrap folder."""
    sections = parse_issue_body(body)

    use_case = clean_value(sections.get("Scenario Title / Use Case", ""))
    if not use_case:
        raise ValueError("Error: 'Scenario Title / Use Case' is empty or missing.")

    description = clean_value(sections.get("Scenario Description", ""))
    if not description:
        raise ValueError("Error: 'Scenario Description' is empty or missing.")

    math_explanation = clean_value(sections.get("Why does M-ATH apply?", ""))
    if not math_explanation:
        raise ValueError("Error: 'Why does M-ATH apply?' is empty or missing.")

    # Parse Model used (combine checkboxes + details)
    models_checked = []
    for line in sections.get("Model or Statistical Method", "").splitlines():
        line = line.strip()
        if line.startswith("- [x]") or line.startswith("- [X]"):
            models_checked.append(line[5:].strip())
            
    model_details = clean_value(sections.get("Model Details / Specifics", ""))
    
    cleaned_models = []
    has_other = False
    for m in models_checked:
        if "other" in m.lower():
            has_other = True
        else:
            cleaned_models.append(m)
            
    if model_details:
        if model_details not in cleaned_models:
            cleaned_models.append(model_details)
        
    model_used = ", ".join(cleaned_models)
    if not model_used:
        model_used = model_details

    # Parse Data needed
    data_checked = []
    for line in sections.get("Telemetry & Data Sources Needed", "").splitlines():
        line = line.strip()
        if line.startswith("- [x]") or line.startswith("- [X]"):
            data_checked.append(line[5:].strip())
            
    other_data = clean_value(sections.get("Other Data Sources", ""))
    if other_data:
        data_checked.append(other_data)
    data_needed = ", ".join(data_checked)

    # Parse source
    source = clean_value(sections.get("References / Source", ""))

    # Parse PEAK sub-process
    peak_subprocess = clean_value(sections.get("PEAK M-ATH Sub-process", ""))

    ref = get_next_ref(CATALOG_PATH)
    folder = slugify(use_case)

    # Bootstrapping directory structure
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

    (scenario_path / "README.md").write_text(readme_template(row, math_explanation, peak_subprocess), encoding="utf-8")

    # Generate default Jupyter Notebook template
    notebook_file = scenario_path / f"{folder}.ipynb"
    notebook_file.write_text(notebook_template(use_case), encoding="utf-8")

    # Update scenarios/catalog.csv
    fieldnames = ["Ref", "Folder", "Use case", "Description", "Model used", "Data needed", "Source"]
    rows = []
    if CATALOG_PATH.exists():
        with open(CATALOG_PATH, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or fieldnames)
            rows = list(reader)

    # Safety duplicate check
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

    print(f"\n[+] Successfully generated scenario {ref} in scenarios/{folder}/")
    print(f"[+] Updated scenarios/catalog.csv")


def main() -> int:
    parser = argparse.ArgumentParser(description="Propose and bootstrap a new threat hunting scenario.")
    parser.add_argument("body_file", nargs="?", help="Optional path to a markdown file containing the proposal description")
    
    args = parser.parse_args()

    try:
        if args.body_file:
            path = Path(args.body_file)
            if not path.exists():
                print(f"Error: File '{args.body_file}' not found.", file=sys.stderr)
                return 1
            body = path.read_text(encoding="utf-8")
        else:
            body = run_interactive()
            
        bootstrap_scenario_from_body(body)
        return 0
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
