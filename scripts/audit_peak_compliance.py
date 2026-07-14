#!/usr/bin/env python3
import os
import sys
import re
import json
import argparse
import csv
from pathlib import Path

# Color helpers for console output
def print_success(msg):
    print(f"\033[92m[+] {msg}\033[0m")

def print_warning(msg):
    print(f"\033[93m[!] {msg}\033[0m")

def print_error(msg):
    print(f"\033[91m[-] {msg}\033[0m", file=sys.stderr)

class PEAKAuditor:
    def __init__(self, repo_root=None):
        if repo_root is None:
            self.repo_root = Path(__file__).resolve().parents[1]
        else:
            self.repo_root = Path(repo_root)
        self.scenarios_dir = self.repo_root / "scenarios"
        self.catalog_path = self.scenarios_dir / "catalog.csv"

    def get_catalog_scenarios(self):
        """Read scenarios from catalog.csv."""
        scenarios = []
        if not self.catalog_path.exists():
            return scenarios
        
        try:
            with open(self.catalog_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ref = row.get("Ref", "").strip()
                    folder = row.get("Folder", "").strip()
                    use_case = row.get("Use case", "").strip()
                    if ref and folder:
                        scenarios.append({
                            "ref": ref,
                            "folder": folder,
                            "use_case": use_case
                        })
        except Exception as e:
            print_error(f"Error reading catalog.csv: {e}")
        return scenarios

    def audit_scenario(self, folder_name, expected_ref=None):
        """Audits a single scenario folder for PEAK M-ATH compliance."""
        scenario_path = self.scenarios_dir / folder_name
        failures = []
        warnings = []
        
        # 1. Structure Checks
        if not scenario_path.exists():
            failures.append(f"Scenario folder `scenarios/{folder_name}` does not exist.")
            return failures, warnings

        # Backlog detection: skip full checks if not implemented yet
        notebooks = list(scenario_path.glob("*.ipynb"))
        py_files = list(scenario_path.glob("*.py"))
        if not notebooks and not py_files:
            warnings.append("Scenario is in backlog (no Jupyter notebook or Python script implemented in root). Skipping compliance checks.")
            return [], warnings

        # Required subdirs
        for subdir in ["input", "output"]:
            if not (scenario_path / subdir).exists():
                failures.append(f"Missing required subdirectory: `{subdir}/`")

        # Required install files
        install_dir = scenario_path / "install"
        if not install_dir.exists():
            failures.append("Missing required subdirectory: `install/`")
        else:
            for file in ["requirements.txt", "install_dependencies.ps1", "install_dependencies.sh"]:
                if not (install_dir / file).exists():
                    failures.append(f"Missing required file: `install/{file}`")

        # 2. README Checks
        readme_path = scenario_path / "README.md"
        if not readme_path.exists():
            failures.append("Missing required file: `README.md`")
        else:
            try:
                content = readme_path.read_text(encoding="utf-8", errors="ignore")
                
                # Check Reference ID
                ref_match = re.search(r"Ref[:\s\*]*(M\d+)", content, re.IGNORECASE)
                if not ref_match:
                    failures.append("README.md does not specify a valid Reference ID (e.g. `Ref: MXX`).")
                elif expected_ref and ref_match.group(1).upper() != expected_ref.upper():
                    failures.append(f"README.md Reference ID mismatch. Found `{ref_match.group(1)}`, expected `{expected_ref}`.")

                # Check M-ATH sub-process
                if not re.search(r"M-ATH\s+Sub-process", content, re.IGNORECASE):
                    failures.append("README.md does not specify the `M-ATH Sub-process` alignment.")

                # Check PEAK Alignment
                if not re.search(r"PEAK\s+Framework\s+Alignment", content, re.IGNORECASE) and not re.search(r"PEAK\s+Alignment", content, re.IGNORECASE):
                    failures.append("README.md is missing the `PEAK Framework Alignment` section or table.")
                else:
                    # Check for all phases
                    for phase in ["Prepare", "Execute", "Act", "Knowledge"]:
                        if not re.search(r"\b" + phase + r"\b", content, re.IGNORECASE):
                            failures.append(f"README.md PEAK alignment is missing references to the `{phase}` phase.")

                # Check telemetry / data requirements
                if not re.search(r"Data\s+needed|Telemetry", content, re.IGNORECASE):
                    warnings.append("README.md does not explicitly document the required telemetry source / `Data needed` section.")
                
            except Exception as e:
                failures.append(f"Error reading README.md: {e}")

        # 3. Jupyter Notebook Checks
        notebooks = list(scenario_path.glob("*.ipynb"))
        if not notebooks:
            failures.append("No Jupyter notebook (`.ipynb`) found in the scenario directory.")
        else:
            # We audit the primary notebook (usually named after the folder or the first one found)
            notebook_path = notebooks[0]
            try:
                with open(notebook_path, "r", encoding="utf-8", errors="ignore") as fn:
                    nb = json.load(fn)
                
                cells = nb.get("cells", [])
                
                # Check for PEAK phase markdown headers
                markdown_headers = []
                for cell in cells:
                    if cell.get("cell_type") == "markdown":
                        source = "".join(cell.get("source", []))
                        for line in source.splitlines():
                            line_strip = line.strip()
                            if line_strip.startswith("#"):
                                markdown_headers.append(line_strip)

                all_headers_text = " ".join(markdown_headers).upper()
                
                for phase in ["PREPARE", "EXECUTE", "ACT", "KNOWLEDGE"]:
                    # Look for phase keyword in markdown headers
                    if phase not in all_headers_text:
                        failures.append(f"Jupyter Notebook `{notebook_path.name}` is missing markdown header/section for the `{phase}` phase.")

                # Code cells check
                code_sources = []
                for cell in cells:
                    if cell.get("cell_type") == "code":
                        code_sources.append("".join(cell.get("source", [])))

                all_code_text = "\n".join(code_sources)

                # Check for detection_logics import (recommended decoupler logic)
                if "detection_logics" not in all_code_text:
                    warnings.append(f"Jupyter Notebook `{notebook_path.name}` does not seem to import shared logic from the `detection_logics` package.")

                # Check for KPITracker usage (recommended execution metric tracker)
                if "KPITracker" not in all_code_text:
                    warnings.append(f"Jupyter Notebook `{notebook_path.name}` does not seem to use `KPITracker` to record execution performance.")

                # Check for output generation inside output/ folder
                if "output/" not in all_code_text and "output_dir" not in all_code_text:
                    warnings.append(f"Jupyter Notebook `{notebook_path.name}` does not seem to write output files to the `output/` directory.")

            except Exception as e:
                failures.append(f"Error parsing Jupyter Notebook `{notebook_path.name}`: {e}")

        return failures, warnings

    def write_local_report(self, folder_name, failures, warnings):
        """Writes a .peak_compliance_report.md file inside the scenario directory."""
        scenario_path = self.scenarios_dir / folder_name
        report_path = scenario_path / ".peak_compliance_report.md"

        # If compliant, remove any existing report
        if not failures and not warnings:
            if report_path.exists():
                try:
                    os.remove(report_path)
                except Exception:
                    pass
            return

        report_lines = [
            f"# PEAK Compliance Report: `{folder_name}`\n",
            "This report documents compliance audits against the **Splunk PEAK M-ATH Framework** standards. Please address the issues listed below before submitting a Pull Request.\n",
        ]

        if failures:
            report_lines.append("## ❌ Critical Non-Compliance Failures\n")
            report_lines.append("These issues break compliance and **must be fixed** (they will block commits and CI builds):\n")
            for f in failures:
                report_lines.append(f"- [ ] {f}")
            report_lines.append("")

        if warnings:
            report_lines.append("## ⚠️ Performance & Decoupling Recommendations\n")
            report_lines.append("These are best practice warnings that do not block the build but should be addressed for high quality:\n")
            for w in warnings:
                report_lines.append(f"- [ ] {w}")
            report_lines.append("")

        report_lines.extend([
            "## How to Fix\n",
            "1. **Check folder structure:** Ensure the scenario directory matches the catalog structure, including `input/`, `output/`, and `install/` with standard shell/PowerShell wrapper scripts.",
            "2. **Align README.md:** Make sure your README has a correct `Ref` ID, specifies the `M-ATH Sub-process`, and outlines how the Prepare, Execute, Act, and Knowledge phases apply.",
            "3. **Structure Notebook:** Open your `.ipynb` notebook and add clear Markdown headers `# PREPARE`, `# EXECUTE`, `# ACT`, and `# KNOWLEDGE` to group cells by their respective PEAK framework phase.",
            "4. **Integrate Helpers:** Decouple common detection algorithms (like DNS queries) by importing from the `detection_logics` package, use the `KPITracker` to write performance stats, and write scored results to `output/`.",
            "\n*This file is generated automatically and is git-ignored. It will be deleted once the scenario is 100% compliant.*"
        ])

        try:
            report_path.write_text("\n".join(report_lines), encoding="utf-8")
        except Exception as e:
            print_error(f"Failed to write compliance report for {folder_name}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Audit Threat Hunting scenarios for Splunk PEAK compliance.")
    parser.add_argument("--scenario", help="Target scenario folder name to check (checks only this scenario)")
    parser.add_argument("--all", action="store_true", help="Check all scenarios in the repository")
    parser.add_argument("--json", help="Path to write JSON compliance results")
    parser.add_argument("--warn-only", action="store_true", help="Print compliance issues but return exit code 0")

    args = parser.parse_args()

    auditor = PEAKAuditor()
    scenarios_to_check = []

    # Resolve targets to check
    if args.scenario:
        # Check specific scenario
        # Match with catalog if possible to get expected Ref
        catalog_scenarios = auditor.get_catalog_scenarios()
        match = next((s for s in catalog_scenarios if s["folder"] == args.scenario), None)
        expected_ref = match["ref"] if match else None
        scenarios_to_check.append({
            "folder": args.scenario,
            "ref": expected_ref
        })
    elif args.all or not sys.stdin.isatty():
        # Check all scenarios from catalog
        catalog_scenarios = auditor.get_catalog_scenarios()
        for s in catalog_scenarios:
            scenarios_to_check.append({
                "folder": s["folder"],
                "ref": s["ref"]
            })
    else:
        # Default behavior: if no arguments, list available scenarios and check all
        catalog_scenarios = auditor.get_catalog_scenarios()
        for s in catalog_scenarios:
            scenarios_to_check.append({
                "folder": s["folder"],
                "ref": s["ref"]
            })

    if not scenarios_to_check:
        print_warning("No scenarios found to check.")
        return 0

    results = {
        "status": "success",
        "scenarios": {}
    }
    
    total_failures = 0
    total_warnings = 0

    print(f"Auditing {len(scenarios_to_check)} scenarios for PEAK M-ATH compliance...")
    print("=" * 60)

    for sc in scenarios_to_check:
        folder = sc["folder"]
        ref = sc["ref"]
        
        failures, warnings = auditor.audit_scenario(folder, ref)
        auditor.write_local_report(folder, failures, warnings)
        
        # Save results
        results["scenarios"][folder] = {
            "ref": ref,
            "compliant": len(failures) == 0,
            "failures": failures,
            "warnings": warnings
        }

        if failures:
            total_failures += len(failures)
            results["status"] = "failed"
            print_error(f"[{ref or '???'} / {folder}] NON-COMPLIANT ({len(failures)} failures, {len(warnings)} warnings)")
            for f in failures:
                print(f"  [FAIL] {f}")
            for w in warnings:
                print(f"  [WARN] {w}")
            report_file = auditor.scenarios_dir / folder / ".peak_compliance_report.md"
            print_warning(f"  Details written to: {report_file}")
            print("-" * 60)
        elif warnings:
            total_warnings += len(warnings)
            print_warning(f"[{ref} / {folder}] COMPLIANT WITH WARNINGS ({len(warnings)} warnings)")
            for w in warnings:
                print(f"  [WARN] {w}")
            report_file = auditor.scenarios_dir / folder / ".peak_compliance_report.md"
            print_warning(f"  Details written to: {report_file}")
            print("-" * 60)
        else:
            print_success(f"[{ref} / {folder}] COMPLIANT")

    print("=" * 60)
    print(f"Audit completed: {total_failures} critical failures, {total_warnings} warnings.")

    # Write JSON results if requested
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as jf:
                json.dump(results, jf, indent=2)
            print_success(f"JSON compliance report written to: {args.json}")
        except Exception as e:
            print_error(f"Failed to write JSON output: {e}")

    # Return exit code
    if total_failures > 0 and not args.warn_only:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
