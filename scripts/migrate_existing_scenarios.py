#!/usr/bin/env python3
"""
Migration script to populate all existing threat hunting scenarios with local install directories,
thin-wrapper bootstrap scripts, and scenario-specific requirements files.
"""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
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

def migrate():
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Scenarios directory: {SCENARIOS_DIR}")
    
    if not SCENARIOS_DIR.exists():
        print("Error: scenarios directory not found.")
        return

    count = 0
    # Iterate over child directories in scenarios/
    for path in SCENARIOS_DIR.iterdir():
        if not path.is_dir():
            continue
        # Skip hidden directories
        if path.name.startswith("."):
            continue
            
        install_dir = path / "install"
        install_dir.mkdir(exist_ok=True)
        
        # 1. Create requirements.txt
        req_file = install_dir / "requirements.txt"
        if not req_file.exists():
            req_file.write_text(REQUIREMENTS_CONTENT, encoding="utf-8")
            
        # 2. Create install_dependencies.ps1
        ps_file = install_dir / "install_dependencies.ps1"
        ps_file.write_text(PS_WRAPPER_CONTENT, encoding="utf-8")
        
        # 3. Create install_dependencies.sh
        sh_file = install_dir / "install_dependencies.sh"
        sh_file.write_text(SH_WRAPPER_CONTENT, encoding="utf-8")
        
        # Make shell script executable (optional, Python won't necessarily set executable flags on Windows,
        # but we can try using chmod if on a Unix-like system, otherwise we write the files).
        try:
            sh_file.chmod(0o755)
        except Exception:
            pass
            
        print(f"Migrated scenario: {path.name}")
        count += 1

    print(f"\nMigration completed. Total scenarios migrated: {count}")

if __name__ == "__main__":
    migrate()
