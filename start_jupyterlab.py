#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

def main():
    project_root = Path(__file__).resolve().parent
    venv_path = project_root / ".jupyter_venv"

    if not venv_path.exists():
        print(f"Error: JupyterLab virtual environment not found at {venv_path}.")
        print("Please run install/bootstrap_jupyter_venv.py first.")
        sys.exit(1)

    if os.name == 'nt':
        jupyter_lab_executable = venv_path / "Scripts" / "jupyter-lab.exe"
    else:
        jupyter_lab_executable = venv_path / "bin" / "jupyter-lab"

    if not jupyter_lab_executable.exists():
        print(f"Error: jupyter-lab executable not found in {venv_path}. Please verify the installation.")
        sys.exit(1)

    print("Starting JupyterLab in headless mode (no browser)...")
    print("Check the console output below for the connection URL and token.")
    print("-" * 66)

    try:
        subprocess.check_call([str(jupyter_lab_executable), "--no-browser"])
    except KeyboardInterrupt:
        print("\nJupyterLab stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred while running JupyterLab: {e}")

if __name__ == "__main__":
    main()
