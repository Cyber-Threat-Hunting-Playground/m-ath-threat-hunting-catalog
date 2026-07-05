#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

def main():
    print("=========================================")
    print("Bootstrapping Central JupyterLab Venv")
    
    install_dir = Path(__file__).resolve().parent
    project_root = install_dir.parent
    venv_path = project_root / ".jupyter_venv"
    
    print(f"Project Root: {project_root}")
    print(f"Venv: {venv_path}")
    print("=========================================")

    # Create venv if it doesn't exist
    if not venv_path.exists():
        print("Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_path)])
    else:
        print("Virtual environment already exists.")

    # Find venv python path
    if os.name == 'nt':
        venv_python = venv_path / "Scripts" / "python.exe"
    else:
        venv_python = venv_path / "bin" / "python"

    if not venv_python.exists():
        print(f"Error: Could not find python executable inside the virtual environment at: {venv_python}")
        sys.exit(1)

    print("Upgrading pip...")
    subprocess.check_call([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"])

    # Install JupyterLab
    jupyter_requirements = install_dir / "requirements_jupyter.txt"
    if jupyter_requirements.exists():
        print("Installing JupyterLab...")
        subprocess.check_call([str(venv_python), "-m", "pip", "install", "-r", str(jupyter_requirements)])
    else:
        print(f"Error: Jupyter requirements not found at {jupyter_requirements}")
        sys.exit(1)

    print("JupyterLab virtual environment bootstrap completed successfully.")
    print("You can now run start_jupyterlab.ps1 or start_jupyterlab.py from the project root.")

if __name__ == "__main__":
    main()
