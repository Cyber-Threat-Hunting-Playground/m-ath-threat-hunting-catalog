$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPath = Join-Path $ProjectRoot ".jupyter_venv"

Write-Host "========================================="
Write-Host "Bootstrapping Central JupyterLab Venv"
Write-Host "Project Root: $ProjectRoot"
Write-Host "Venv: $VenvPath"
Write-Host "========================================="

# Find python
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    Write-Error "python was not found in PATH. Please install Python 3."
    exit 1
}

# Create venv if it doesn't exist
if (-not (Test-Path $VenvPath)) {
    Write-Host "Creating virtual environment..."
    python -m venv $VenvPath
} else {
    Write-Host "Virtual environment already exists."
}

# Find venv python path
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    # Fallback for PowerShell Core on non-Windows
    $VenvPython = Join-Path $VenvPath "bin/python"
}

if (-not (Test-Path $VenvPython)) {
    Write-Error "Could not find python executable inside the virtual environment at: $VenvPython"
    exit 1
}

Write-Host "Upgrading pip..."
& $VenvPython -m pip install --upgrade pip

# Install JupyterLab
$JupyterRequirements = Join-Path $PSScriptRoot "requirements_jupyter.txt"
if (Test-Path $JupyterRequirements) {
    Write-Host "Installing JupyterLab..."
    & $VenvPython -m pip install -r $JupyterRequirements
} else {
    Write-Error "Jupyter requirements not found at $JupyterRequirements"
    exit 1
}

Write-Host "JupyterLab virtual environment bootstrap completed successfully."
Write-Host "You can now run start_jupyterlab.ps1 or start_jupyterlab.py from the project root."
