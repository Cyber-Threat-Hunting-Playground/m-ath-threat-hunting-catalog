$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".jupyter_venv"

if (-not (Test-Path $VenvPath)) {
    Write-Error "JupyterLab virtual environment not found at $VenvPath. Please run install\bootstrap_jupyter_venv.ps1 first."
    exit 1
}

$JupyterLabExecutable = Join-Path $VenvPath "Scripts\jupyter-lab.exe"

if (-not (Test-Path $JupyterLabExecutable)) {
    # Fallback for non-Windows if someone runs this via pwsh
    $JupyterLabExecutable = Join-Path $VenvPath "bin/jupyter-lab"
}

if (-not (Test-Path $JupyterLabExecutable)) {
    Write-Error "jupyter-lab executable not found in $VenvPath. Please verify the installation."
    exit 1
}

Write-Host "Starting JupyterLab in headless mode (no browser)..."
Write-Host "Check the console output below for the connection URL and token."
Write-Host "------------------------------------------------------------------"

& $JupyterLabExecutable --no-browser
