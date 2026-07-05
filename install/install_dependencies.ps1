$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$requirementsFile = Join-Path $scriptDir "requirements.txt"

if (-not (Test-Path $requirementsFile)) {
    Write-Error "requirements.txt not found at: $requirementsFile"
    exit 1
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue

if (-not $pythonCommand) {
    Write-Error "python was not found in PATH. Install Python 3 and ensure the 'python' command is available before running this script."
    exit 1
}

Write-Host "Using requirements file: $requirementsFile"

# Ensure pip is available
python -m ensurepip --default-pip
python -m pip install --upgrade pip
python -m pip install -r $requirementsFile
python -c "import requests; print('requests OK:', requests.__version__)"

Write-Host "Dependency installation completed."
