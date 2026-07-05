param (
    [Parameter(Mandatory=$true)]
    [string]$ScenarioPath
)

$ErrorActionPreference = "Stop"

# Resolve ScenarioPath to absolute path
$ScenarioPath = (Resolve-Path $ScenarioPath).Path
$ScenarioName = Split-Path $ScenarioPath -Leaf
$VenvPath = Join-Path $ScenarioPath ".venv"

Write-Host "========================================="
Write-Host "Bootstrapping Virtual Environment for M-ATH"
Write-Host "Scenario: $ScenarioName"
Write-Host "Path: $ScenarioPath"
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

# Install base requirements
$RootRequirements = Join-Path $PSScriptRoot "requirements.txt"
if (Test-Path $RootRequirements) {
    Write-Host "Installing base requirements from root..."
    & $VenvPython -m pip install -r $RootRequirements
} else {
    Write-Warning "Root requirements.txt not found at $RootRequirements"
}

# Install detection_logics package in editable mode
$DetectionLogicsPath = (Resolve-Path (Join-Path $PSScriptRoot "../detection_logics")).Path
Write-Host "Installing detection_logics in editable mode..."
& $VenvPython -m pip install -e $DetectionLogicsPath

# Install scenario-specific requirements
$ScenarioRequirements = Join-Path $ScenarioPath "install\requirements.txt"
if (Test-Path $ScenarioRequirements) {
    Write-Host "Installing scenario-specific requirements..."
    & $VenvPython -m pip install -r $ScenarioRequirements
}

# Register Jupyter kernel
Write-Host "Registering Jupyter kernel 'math-$ScenarioName'..."
& $VenvPython -m ipykernel install --user --name="math-$ScenarioName" --display-name="M-ATH: $ScenarioName"

Write-Host "Virtual environment bootstrap completed successfully."
