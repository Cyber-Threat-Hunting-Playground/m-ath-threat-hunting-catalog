$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..\..")

# Install the shared dependencies used across all scenarios
& (Join-Path $repoRoot "install\install_dependencies.ps1")

# Install any additional dependencies required only by this scenario
$scenarioRequirements = Join-Path $scriptDir "requirements.txt"
$hasExtras = (Test-Path $scenarioRequirements) -and (Select-String -Path $scenarioRequirements -Pattern "^\s*[^#\s]" -Quiet)

if ($hasExtras) {
    Write-Host "Installing scenario-specific dependencies from: $scenarioRequirements"
    python -m pip install -r $scenarioRequirements
} else {
    Write-Host "No scenario-specific dependencies to install."
}

Write-Host "Scenario dependency installation completed."
