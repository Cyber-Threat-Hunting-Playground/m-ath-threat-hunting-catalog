$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& "$scriptDir/../../../install/bootstrap_scenario_venv.ps1" -ScenarioPath "$scriptDir/.."
