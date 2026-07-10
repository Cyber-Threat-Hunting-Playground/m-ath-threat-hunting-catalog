# Example M-ATH Scenario Template

**Ref:** M00_TEMPLATE

## Description
This is a bootstrap template folder for new Threat Hunting M-ATH scenarios.

## Structure
- `input/`: Raw telemetry or data input files (e.g., CSV, JSON exports).
- `output/`: Generated charts, prioritized lead tables, and logs.
- `config/`: Scenario-specific local configuration.
  - `.env.example`: Template for credentials/endpoints. Copy to `.env` locally.
- `install/`: Isolated dependency installation scripts.
  - `requirements.txt`: List of Python packages required for this scenario.
  - `install_dependencies.sh`: Unix script to initialize environment.
  - `install_dependencies.ps1`: Windows PowerShell script to initialize environment.
