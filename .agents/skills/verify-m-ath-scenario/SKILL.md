---
name: verify-m-ath-scenario
description: Run automated validation and integration checks on a M-ATH Jupyter notebook or script.
---

# Verifying a M-ATH Scenario

Use this skill to validate a scenario before submitting a Pull Request, or when debugging CI/CD pipeline failures.

## Verification Workflow

### 1. Catalog & Folder Structure Verification
Run the python check scripts to ensure that the scenario folder structure matches the repository specifications:
```powershell
# Check if all scenario folders exist and contain required input/output dirs
python .github/scripts/find_missing_scenarios_folders.py

# Check if scenarios in catalog.csv match existing directories
python .github/scripts/find_missing_in_catalog.py
```

### 2. Notebook Execution Test
To ensure the Jupyter notebook executes successfully from start to finish without raising unhandled exceptions, use `nbconvert` to run it headlessly:
```powershell
# Navigate to the scenario directory
cd scenarios/<scenario_folder_name>

# Install requirements
pip install -r requirements-<suffix>.txt

# Run the notebook in-place and output execution logs
jupyter nbconvert --to notebook --execute <scenario_folder_name>.ipynb --output test_execution.ipynb
```
*Note: Clean up any generated `test_execution.ipynb` or test artifacts in `output/` before committing.*

### 3. Check for Shared Logic Decoupling
Ensure the notebook does not hardcode common tasks (e.g., domain parsing, VirusTotal reputation checks, SentinelOne triage). Look for imports from `detection_logics` package:
- Check for `import detection_logics` or specific module imports.
- Confirm that the `apply` scoring methods are used.

### 4. Output Validation
Check the schema of the CSV file generated under `output/`:
- Ensure that the columns match the requirements outlined in the scenario's local `README.md`.
- Verify that it outputs a scoring indicator (e.g., `prediction`, `score`, or `anomaly_score`).
