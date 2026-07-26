# GitHub Workflows & Automation

The repository contains continuous integration workflows configured under `.github/workflows/` to automate validations, compliance checks, data enrichment, and catalog updates.

## GitHub Actions Integration

1. **VirusTotal Enrichment**:
   - Add the `VT_API_KEY` secret in repository settings (**Settings** → **Secrets and variables** → **Actions**).
   - Runs automatically when high-confidence findings are updated, or manually via workflow dispatch.

2. **Auto-Validation Checks**:
   - Automated workflows run daily (at midnight or 2:00 AM UTC) to detect missing scenario entries, unmapped Atomic Red Team tests, or folder structure inconsistencies.

---

## Workflow Details

* **Check Atomic Red Team Scenarios** ([check-art-scenarios.yml](../.github/workflows/check-art-scenarios.yml)):
  - Runs daily at midnight UTC or manually.
  - Downloads the latest Atomic Red Team YAML index and checks mapped MITRE ATT&CK techniques against `scenarios/catalog.csv`.
  - Automatically updates scenario `README.md` files with newly identified test cases and opens/updates a Pull Request (`update-art-scenarios`).
* **Check Catalog Sync** ([check-catalog-sync.yml](../.github/workflows/check-catalog-sync.yml)):
  - Runs daily at 2:00 AM GMT or manually.
  - Identifies scenario directories not registered in `scenarios/catalog.csv` (using [find_missing_in_catalog.py](../.github/scripts/find_missing_in_catalog.py)) and files GitHub Issues (using [create_missing_catalog_issues.py](../.github/scripts/create_missing_catalog_issues.py)).
* **Check Scenarios Folders** ([check-scenarios-folders.yml](../.github/workflows/check-scenarios-folders.yml)):
  - Runs daily at 2:00 AM GMT or manually.
  - Verifies that all scenarios in `catalog.csv` have folders containing `input/` and `output/` directories (using [find_missing_scenarios_folders.py](../.github/scripts/find_missing_scenarios_folders.py)) and files GitHub Issues (using [create_missing_scenarios_folder_issues.py](../.github/scripts/create_missing_scenarios_folder_issues.py)).
* **Check Data Transform Scripts** ([check-data-transform.yml](../.github/workflows/check-data-transform.yml)):
  - Triggered on PRs/pushes to `data_transform/`.
  - Quality checks Python scripts (using [create_data_transform_issues.py](../.github/scripts/create_data_transform_issues.py)) for compilation, shebang structure, top-level docstrings, and argparse `--dry-run` support, opening issues for compliance failures.
* **Check PEAK M-ATH Compliance** ([check-peak-compliance.yml](../.github/workflows/check-peak-compliance.yml)):
  - Triggered on pushes/PRs affecting `scenarios/**` or audit scripts, or manually.
  - Audits scenario notebooks and files for alignment with the Splunk PEAK Threat Hunting Framework (using `audit_peak_compliance.py`), creating issues for non-compliant scenarios and enforcing build checks.
* **Create Scenario from Issue** ([create-scenario-from-issue.yml](../.github/workflows/create-scenario-from-issue.yml)):
  - Triggered when an issue is labeled `create-scenario` or manually dispatched with an issue number.
  - Automatically bootstraps new scenario folder structures and updates `scenarios/catalog.csv` via a Pull Request (using `generate_scenario_from_issue.py`).
* **Download Confusables** ([download-confusables.yml](../.github/workflows/download-confusables.yml)):
  - Runs automatically on pushes to the default branch or manually.
  - Updates Unicode confusables data under `detection_logics/resources/unicode_TR39_confusables.txt` dynamically.
* **Run Test Suite** ([run-tests.yml](../.github/workflows/run-tests.yml)):
  - Triggered on pushes and pull requests to `main`/`master` (excluding doc changes) or manually.
  - Installs requirements and executes unit tests via `pytest`.
* **Track Other Data Sources** ([track-other-data-sources.yml](../.github/workflows/track-other-data-sources.yml)):
  - Triggered when issues labeled `proposed-scenario` are opened, edited, or labeled.
  - Checks for non-standard data sources mentioned in issue bodies and creates tracking issues (using `check_other_data_sources.py`).
* **Add VirusTotal verdicts** ([virustotal-high-confidence.yml](../.github/workflows/virustotal-high-confidence.yml)):
  - Enriches high-confidence findings automatically with VirusTotal verdicts upon change.

