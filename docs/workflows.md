# GitHub Workflows & Automation

The repository contains continuous integration workflows configured under `.github/workflows/` to automate validations, compliance checks, data enrichment, and catalog updates.

## GitHub Actions Integration

1. **VirusTotal Enrichment**:
   - Add the `VT_API_KEY` secret in repository settings (**Settings** → **Secrets and variables** → **Actions**).
   - Runs automatically when high-confidence findings are updated, or manually via workflow dispatch.

2. **Auto-Validation Checks**:
   - Automated workflows run daily at 2:00 AM GMT to detect missing scenario entries or folders and verify script compliance.

---

## Workflow Details

* **Check Catalog Sync** ([check-catalog-sync.yml](../.github/workflows/check-catalog-sync.yml)):
  - Runs daily or manually.
  - Identifies scenario directories not registered in `scenarios/catalog.csv` (using [find_missing_in_catalog.py](../.github/scripts/find_missing_in_catalog.py)) and files GitHub Issues (using [create_missing_catalog_issues.py](../.github/scripts/create_missing_catalog_issues.py)).
* **Check Scenarios Folders** ([check-scenarios-folders.yml](../.github/workflows/check-scenarios-folders.yml)):
  - Runs daily or manually.
  - Verifies that all scenarios in `catalog.csv` have folders containing `input/` and `output/` directories (using [find_missing_scenarios_folders.py](../.github/scripts/find_missing_scenarios_folders.py)) and files GitHub Issues (using [create_missing_scenarios_folder_issues.py](../.github/scripts/create_missing_scenarios_folder_issues.py)).
* **Check Data Transform Scripts** ([check-data-transform.yml](../.github/workflows/check-data-transform.yml)):
  - Triggered on PRs/pushes to `data_transform/`.
  - Quality checks Python scripts (using [create_data_transform_issues.py](../.github/scripts/create_data_transform_issues.py)) for compilation, shebang structure, top-level docstrings, and argparse `--dry-run` support, opening issues for compliance failures.
* **Download Confusables** ([download-confusables.yml](../.github/workflows/download-confusables.yml)):
  - Runs automatically on pushes to the default branch or manually.
  - Updates Unicode confusables data under `detection_logics/resources/unicode_TR39_confusables.txt` dynamically.
* **Add VirusTotal verdicts** ([virustotal-high-confidence.yml](../.github/workflows/virustotal-high-confidence.yml)):
  - Enriches high-confidence findings automatically with VirusTotal verdicts upon change.
