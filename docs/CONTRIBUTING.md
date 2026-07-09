# Contributing a Threat Hunting Scenario

Thank you for choosing to contribute to the Threat Hunting M-ATH Catalog! This guide walks you through proposing, implementing, and submitting a new Model-Assisted Threat Hunting (M-ATH) scenario locally.

---

## 1. Prerequisites

Before starting, ensure you have the following installed on your machine:
* **Python** (version 3.12 or newer)
* **Git**
* **virtualenv** (or python standard library `venv`)

---

## 2. Propose & Bootstrap a Scenario

To start, you need to add your scenario to the catalog and bootstrap the scenario directory. You can do this interactively or by using a markdown file.

### Mode A: Interactive Questionnaire (Console)
Run the proposal script without arguments:
```bash
python scripts/propose_scenario.py
```
This launches a step-by-step questionnaire in your console to gather details (such as Use Case, PEAK Sub-process, Model type, and Data Needed) and bootstrap your scenario files automatically.

### Mode B: File-based proposal
If you already have your proposal written down in a markdown file (using the same sections as the GitHub Issue Form template), pass the path to the script:
```bash
python scripts/propose_scenario.py path/to/proposal.md
```

### What gets created?
The script will automatically:
1. Allocate the next Reference ID (e.g. `M26`) in `scenarios/catalog.csv`.
2. Slugify the Scenario name to create a folder under `scenarios/` (e.g. `scenarios/vpn_remote_access_abuse/`).
3. Generate standard subfolders (`input/`, `output/`, `install/`).
4. Generate wrapper setup scripts and a custom `README.md` containing your M-ATH explanation.

---

## 3. Prepare the Scenario Environment

Each scenario can manage its own specific package requirements. To configure your local virtual environment:
1. Add scenario-specific packages (e.g., `scikit-learn`, `numpy`) to `scenarios/<your_scenario>/install/requirements.txt`.
2. Run the platform-appropriate setup script to create the scenario virtualenv:
   * **Windows (PowerShell)**:
     ```powershell
     powershell -ExecutionPolicy Bypass -File scenarios/<your_scenario>/install/install_dependencies.ps1
     ```
   * **Unix / Linux / macOS**:
     ```bash
     bash scenarios/<your_scenario>/install/install_dependencies.sh
     ```

---

## 4. Implement Your Scenario

Now, develop your threat hunt analytics:
1. Create a Jupyter Notebook (`.ipynb`) or a Python script (`.py`) inside `scenarios/<your_scenario>/`.
2. Put any test dataset files (e.g., mock DNS traffic logs, AD event logs) inside the `input/` folder.
3. Write your analytics code. Ensure that:
   * Data is loaded from the `input/` folder.
   * Results and findings are written to the `output/` folder.
   * If applying standard risk-scoring or enrichment logic, reuse the shared `detection_logics` package rules.

---

## 5. Quality & Compliance Verification

Before staging or committing your work, run the project's sanity compliance checks locally:
```bash
python scripts/pre_commit_check.py
```
This validator checks for:
* Virtual environments committed by mistake.
* Unintended database dumps or dataset files staged in scenario directories (only `.gitkeep`, scripts, and `.example` templates are permitted to be committed).
* Leakage of sensitive paths (e.g., local system file URLs) or local usernames.
* Hardcoded generic/company placeholders.

Fix any reported failures before continuing.

---

## 6. Submit a Pull Request

Once everything is verified and compliant:
1. Create a new git branch:
   ```bash
   git checkout -b propose-scenario-<RefID>
   ```
2. Commit your scenario folder and catalog changes:
   ```bash
   git add scenarios/catalog.csv scenarios/<your_scenario>/
   git commit -m "feat: implement scenario <RefID> - <Scenario Title>"
   ```
3. Push your branch and open a Pull Request on GitHub. The test suite and catalog check will run automatically to verify your PR.
