---
name: create-m-ath-scenario
description: Guide on how to bootstrap, structure, and register a new Model-Assisted Threat Hunting (M-ATH) scenario in the catalog.
---

# Creating a M-ATH Scenario

Use this skill when you need to initialize a new threat hunting scenario. This ensures consistency across the repository and proper integration with downstream validation pipelines.

## Step-by-Step Workflow

### 1. Register in Scenario Catalog
Add a new row to [catalog.csv](../../scenarios/catalog.csv). Format:
```csv
Ref,Folder,Use case,Description,Model used,Data needed,Source
```
- **Ref:** The next reference ID (e.g., `M30`).
- **Folder:** The snake_case folder name (e.g., `process_injection_anomaly_scoring`).
- **Use case:** Clear descriptive title.
- **Description:** Summary of the hunt objective and ML approach.
- **Model used:** Algorithms (e.g., isolation forest, PCA, K-Means).
- **Data needed:** Telemetry sources (e.g., EDR logs, DNS).
- **Source:** External references/inspiration if any.

### 2. Create the Directory Structure
Under [scenarios/](../../scenarios), create the following layout:
```text
scenarios/<scenario_folder_name>/
├── README.md
├── <scenario_folder_name>.ipynb
├── requirements-<suffix>.txt (optional)
├── config/
│   ├── .env (optional config/secrets template)
│   └── evidence_forge.yaml (optional, if using EvidenceForge)
├── input/
│   ├── validation_sample.csv (for manual/real datasets) OR
│   └── validation_sample_evidenceforge.csv (generated synthetically)
├── output/
│   └── .gitkeep (to track folder empty by default)
├── models/ (optional, for saved pickle/onnx files)
└── exclusions/ (optional, for false positive lists)
```

### 3. Create or Generate Input Telemetry
For testing and validation, a scenario needs sample input data under `input/`. You can either provide manual real-world logs or generate synthetic ones:
- **Synthetic Logs (EvidenceForge):** Create an EvidenceForge configuration file named `config/evidence_forge.yaml` inside your scenario folder. Generate the telemetry by running:
  ```powershell
  python scripts/generate_telemetry.py --scenario scenarios/<scenario_folder_name>
  ```
  This creates `input/validation_sample_evidenceforge.csv`, which is ignored in git via [.gitignore](../../.gitignore).
- **Manual Data:** Place a sanitized and anonymized CSV file directly in `input/validation_sample.csv`.

### 4. Write local README.md
The local `README.md` must contain:
- **Ref ID** (matching catalog)
- **Description** of the detection
- **M-ATH Sub-process** (Classification, Clustering, Anomaly Detection, or Time-Series)
- **PEAK Framework Alignment** table (Prepare, Execute, Act, Knowledge phases)
- **Method** (step-by-step workflow of the notebook)
- **Data Needed** & **Data Collection Initial Query**
- **Prerequisites** and **Execution Instructions**

### 5. Code structure of the Notebook
Every notebook must follow this structure:
1. **Prepare Phase:** Imports, environment checks, loading modular logic from `detection_logics` (e.g., [s1_triage.py](../../detection_logics/s1_triage.py)).
2. **Execute Phase:** Read data from `input/validation_sample_evidenceforge.csv` (if using EvidenceForge) or `input/validation_sample.csv`, perform feature extraction, apply model/heuristics, and flag candidates.
3. **Act Phase:** Output candidates to `output/` as a CSV file containing scored leads.

### Verification Checklist
- [ ] Run `python .github/scripts/find_missing_in_catalog.py` to ensure the folder matches the catalog entry.
- [ ] Run `python .github/scripts/find_missing_scenarios_folders.py` to check folder structure compliance.
