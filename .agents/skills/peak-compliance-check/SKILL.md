---
name: peak-compliance-check
description: Audit threat hunting scenarios for alignment with the Splunk PEAK Threat Hunting Framework phases.
---

# PEAK Compliance Auditing

Use this skill to audit existing or newly written threat hunting scenarios against the **Splunk PEAK Framework** standards. This ensures that every hunt covers the operational loop from telemetry selection to knowledge feedback.

## Automated Compliance Auditing

The repository includes an automated compliance auditor script at [audit_peak_compliance.py](file:///c:/Users/jmarc/OneDrive/Documents/Projets/Threat%20Hunting/threat_hunting_m-ath_catalog/scripts/audit_peak_compliance.py) that checks the folder structure, README alignment, and Jupyter Notebook cells.

### Running the Auditor

You can run the auditor manually using Python:

```powershell
# Audit a single scenario directory
python scripts/audit_peak_compliance.py --scenario <scenario_folder_name>

# Audit all scenarios defined in the catalog.csv
python scripts/audit_peak_compliance.py --all

# Audit all scenarios and write output to a JSON file
python scripts/audit_peak_compliance.py --all --json peak_compliance_results.json
```

---

## PEAK Framework Compliance Requirements

The automated tool checks the following checklist:

### 1. Prepare Phase
Verify that the scenario README and Notebook cover:
- **Topic Identification:** Must have a reference ID (e.g., `Ref: M01` in README) matching the threat catalog.
- **Data Requirements:** Data needed / telemetry sources must be documented in README.
- **Algorithm Selection:** Statistical/ML models documented in README and a markdown header `# PREPARE` exists in the Jupyter Notebook to set up imports, configuration, and environment.

### 2. Execute Phase
Check that the Jupyter notebook implementation includes:
- **Phase Header:** A markdown header `# EXECUTE` to group data loading and execution cells.
- **Data Ingestion:** Ingests raw data from `input/validation_sample.csv` or configured subdirectories.
- **Normalization & Feature Extraction:** Cleans and normalizes columns.
- **Model Ingestion & Prediction:** Runs the model (statistical or machine learning).
- **Candidate Filtering:** Identifies and filters leads.

### 3. Act Phase
Ensure the scenario provides a pathway to operationalize findings:
- **Phase Header:** A markdown header `# ACT` to group findings and output cells.
- **Scored Leads:** Outputs findings with clear confidence levels or anomaly scores to `output/`.
- **Enrichment Integration:** Calls shared helpers (VirusTotal, active directory, etc.) to assist in triage.
- **KPI Auditing:** Uses `KPITracker` to record execution duration, input size, and row throughput.

### 4. Knowledge Phase
Verify that the feedback loop is documented:
- **Phase Header:** A markdown header `# KNOWLEDGE` (or `# KNOWLEDGE / FEEDBACK`) to group feedback details.
- **Model Retraining:** Mentions how false positives can be fed back to retrain/adjust parameters.
- **Detection Optimization:** Mentions how findings can be converted into static detection rules (e.g., Sigma rules, Splunk correlation searches).

---

## Lifecycle Enforcements

### 1. Pre-Commit Validation
When staging files inside a scenario folder, `scripts/pre_commit_check.py` automatically runs the compliance auditor on that scenario.
- **If non-compliant:** The commit is aborted.
- **Documentation:** A local detailed report is written to `scenarios/<scenario_folder>/.peak_compliance_report.md` (which is git-ignored). Read this report to identify exactly what checks failed.

To bypass this check during emergency commits, set the environment variable:
```powershell
$env:PEAK_SKIP_COMPLIANCE="1"
git commit -m "commit message"
```

### 2. CI/CD Pipeline & GitHub Issues
On pull requests or pushes to main/master:
- The GitHub workflow `.github/workflows/check-peak-compliance.yml` runs the compliance audit on all cataloged scenarios.
- **GitHub Issue Creation:** If any scenario fails compliance, a script automatically creates or updates a GitHub Issue titled `PEAK Non-Compliance: <scenario_folder> (MXX)` with the detailed failure checklist, labeled `peak-non-compliance`.
- The build will fail, blocking the Pull Request until compliance issues are fixed.
