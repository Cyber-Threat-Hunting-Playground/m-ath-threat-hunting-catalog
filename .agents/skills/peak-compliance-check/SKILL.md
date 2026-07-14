---
name: peak-compliance-check
description: Audit threat hunting scenarios for alignment with the Splunk PEAK Threat Hunting Framework phases.
---

# PEAK Compliance Auditing

Use this skill to audit existing or newly written threat hunting scenarios against the **Splunk PEAK Framework** standards. This ensures that every hunt covers the operational loop from telemetry selection to knowledge feedback.

## PEAK Framework Phase Auditing Checklist

### 1. Prepare Phase
Verify that the scenario README and Notebook cover:
- [ ] **Topic Identification:** Does it have a reference ID (e.g., `M01`) aligned with the threat catalog?
- [ ] **Data Requirements:** Are the telemetry sources specified (e.g., DNS queries, process execution logs, authentication events)?
- [ ] **Algorithm Selection:** Is the ML or statistical approach clearly documented (e.g., LSTM, K-Means clustering, Isolation Forest)?

### 2. Execute Phase
Check that the Jupyter notebook implementation includes:
- [ ] **Data Ingestion:** Ingests raw data from `input/validation_sample.csv` or configured directories.
- [ ] **Normalization & Feature Extraction:** Cleans and normalizes columns (e.g., domain extraction, stripping TLDs, calculating TF-IDF or text entropy).
- [ ] **Model Ingestion & Prediction:** Runs the model (either pretrained weights in `models/` or statistical/unsupervised methods).
- [ ] **Candidate Filtering:** Identifies and filters leads that fall outside normal statistical thresholds.

### 3. Act Phase
Ensure the scenario provides a pathway to operationalize findings:
- [ ] **Scored Leads:** Outputs findings with clear confidence levels or anomaly scores to `output/` (e.g. `dictionary_dga_results.csv`).
- [ ] **Enrichment Integration:** Calls shared helpers (like VirusTotal or active directory details) to assist in triage.
- [ ] **Incident Path:** Suggests clear remediation or triage steps (e.g., blocking malicious domains, investigating process parents).

### 4. Knowledge Phase
Verify that the feedback loop is documented:
- [ ] **Model Retraining:** Mentions how false positives can be fed back to retrain or adjust parameters/thresholds.
- [ ] **Detection Optimization:** Mentions how the findings can be converted into static detection rules (e.g., Sigma rules, Splunk correlation searches) to automate the detection of this threat in the future.
- [ ] **Feedback Loop:** Suggests adjustments to ingestion pipelines for better data quality.
