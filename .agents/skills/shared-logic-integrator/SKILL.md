---
name: shared-logic-integrator
description: Integrate reusable detection and enrichment scoring logics from the detection_logics package into scenarios.
---

# Shared Logic Integration

Use this skill when you are writing or updating a M-ATH scenario that needs to enrich indicators (IPs, domains, hashes, process lines) or apply modular detection scoring rules.

## Standard Modular Structure

All shared scoring rules live inside the [detection_logics/](../../detection_logics) package. 

### Available Core Logics

1.  **VirusTotal Verdict Check (`vt_verdict_not_clean`):**
    - File: [vt_verdict_not_clean.py](../../detection_logics/vt_verdict_not_clean.py)
    - Purpose: Increments threat score based on VirusTotal findings (e.g. +2 for malicious, +1 for suspicious).
2.  **IDN & Punycode Security Analysis (`idn_security_analysis`):**
    - File: [idn_security_analysis.py](../../detection_logics/idn_security_analysis.py)
    - Purpose: Analyzes Internationalized Domain Names (IDNs) for homograph attacks or character confusables.
3.  **SentinelOne Triage (`s1_triage`):**
    - File: [s1_triage.py](../../detection_logics/s1_triage.py)
    - Purpose: Queries S1 Singularity Data Lake for context (process lineage, file writes) and uses an LLM to explain the activity and triage false positives.
4.  **DNS Suspicious String (`dns_suspicious_string`):**
    - File: [dns_suspicious_string.py](../../detection_logics/dns_suspicious_string.py)
    - Purpose: Evaluates DNS strings for high-entropy characters or specific dictionary matching anomalies.

## Integrating Logic into a Scenario

To use these in a Jupyter notebook:
1. Ensure the `detection_logics` package is installed in your python environment (usually via `pip install -e ./detection_logics` or by running `sys.path.append()`).
2. Import the desired module:
   ```python
   from detection_logics import vt_verdict_not_clean, idn_security_analysis
   ```
3. Loop through your candidates and evaluate their score:
   ```python
   score_increment, reason = vt_verdict_not_clean.apply(raw_domain, decoded_domain)
   candidate_score += score_increment
   ```

## Writing New Shared Logic
When creating a new scoring rule inside [detection_logics/](../../detection_logics):
- Must define `REASON_NAME = "your_logic_name"`.
- Must export an `apply` method with standard inputs:
  ```python
  def apply(value: str, decoded_value: str) -> tuple[int, str | None]:
      # returns: (score_increment, reason_name_or_None)
  ```
- Expose the module in `detection_logics/__init__.py`.
- Add test coverage in the `tests/` directory.
