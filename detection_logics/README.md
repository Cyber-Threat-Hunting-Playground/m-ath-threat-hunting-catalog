# Shared Detection Logics Package

This directory contains modular, reusable "detection logic" rules. These rules are applied to candidate threat hunt leads (typically URLs, domain names, or other text values) during scenarios to:
- **Increase a risk score** based on rule hits.
- **Add standardized reason tags** explaining *why* the score was increased.

This delegates generic triage and enrichment scoring rules to this shared package, letting Jupyter Notebooks and scenario scripts focus on core analytics (feature extraction, clustering, anomaly detection, modeling, and ranking).

---

## Logic Module Signature & Integration

Each detection logic module must implement a simple contract:
- Export an `apply(value: str, decoded_value: str) -> (score_delta: int, reason_name: str | None)` function.
- Return `(0, None)` if there is no hit.
- Return a positive score delta and a stable string reason identifier (tag) if the rule hits.

**Inputs:**
- `value`: The raw telemetry value (e.g., DNS query, HTTP URL).
- `decoded_value`: A normalized or decoded version of the value (e.g., punycode-decoded or Base64-decoded string).

**Outputs:**
- `score_delta`: An integer risk score increase.
- `reason_name`: String identifier indicating the matched rule (e.g., `dns_suspicious_string`).

After writing a new module, register its functions in `__init__.py` to run under the correct context (DNS or URL logic pipelines).

---

## Active Detection Logic Modules

The `detection_logics` package currently contains the following rules:

### 1. DNS Suspicious String ([dns_suspicious_string.py](./dns_suspicious_string.py))
- **Checks:** Detects known suspicious patterns/substrings in raw DNS values (punycode labels) and/or decoded values.
- **Scoring:** `+1` risk score per unique suspicious string match.
- **Reason Tag:** `dns_suspicious_string`

### 2. VirusTotal Verdict Check ([vt_verdict_not_clean.py](./vt_verdict_not_clean.py))
- **Checks:** Detects non-clean VirusTotal verdicts embedded in telemetry tags/metadata (e.g. `vt:malicious`, `vt_verdict=suspicious`, `[vt: suspicious]`).
- **Scoring:**
  - `malicious` → `+2`
  - `suspicious` (and other non-clean/undetected verdicts) → `+1`
- **Reason Tag:** `vt_verdict_not_clean`
