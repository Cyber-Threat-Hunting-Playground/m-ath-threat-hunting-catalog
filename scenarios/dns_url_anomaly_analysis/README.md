# DNS & URL suspicion analysis

**Ref:** M23

## Description

This scenario reads CSV files from `input/` recursively and flags potentially suspicious DNS questions and URL access patterns. It uses rule-based scoring, including Shannon entropy, suspicious keywords, risky TLDs, and punycode or base64 decoding, together with shared detection logics to prioritize findings.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Use heuristic scoring and anomaly-oriented enrichment to surface suspicious DNS and URL activity.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, scoring/decoding helpers |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | CSV loading, DNS/URL scoring, exclusion filtering, uncommon-country analysis |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Results dashboard, CSV exports, high-confidence slice |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Update TLD/keyword lists, refine exclusions, share anomalies with network teams |

## Method

1. **Load** - Read CSV files from `input/` and subfolders.
2. **Normalize** - Detect supported DNS and URL fields across varying input sources.
3. **Score** - Apply entropy checks, suspicious keyword checks, risky-TLD checks, and decoding logic.
4. **Enrich** - Reuse shared detection logics and exclusions to reduce obvious false positives.
5. **Output** - Write prioritized findings to `output/` for analyst review.

## Data Needed

- EDR logs or exported DNS and URL telemetry in CSV format
- Optional source metadata to support investigation of suspicious results

## Data Collection - Initial Query

Export DNS and URL telemetry from EDR, proxy, or web telemetry sources and store it as CSV. Preserve request values, timestamps, and source context so suspicious domains and URLs can be validated after scoring.

## Input

Place CSV input files in `input/` or nested subfolders such as `input/sentinelone/`. The notebook handles scenario-local path configuration in its first cell.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- Review any exclusions stored under `exclusions/` before running the notebook
- This scenario includes `dns_url_anomaly_analysis.ipynb` as the analysis notebook

## Output

| File | Description |
|------|-------------|
| `output/` | Scored DNS and URL findings with supporting reasons and context |

## How to Run

1. Add DNS or URL CSV input to `input/`.
2. Open `dns_url_anomaly_analysis.ipynb` and run all cells.
3. Review the generated findings in `output/`.

For pipeline execution (GitHub Actions), see the main [README](../../README.md).

## Atomic Red Team Tests

| Test Name | Test ID | Platform | Identified Date | Human Confirmed |
| --- | --- | --- | --- | --- |
| Malicious User Agents - Powershell | 81c13829-f6c9-45b8-85a6-053366d55297 | windows | 2026-07-14 | No |
| Malicious User Agents - CMD | dc3488b0-08c7-4fea-b585-905c83b48180 | windows | 2026-07-14 | No |
| Malicious User Agents - Nix | 2d7c471a-e887-4b78-b0dc-b0df1f2e0658 | linux, macos | 2026-07-14 | No |
