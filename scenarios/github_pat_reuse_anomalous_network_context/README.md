# GitHub PAT reuse in anomalous network context

**Ref:** M27

## Description

This scenario detects possible theft and reuse of GitHub Personal Access Tokens (PATs) by baselining normal PAT usage and identifying suspicious context drift. It focuses on token use from unusual geolocations, unexpected network carriers/ASNs, and unusual user-agent families, plus impossible-travel velocity between consecutive uses of the same PAT.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Build per-token behavioral baselines from historical audit events and score newer events for anomalous deviations.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, configuration |
| **Execute** | Gather data, pre-process, apply model, analyze, refine, escalate | Data loading, preprocessing, model execution, candidate filtering |
| **Act** | Document findings, preserve hunt, create detections/playbooks | KPI tables, results export |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Feedback loops, model retraining, static rule creation |

## Method

1. **Load** - Read GitHub PAT audit log events from `input/`.
2. **Baseline** - Learn each PAT's usual countries, carriers, ASNs, user-agent families, and common usage hours from early historical events.
3. **Detect** - Score newer events for context drift (`new_country`, `new_network_carrier`, `new_user_agent_family`, `impossible_travel_velocity`, etc.).
4. **Prioritize** - Keep medium/high-risk findings above a score threshold.
5. **Investigate** - Review top findings for signs of stolen token use and credential abuse.

## Data Needed

- GitHub audit logs (or equivalent export) with PAT usage context
- Fields for timestamp, actor, token identifier, IP/location, network carrier or ASN, and user-agent

## Input

Place input CSV files in `input/`.

The provided sample generator outputs:

- `input/github_pat_audit_sample.csv` - realistic fake PAT usage telemetry

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- Python with `pandas` available

## Output

| File | Description |
|------|-------------|
| `output/github_pat_reuse_scored_events.csv` | Full scored dataset with baseline-period marker, score, reasons, velocity, and risk level |
| `output/github_pat_reuse_findings.csv` | Prioritized suspicious events where score is above threshold |
| `output/github_pat_reuse_kpis.png` | KPI dashboard image generated at the end of the notebook |

## How to Run

From the repository root:

```powershell
python scenarios/github_pat_reuse_anomalous_network_context/input/generate_fake_github_pat_logs.py
python scenarios/github_pat_reuse_anomalous_network_context/github_pat_reuse_anomalous_network_context.py
```

Optional detector parameters:

```powershell
python scenarios/github_pat_reuse_anomalous_network_context/github_pat_reuse_anomalous_network_context.py `
  --input scenarios/github_pat_reuse_anomalous_network_context/input/github_pat_audit_sample.csv `
  --output-dir scenarios/github_pat_reuse_anomalous_network_context/output `
  --min-score 3 `
  --baseline-ratio 0.7
```

Notebook execution:

```powershell
# Open and run all cells:
scenarios/github_pat_reuse_anomalous_network_context/github_pat_reuse_anomalous_network_context.ipynb
```

## Test dataset details

`generate_fake_github_pat_logs.py` intentionally mixes:

- normal developer PAT usage (same country/carrier/UA patterns)
- a small number of injected suspicious PAT reuses from distant geographies
- suspicious user-agent families (for example `curl`, `python-requests`, `Go-http-client`)
- proxy/VPN source flag and higher-privilege token scopes

This allows quickly validating that the detector elevates realistic takeover-like events while leaving routine usage at low score.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
