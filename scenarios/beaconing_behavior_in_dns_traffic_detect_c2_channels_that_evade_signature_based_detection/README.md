# Beaconing behavior in DNS traffic (Detect C2 channels that evade signature-based detection)

**Ref:** M02

## Description

This scenario hunts for DNS beaconing that may indicate command-and-control activity such as Cobalt Strike. The goal is to find hosts that contact a domain at near-constant intervals even when the traffic blends into otherwise normal DNS activity.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Identify DNS communication patterns that deviate from expected timing and frequency baselines.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, interval statistics definitions |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | DNS data loading, interval computation, CV-based periodicity flagging |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Results export, DNS blocklist candidates |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Tune thresholds, add exclusions, share with DNS/SOC teams |

## Method

1. **Load** - Read DNS telemetry exported to `input/`.
2. **Normalize** - Group records by host and destination domain or IP so repeated communication can be measured.
3. **Measure** - Calculate connection intervals, frequency, and simple periodicity indicators.
4. **Prioritize** - Surface hosts with near-constant or otherwise suspicious beacon-like timing.
5. **Investigate** - Correlate suspicious domains with destination reputation, process lineage, and host context.

## Data Needed

- DNS logs with timestamps, source host identifiers, and queried domains
- Optional enrichment such as endpoint name, process, or destination reputation

## Data Collection - Initial Query

Query DNS telemetry for repeated outbound requests over a meaningful time window, then export the results to CSV for analysis in this scenario folder. Focus on fields that preserve event time, source host, and destination domain so interval-based analysis remains possible.

## Input

Place DNS CSV files in `input/`. Include enough history to observe repeated requests from the same host to the same destination.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- This scenario includes `beaconing_dns.ipynb` as the analysis entry point

## GitHub Codespaces

This scenario is compatible with GitHub Codespaces.

1. Open the repository in a Codespace.
2. If the Codespace was created before dependency changes, run **Dev Containers: Rebuild Container** from the Command Palette so the devcontainer reinstalls packages from `install/requirements.txt`.
3. Place the scenario input data into this scenario's `input/` folder.
4. Open the notebook and run all cells.

Notes:
- The notebook resolves paths relative to the repository workspace and works in local clones and Codespaces.
- If this scenario later adds extra dependencies beyond `install/requirements.txt`, install them inside the Codespace before running the notebook.

## Output

| File | Description |
|------|-------------|
| `output/` | Ranked beaconing candidates and any supporting exports produced by the notebook |

## How to Run

1. Export DNS telemetry into `input/`.
2. Open `beaconing_dns.ipynb` and run all cells.
3. Review the scored beaconing candidates in `output/`.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
