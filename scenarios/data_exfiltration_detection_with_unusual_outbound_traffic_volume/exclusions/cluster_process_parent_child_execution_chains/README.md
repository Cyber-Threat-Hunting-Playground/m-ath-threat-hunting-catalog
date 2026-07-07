# Cluster process parent-child execution chains

**Ref:** M08

## Description

This scenario clusters process parent-child execution chains across the endpoint fleet to establish normal lineage patterns and surface rare or previously unseen process trees. The approach helps identify living-off-the-land abuse, novel malware execution, and compromised applications that break from normal parent-child behavior.

## M-ATH Sub-process

**Clustering** - Group common execution chains together and surface clusters or outliers that represent unusual lineage behavior.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, rarity thresholds |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | EDR data loading, parent-child frequency counting, rarity flagging |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Rare pairs export |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Update allowlists, tune thresholds, share with endpoint/SOC teams |

## Method

1. **Load** - Read process execution telemetry from `input/`.
2. **Build Chains** - Construct parent-child relationships and represent them as lineage sequences.
3. **Vectorize** - Convert lineage chains into features suitable for clustering or rarity scoring.
4. **Cluster** - Group common lineage patterns and isolate rare or novel chains.
5. **Investigate** - Review anomalous chains for suspicious parents, children, or execution context.

## Data Needed

- EDR process telemetry with process name, parent process name, timestamp, host, and command-line details
- Optional signer and path metadata to strengthen analyst review

## Data Collection - Initial Query

Query endpoint telemetry for process creation events that include both child and parent process fields. Export enough history to build a representative baseline of common process lineage patterns.

## Input

Place process execution exports in `input/`. Preserve parent-child relationships and host context in the exported data.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- This scenario includes `process_lineage.ipynb` as the analysis notebook

## Output

| File | Description |
|------|-------------|
| `output/` | Clustered execution-chain results and rare lineage candidates |

## How to Run

1. Export process creation telemetry into `input/`.
2. Open `process_lineage.ipynb` and run all cells.
3. Review the rare or never-seen parent-child chains written to `output/`.

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
