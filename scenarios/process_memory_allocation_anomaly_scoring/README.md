# Process Memory Allocation Anomaly Scoring

**Ref:** M26

## Description

Detect process memory injection techniques such as Process Hollowing, DLL Injection, and reflective DLL loading by isolating processes that exhibit anomalous memory allocation profiles. By monitoring dynamic memory adjustments on endpoints, threat hunters can uncover stealthy implants, packing, and beaconing code that bypass traditional on-disk antivirus checks.

## M-ATH Sub-process

Model-Assisted Methods

## Why M-ATH Applies

Traditional detection rules struggle with process memory events due to the high volume of legitimate VirtualAlloc and VirtualProtect actions performed by browsers, JIT compilers (e.g., JVM, .NET), and signed software. Model-Assisted Threat Hunting (M-ATH) is required to build baseline behavior models for common processes (e.g., svchost.exe, explorer.exe) and identify instances that deviate from their normal cluster distributions.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, configuration |
| **Execute** | Gather data, pre-process, apply model, analyze, refine, escalate | Data loading, preprocessing, model execution, candidate filtering |
| **Act** | Document findings, preserve hunt, create detections/playbooks | KPI tables, results export |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Feedback loops, model retraining, static rule creation |

## Data needed

Endpoint Detection & Response (EDR) logs, Windows Event logs

## Source

MITRE ATT&CK T1055 (Process Injection), elastic guide to threat hunting in-memory detection.

## Inputs

Place input data (CSV, JSON, etc.) in `input/`.

## Outputs

Results are written to `output/`.

## How to run

1. Add input data to `input/`
2. Run the scenario notebook or script
3. Review outputs in `output/`
