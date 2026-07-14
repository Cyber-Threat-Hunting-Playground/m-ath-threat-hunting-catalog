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

## Atomic Red Team Tests

| Test Name | Test ID | Platform | Identified Date | Human Confirmed |
| --- | --- | --- | --- | --- |
| Shellcode execution via VBA | 1c91e740-1729-4329-b779-feba6e71d048 | windows | 2026-07-14 | No |
| Remote Process Injection in LSASS via mimikatz | 3203ad24-168e-4bec-be36-f79b13ef8a83 | windows | 2026-07-14 | No |
| Section View Injection | c6952f41-6cf0-450a-b352-2ca8dae7c178 | windows | 2026-07-14 | No |
| Dirty Vanity process Injection | 49543237-25db-497b-90df-d0a0a6e8fe2c | windows | 2026-07-14 | No |
| Read-Write-Execute process Injection | 0128e48e-8c1a-433a-a11a-a5387384f1e1 | windows | 2026-07-14 | No |
| Process Injection with Go using UuidFromStringA WinAPI | 2315ce15-38b6-46ac-a3eb-5e21abef2545 | windows | 2026-07-14 | No |
| Process Injection with Go using EtwpCreateEtwThread WinAPI | 7362ecef-6461-402e-8716-7410e1566400 | windows | 2026-07-14 | No |
| Remote Process Injection with Go using RtlCreateUserThread WinAPI | a0c1725f-abcd-40d6-baac-020f3cf94ecd | windows | 2026-07-14 | No |
| Remote Process Injection with Go using CreateRemoteThread WinAPI | 69534efc-d5f5-4550-89e6-12c6457b9edd | windows | 2026-07-14 | No |
| Remote Process Injection with Go using CreateRemoteThread WinAPI (Natively) | 2a4ab5c1-97ad-4d6d-b5d3-13f3a6c94e39 | windows | 2026-07-14 | No |
| Process Injection with Go using CreateThread WinAPI | 2871ed59-3837-4a52-9107-99500ebc87cb | windows | 2026-07-14 | No |
| Process Injection with Go using CreateThread WinAPI (Natively) | 2a3c7035-d14f-467a-af94-933e49fe6786 | windows | 2026-07-14 | No |
| UUID custom process Injection | 0128e48e-8c1a-433a-a11a-a5304734f1e1 | windows | 2026-07-14 | No |
