# Process Memory Allocation Anomaly Scoring

**Ref:** M27

## Description

Detect process memory injection techniques such as Process Hollowing, DLL Injection, and reflective DLL loading by isolating processes that exhibit anomalous memory allocation profiles. By monitoring dynamic memory adjustments on endpoints, threat hunters can uncover stealthy implants, packing, and beaconing code that bypass traditional on-disk antivirus checks.

## Why M-ATH Applies

Traditional detection rules struggle with process memory events due to the high volume of legitimate VirtualAlloc and VirtualProtect actions performed by browsers, JIT compilers (e.g., JVM, .NET), and signed software. Model-Assisted Threat Hunting (M-ATH) is required to build baseline behavior models for common processes (e.g., svchost.exe, explorer.exe) and identify instances that deviate from their normal cluster distributions.

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
