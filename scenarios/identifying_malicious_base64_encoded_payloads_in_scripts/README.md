# Identifying malicious base64 encoded payloads in scripts

**Ref:** M05

## Description

This scenario detects suspicious Base64-encoded commands and script payloads that attackers use to hide intent and evade straightforward signatures. The hunt is intended to surface unusually long encoded commands, decoded content that matches obfuscation patterns, and payloads associated with known offensive tradecraft.

## M-ATH Sub-process

**Model-Assisted Methods** - Decode and score encoded script content so suspicious patterns can be prioritized for review.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, Base64 decode/scoring helpers |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | EDR data loading, Base64 extraction, decoding, scoring |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Results export |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Update scoring heuristics, share payloads with SOC/intel teams |

## Method

1. **Load** - Read script or command-line telemetry from `input/`.
2. **Extract** - Identify candidate Base64 strings in commands, script blocks, or payload fields.
3. **Decode** - Convert Base64 strings back to plaintext where possible.
4. **Score** - Flag long, obfuscated, or suspicious decoded content for review.
5. **Investigate** - Review decoded commands alongside host, user, and parent-process context.

## Data Needed

- EDR telemetry with command line, script block, or payload fields
- Optional host and user context for analyst triage

## Data Collection - Initial Query

Export process or script execution telemetry that preserves full command lines or script content. Encoded payload hunts are far less useful when command text is truncated during export.

## Input

Place command-line or script telemetry exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- This scenario includes `base64_payloads.ipynb` as the analysis notebook

## Output

| File | Description |
|------|-------------|
| `output/` | Decoded and prioritized Base64 payload findings |

## How to Run

1. Export command-line or script telemetry into `input/`.
2. Open `base64_payloads.ipynb` and run all cells.
3. Review the decoded and scored payload findings in `output/`.

## References

- https://github.com/THORCollective/HEARTH/blob/main/Alchemy/M005.md

For pipeline execution (GitHub Actions), see the main [README](../../README.md).

## Atomic Red Team Tests

| Test Name | Test ID | Platform | Identified Date | Human Confirmed |
| --- | --- | --- | --- | --- |
| Decode base64 Data into Script | f45df6be-2e1e-4136-a384-8f18ab3826fb | macos, linux | 2026-07-14 | No |
| Execute base64-encoded PowerShell | a50d5a97-2531-499e-a1de-5544c74432c6 | windows | 2026-07-14 | No |
| Execute base64-encoded PowerShell from Windows Registry | 450e7218-7915-4be4-8b9b-464a49eafcec | windows | 2026-07-14 | No |
| Execution from Compressed File | f8c8a909-5f29-49ac-9244-413936ce6d1f | windows | 2026-07-14 | No |
| DLP Evasion via Sensitive Data in VBA Macro over email | 129edb75-d7b8-42cd-a8ba-1f3db64ec4ad | windows | 2026-07-14 | No |
| DLP Evasion via Sensitive Data in VBA Macro over HTTP | e2d85e66-cb66-4ed7-93b1-833fc56c9319 | windows | 2026-07-14 | No |
| Obfuscated Command in PowerShell | 8b3f4ed6-077b-4bdd-891c-2d237f19410f | windows | 2026-07-14 | No |
| Obfuscated Command Line using special Unicode characters | e68b945c-52d0-4dd9-a5e8-d173d70c448f | windows | 2026-07-14 | No |
| Snake Malware Encrypted crmlog file | 7e47ee60-9dd1-4269-9c4f-97953b183268 | windows | 2026-07-14 | No |
| Execution from Compressed JScript File | fad04df1-5229-4185-b016-fb6010cd87ac | windows | 2026-07-14 | No |
| Obfuscated PowerShell Command via Character Array | 6683baf0-6e77-4f58-b114-814184ea8150 | windows | 2026-07-14 | No |
