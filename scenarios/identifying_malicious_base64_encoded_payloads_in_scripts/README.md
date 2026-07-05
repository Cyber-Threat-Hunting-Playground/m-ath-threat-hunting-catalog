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
| `output/` | Decoded and prioritized Base64 payload findings |

## How to Run

1. Export command-line or script telemetry into `input/`.
2. Open `base64_payloads.ipynb` and run all cells.
3. Review the decoded and scored payload findings in `output/`.

## References

- https://github.com/THORCollective/HEARTH/blob/main/Alchemy/M005.md

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
