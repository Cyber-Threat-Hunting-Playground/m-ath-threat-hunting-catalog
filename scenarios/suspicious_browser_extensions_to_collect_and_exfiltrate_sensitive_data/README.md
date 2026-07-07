# Suspicious browser extensions to collect and exfiltrate sensitive data

**Ref:** M20

## Description

This scenario hunts for browser or VS Code extensions that appear designed to collect sensitive information and exfiltrate it. The analysis can focus on extension permissions, installed package metadata, network destinations, and behavioral indicators that distinguish legitimate extensions from risky ones.

## M-ATH Sub-process

**Model-Assisted Methods** - Score or classify extension artifacts using multiple behavioral and metadata signals to prioritize suspicious candidates.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, risk-scoring definitions |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | Extension data loading, permission/keyword scoring, flagging |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Results export |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Update permission/keyword lists, share with IT admin |

## Method

1. **Load** - Read extension inventory or metadata exports from `input/`.
2. **Extract** - Capture publisher, permissions, package metadata, and network or file-system behaviors.
3. **Score** - Prioritize extensions with excessive permissions, suspicious publishers, or exfiltration-like indicators.
4. **Correlate** - Compare findings with known approved extensions or internal allowlists.
5. **Investigate** - Review the most suspicious extensions for collection and exfiltration risk.

## Data Needed

- Browser or VS Code extension inventories, manifests, permission sets, or behavior telemetry
- Optional network and file activity associated with extension processes

## Data Collection - Initial Query

Export installed extension metadata and, where available, extension-related network or process telemetry. Keep publisher, version, permission, and path details so suspicious packages can be validated quickly.

## Input

Place extension inventory or behavior exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- This scenario includes `browser_extensions.ipynb` as the analysis notebook

## Output

| File | Description |
|------|-------------|
| `output/` | Ranked suspicious extension candidates and supporting metadata |

## How to Run

1. Export extension metadata or related telemetry into `input/`.
2. Open `browser_extensions.ipynb` and run all cells.
3. Review suspicious extension findings in `output/`.

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
