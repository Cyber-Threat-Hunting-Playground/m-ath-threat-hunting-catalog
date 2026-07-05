# Threat Hunting Using Composite Scoring and VirusTotal Telemetry

**Ref:** M15

## Description

This scenario applies a composite scoring model to VirusTotal command-line telemetry by combining multiple behavioral features into a single weighted score. The goal is to prioritize novel, suspicious, or obfuscated command activity that might otherwise be lost in noisy telemetry.

## M-ATH Sub-process

**Model-Assisted Methods** - Combine multiple weak signals into a single prioritization score for analyst review.

## Method

1. **Load** - Read VirusTotal or equivalent command-line telemetry from `input/`.
2. **Extract Features** - Capture behavioral indicators such as obfuscation, rarity, suspicious argument patterns, or execution context.
3. **Score** - Combine the signals into a weighted composite score.
4. **Prioritize** - Rank commands or samples by the final score.
5. **Investigate** - Review the top findings and adapt the same approach to internal telemetry if useful.

## Data Needed

- VirusTotal threat intelligence or command-line telemetry exports
- Optional internal command-line telemetry if adapting the method beyond VirusTotal

## Data Collection - Initial Query

Export command-line telemetry with enough fidelity to preserve argument structure and suspicious patterns. Composite scoring works best when each record includes the raw command line and any auxiliary context used to compute risk features.

## Input

Place input data such as CSV or JSON exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## GitHub Codespaces

This scenario is compatible with GitHub Codespaces.

1. Open the repository in a Codespace.
2. If the Codespace was created before dependency changes, run **Dev Containers: Rebuild Container** from the Command Palette so the devcontainer reinstalls packages from `install/requirements.txt`.
3. Place the scenario input data into this scenario's `input/` folder.
4. Run the notebook or script you implement for this scenario from inside the repository workspace.
5. Write the resulting findings to this scenario's `output/` folder.

Notes:
- Relative paths in your implementation should be anchored to the repository workspace so the same code works locally and in Codespaces.
- If your implementation needs extra packages or secrets, install them in the Codespace and configure them as Codespaces secrets before running.

## Output

| File | Description |
|------|-------------|
| `output/` | Composite-scored command-line findings and supporting feature values |

## How to Run

1. Export VirusTotal or equivalent command-line telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write the ranked findings to `output/` and review the highest-scoring commands.

## References

- https://detect.fyi/in-the-wild-threat-hunting-using-composite-scoring-and-virustotal-telemetry-53605f27ae17

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
