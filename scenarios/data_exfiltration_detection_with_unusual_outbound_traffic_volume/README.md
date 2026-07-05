# Data exfiltration detection with unusual outbound traffic volume

**Ref:** M03

## Description

This scenario looks for unusual outbound traffic volume that may indicate data exfiltration. The hunt focuses on spikes in transferred bytes, especially during non-standard business hours or when associated with file types and destinations that may carry sensitive information.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Identify outbound traffic volumes that deviate from expected user, host, or service baselines.

## Method

1. **Load** - Read outbound network telemetry from `input/`.
2. **Aggregate** - Summarize transferred bytes by host, user, destination, and time window.
3. **Baseline** - Compare current traffic volumes against historical norms.
4. **Prioritize** - Highlight spikes that occur at unusual times, to unusual destinations, or around sensitive file movement.
5. **Investigate** - Validate whether the volume increase is expected business activity or possible exfiltration.

## Data Needed

- Network telemetry with source host, destination, bytes sent, timestamp, and protocol information
- Optional file, user, or application context to explain large transfers

## Data Collection - Initial Query

Query outbound network telemetry for byte counts over time and export fields that support aggregation by host, user, destination, and time window. Include enough history to compare current behavior against a recent baseline.

## Input

Place outbound traffic exports in `input/`. CSV input should preserve timestamps and byte counts so spikes can be identified reliably.

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
| `output/` | Ranked outbound-volume anomalies and supporting context for analyst review |

## How to Run

1. Export outbound network telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you attach to this folder.
3. Write prioritized findings to `output/` and review the largest unexplained outbound transfers.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
