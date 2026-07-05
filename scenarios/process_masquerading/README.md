# Process masquerading

**Ref:** M14

## Description

This scenario hunts for processes that borrow the names of legitimate binaries while behaving in suspicious ways. It focuses on binaries that execute from unusual paths, lack valid signatures, spawn from atypical parent processes, or use anomalous command-line arguments.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare process identity and execution context against normal software behavior to find masquerading candidates.

## Method

1. **Load** - Read endpoint process telemetry from `input/`.
2. **Normalize** - Extract process name, path, signature, parent process, and command-line fields.
3. **Compare** - Evaluate whether the binary name matches expected path and signer patterns.
4. **Prioritize** - Flag binaries that look legitimate by name but diverge in path, lineage, or arguments.
5. **Investigate** - Review the top findings with host, user, and signer context.

## Data Needed

- EDR logs and Windows event data with process name, image path, parent process, signer, and command-line information
- Optional hash or reputation enrichment for prioritization

## Data Collection - Initial Query

Export process creation telemetry with full image path, parent process, and signer metadata where possible. Masquerading analysis is far more reliable when the export preserves both binary identity and execution context.

## Input

Place process telemetry exports in `input/`.

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
| `output/` | Ranked process-masquerading candidates and supporting execution context |

## How to Run

1. Export process execution telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized findings to `output/` and review them with signer, path, and lineage context.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
