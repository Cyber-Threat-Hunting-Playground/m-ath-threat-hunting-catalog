# Persistence Discovery: Suspicious Auto-Run Files

**Ref:** M19

## Description

This scenario hunts for suspicious Windows persistence by focusing on Registry and file-system locations that automatically launch programs. The objective is to find auto-run entries and startup artifacts that deviate from expected software behavior or point to malicious persistence.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare observed auto-run artifacts against common persistence baselines to identify unusual entries.

## Method

1. **Load** - Read Registry and file-system telemetry from `input/`.
2. **Enumerate** - Identify entries from known auto-run locations and startup paths.
3. **Profile** - Compare the observed artifacts against expected software and host behavior.
4. **Prioritize** - Highlight unsigned, low-prevalence, or path-anomalous entries.
5. **Investigate** - Validate the persistence items with signer, path, host, and user context.

## Data Needed

- EDR, Windows event, or SIEM telemetry that captures Registry run keys, startup folders, and related file activity
- Optional signer, hash, or reputation data for prioritization

## Data Collection - Initial Query

Export telemetry that covers Windows auto-run locations, startup folders, and related process or file metadata. Preserve path details so suspicious execution locations can be reviewed accurately.

## Input

Place Registry or auto-run telemetry exports in `input/`.

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
| `output/` | Suspicious auto-run artifacts and supporting persistence context |

## How to Run

1. Export Registry and startup telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized persistence findings to `output/` and review them with host and signer context.

## References

- https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/registryautoruns
- https://www.cyberark.com/resources/threat-research-blog/persistence-techniques-that-persist

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
