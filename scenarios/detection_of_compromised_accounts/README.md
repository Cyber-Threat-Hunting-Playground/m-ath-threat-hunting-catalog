# Detection of compromised accounts

**Ref:** M01

## Description

This scenario detects account takeover or compromised-user activity by learning each user's normal login behavior and surfacing deviations. Examples include unusual login times, unfamiliar locations, new device types, or other authentication patterns that break from the user's recent baseline.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare current authentication behavior against user-specific baselines to identify anomalous access.

## Method

1. **Load** - Read authentication and endpoint telemetry from `input/`.
2. **Baseline** - Model normal login times, locations, devices, and access patterns for each user.
3. **Detect** - Flag logins that deviate from the user's usual behavior.
4. **Correlate** - Combine identity anomalies with endpoint or lateral-movement indicators when available.
5. **Investigate** - Review the most suspicious accounts for takeover evidence.

## Data Needed

- Authentication records from AD, identity providers, or Windows event logs
- Optional EDR enrichment such as endpoint name, device type, or process activity

## Data Collection - Initial Query

Export login telemetry with user identity, timestamp, source location or IP, and device context. Include recent history so each user's normal login behavior can be compared with current events.

## Input

Place authentication telemetry exports in `input/`. CSV files should preserve user, time, and device or location context for each event.

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
| `output/` | Ranked compromised-account candidates and supporting authentication context |

## How to Run

1. Export authentication telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized account anomalies to `output/` and review them with identity and endpoint context.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
