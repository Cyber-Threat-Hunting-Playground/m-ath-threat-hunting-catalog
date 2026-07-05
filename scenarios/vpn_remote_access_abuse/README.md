# VPN/Remote access abuse

**Ref:** M22

## Description

This scenario detects abuse of VPN or remote access following credential theft or insider misuse. It uses user behavior analytics on enriched VPN and authentication telemetry to flag unusual countries or ASNs, impossible travel, abnormal access times, and suspicious post-VPN data transfer.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare VPN and remote-access behavior against user-specific baselines to identify suspicious deviations.

## Method

1. **Load** - Read VPN, authentication, and optionally NetFlow telemetry from `input/`.
2. **Baseline** - Learn each user's normal geographies, access hours, device patterns, and transfer volumes.
3. **Detect** - Flag first-time countries, unusual ASNs, impossible travel, atypical hours, and abnormal data transfer.
4. **Correlate** - Combine access anomalies with follow-on network behavior to raise higher-confidence cases.
5. **Investigate** - Review the highest-priority sessions for signs of credential theft or misuse.

## Data Needed

- VPN and remote-access logs with user identity, source IP, timestamp, and session details
- Authentication telemetry and optional NetFlow or transfer-volume data
- Optional Geo-IP enrichment for country and ASN analysis

## Data Collection - Initial Query

Export VPN and authentication telemetry together with any available transfer-volume or NetFlow context. Include enough history to learn each user's normal access geography and timing patterns before evaluating current sessions.

## Input

Place VPN, authentication, and related network telemetry exports in `input/`.

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
| `output/` | Ranked suspicious VPN or remote-access sessions and supporting anomaly context |

## How to Run

1. Export VPN and authentication telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized session anomalies to `output/` and review them with identity and network context.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
