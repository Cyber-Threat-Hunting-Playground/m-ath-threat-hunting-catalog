# Identify potential injections in User-agent string

**Ref:** M13

## Description

This scenario looks for potentially malicious or uncommon user-agent strings by clustering request attributes such as user-agent value, URL length, and the number of variables passed in the request. The goal is to isolate outlier clusters that may represent injection attempts, scanning, or tool-driven activity.

## M-ATH Sub-process

**Clustering** - Group similar requests together and surface rare or suspicious user-agent patterns as outliers.

## Method

1. **Load** - Read web or WAF telemetry from `input/`.
2. **Extract Features** - Capture user-agent text, URL length, parameter count, and related request attributes.
3. **Cluster** - Group similar requests into common behavioral clusters.
4. **Prioritize** - Highlight requests that land in rare clusters or carry suspicious user-agent patterns.
5. **Investigate** - Review the flagged clusters for injection indicators, automation, or exploit traffic.

## Data Needed

- Web server or WAF logs containing user-agent strings, URLs, and request parameters
- Optional source IP, response code, and application context for triage

## Data Collection - Initial Query

Export web request telemetry that preserves raw user-agent values, request URLs, and parameter counts or full query strings. Retain enough context to separate normal browser traffic from scanners, scripted tooling, or malformed requests.

## Input

Place web or WAF exports in `input/`. CSV files should keep user-agent, URL, and request metadata intact.

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
| `output/` | Clustered user-agent findings and rare request patterns for analyst review |

## How to Run

1. Export web or WAF telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized findings to `output/` and review the rare user-agent clusters.

For pipeline execution (GitHub Actions / Codespaces), see the main [README](../../README.md).
