# Database query anomalies

**Ref:** M04

## Description

This scenario detects abnormal database activity that may indicate unauthorized data manipulation or exfiltration. The focus is on unusual concentrations of INSERT, UPDATE, DELETE, or other high-impact queries executed in short time windows, especially against sensitive datasets.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare query behavior against normal workload patterns to find unusual spikes or operator activity.

## Method

1. **Load** - Read database audit or query telemetry from `input/`.
2. **Normalize** - Classify statements by user, database, action type, and time window.
3. **Baseline** - Measure normal query rates and action mixes for users and systems.
4. **Detect** - Flag bursts of high-risk query activity or access that deviates from expected patterns.
5. **Investigate** - Review the affected tables, user identity, source host, and time of execution.

## Data Needed

- Database logs with query type, user or service account, target database or table, and timestamp
- Optional source host, application name, or row-count metadata for triage

## Data Collection - Initial Query

Export database audit records that include statement type and execution context. Focus on privileged or high-volume modification operations and retain enough history to establish normal behavior per user or system.

## Input

Place database telemetry exports in `input/`. Prefer CSV files that include timestamps, actor identity, query type, and target object details.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## Output

| File | Description |
|------|-------------|
| `output/` | Ranked database query anomalies and supporting context for review |

## How to Run

1. Export database query telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized anomalies to `output/` and review them with database ownership context.

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
