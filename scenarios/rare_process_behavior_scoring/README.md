# Rare Process Behavior Scoring

**Ref:** M11

## Description

This scenario learns the typical processes and command lines seen on individual endpoints and then highlights rare behavior. It is intended to surface unusual scripting engine usage, unexpected parent-child relationships, or process frequency changes that may indicate compromise.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare current process behavior with endpoint-specific baselines to identify rare executions.

## Method

1. **Load** - Read process telemetry from `input/`.
2. **Baseline** - Build endpoint-level frequency profiles for process names and command lines.
3. **Score** - Assign rarity scores to processes, command lines, and lineage patterns.
4. **Prioritize** - Surface executions that are rare for the endpoint or spike sharply in frequency.
5. **Investigate** - Review the highest-scoring processes for abuse or compromise.

## Data Needed

- Process execution telemetry with endpoint, process name, parent process, command line, and timestamp
- Optional signer or asset-role metadata to improve prioritization

## Data Collection - Initial Query

Export endpoint process creation telemetry over a window long enough to capture normal process usage per system. Preserve command-line and parent process fields so rare behavior can be interpreted correctly.

## Input

Place process execution telemetry exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## Output

| File | Description |
|------|-------------|
| `output/` | Ranked rare-process findings and endpoint-specific rarity context |

## How to Run

1. Export process telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized rare-process findings to `output/` and review them with host and lineage context.

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
