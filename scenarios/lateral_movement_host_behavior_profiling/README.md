# Lateral Movement / Host Behavior Profiling

**Ref:** M09

## Description

This scenario profiles host behavior to detect lateral movement or pivoting activity. It focuses on deviations in process, registry, and network behavior that may indicate a compromised system moving beyond its normal operating profile.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare current host behavior against recent baselines to surface deviations consistent with lateral movement.

## Method

1. **Load** - Read host telemetry from `input/`.
2. **Profile** - Build normal behavior profiles for processes, registry operations, and network connections.
3. **Detect** - Flag hosts whose recent activity deviates sharply from their baseline.
4. **Correlate** - Combine unusual process, registry, and network changes into a host-level suspicion score.
5. **Investigate** - Review the top anomalous hosts for signs of pivoting or compromise.

## Data Needed

- EDR logs covering process creation, registry activity, and network connections
- Optional identity context or asset criticality to improve prioritization

## Data Collection - Initial Query

Export endpoint telemetry with enough history to establish a meaningful normal baseline per host. Include timestamps, host identifiers, and the key process, registry, and network fields needed for correlation.

## Input

Place endpoint telemetry exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## Output

| File | Description |
|------|-------------|
| `output/` | Ranked host-behavior anomalies and lateral-movement candidates |

## How to Run

1. Export host telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized host anomalies to `output/` and review them for pivoting or compromise.

## References

- https://www.reddit.com/r/learnmachinelearning/comments/ly9vdx/need_help_with_ml_for_security_p/

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
