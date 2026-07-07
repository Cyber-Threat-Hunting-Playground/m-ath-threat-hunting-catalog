# Network Traffic Anomaly Detection

**Ref:** M10

## Description

This scenario uses unsupervised methods such as clustering or isolation forests to flag unusual network flows, port usage, and traffic spikes that may indicate stealthy communication. The goal is to surface suspicious network behavior that is difficult to detect with fixed rules alone.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Compare network behavior against recent traffic norms to identify outlier flows.

## Method

1. **Load** - Read network telemetry from `input/`.
2. **Extract Features** - Capture flow size, duration, port usage, protocol, and timing characteristics.
3. **Model** - Apply unsupervised techniques such as clustering or Isolation Forest.
4. **Prioritize** - Rank flows that sit far from common traffic patterns.
5. **Investigate** - Review the outliers with host, service, and destination context.

## Data Needed

- Network flow or connection telemetry with ports, protocols, byte counts, and timestamps
- Optional host or process enrichment for analyst validation

## Data Collection - Initial Query

Export network telemetry over a representative time window and preserve the fields needed for flow-level feature engineering. Include both ordinary service traffic and candidate suspicious traffic so anomaly methods can establish useful contrast.

## Input

Place network flow exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## Output

| File | Description |
|------|-------------|
| `output/` | Ranked network anomalies and supporting flow context |

## How to Run

1. Export network telemetry into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write prioritized flow anomalies to `output/` and review them with host and service context.

## References

- https://en.wikipedia.org/wiki/Network_behavior_anomaly_detection

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
