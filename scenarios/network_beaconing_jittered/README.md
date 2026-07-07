# Network beaconing (jittered)

**Ref:** M24

## Description

This scenario performs model-assisted threat hunting for jittered beaconing, where command-and-control traffic uses irregular or randomized intervals to evade simple periodicity detectors. The notebook combines robust time-series features, an ensemble of anomaly models, and visualizations to help analysts triage suspicious network flows.

## M-ATH Sub-process

**Forecasting and Anomaly Detection** - Identify beacon-like timing behavior even when attackers randomize their sleep intervals.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Imports, SentinelOne CSV loading, column normalization |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | Feature engineering (ACF, spectrum, burstiness), ensemble ML (Isolation Forest + One-Class SVM + DBSCAN), anomaly heatmaps |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Results export, SPL pivots, PEAK tips |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Tune parameters, add enrichments, share with SOC/IR teams |

## Method

1. **Load** - Query or import network telemetry for candidate flows.
2. **Feature Extraction** - Compute inter-arrival statistics, burstiness, autocorrelation, and spectral indicators.
3. **Model** - Run an ensemble of Isolation Forest, One-Class SVM, and DBSCAN on PCA-transformed features.
4. **Visualize** - Render plots and heatmaps to help triage suspicious flows.
5. **Output** - Export scored findings for follow-up or downstream correlation.

## Data Needed

- Network telemetry with source IP, destination IP, destination port, and timestamps
- Direct or exported access to Splunk if using the provided notebook workflow

## Data Collection - Initial Query

Collect network telemetry over a time window long enough to reveal repeated communication intervals. If running the provided notebook directly against Splunk, review the connection settings and adapt the SPL query to your indexes, datamodels, and sourcetypes.

## Input

This scenario can be driven either by a direct Splunk query inside the notebook or by adapting the notebook to imported network telemetry stored under `input/`.

## Prerequisites

- Python 3.9+
- JupyterLab or Jupyter Notebook
- Install required packages: `splunk-sdk`, `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `seaborn`
- Network access and valid credentials for the target Splunk instance if using the direct-query notebook flow

## Output

| File | Description |
|------|-------------|
| `output/peak_beaconing_jittered_results.csv` | Per-flow features, anomaly scores, and prioritized jittered beaconing candidates |
| Notebook plots | Heatmaps and charts used for analyst triage |

## How to Run

1. Open `peak_beaconing_jittered_en.ipynb` or `peak_beaconing_jittered.ipynb`.
2. Configure the Splunk connection cell and adjust the query for your environment.
3. Run all cells to compute features, score flows, and render triage visualizations.
4. Review the exported results in `output/peak_beaconing_jittered_results.csv`.

## Tuning Notes

- `BIN_SEC = 10` controls time-series resolution
- `MAX_LAG_SEC = 1800` controls the autocorrelation horizon
- Review ensemble thresholds such as `contamination`, `nu`, `eps`, `min_samples`, and the final `score_ensemble` cutoff to fit your environment

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
