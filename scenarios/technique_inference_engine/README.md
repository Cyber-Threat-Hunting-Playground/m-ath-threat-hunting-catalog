# Technique Inference Engine

**Ref:** M16

## Description

This scenario helps analysts infer tactics, techniques, and procedures that may co-occur in a campaign. It uses recommender-style methods on CTI reports labeled with ATT&CK techniques to predict additional techniques that may be relevant even when they are under-reported in the source material.

## M-ATH Sub-process

**Model-Assisted Methods** - Use implicit-feedback recommendation methods to infer likely related techniques from partially observed campaign behavior.

## Method

1. **Load** - Read CTI-derived technique observations from `input/`.
2. **Represent** - Model campaigns or reports as partially observed technique sets.
3. **Infer** - Apply recommendation logic to predict related or missing techniques.
4. **Visualize** - Use embeddings or dimensionality reduction such as t-SNE for analyst exploration.
5. **Investigate** - Review the inferred techniques as leads for additional hunting.

## Data Needed

- CTI reports or structured campaign observations labeled with ATT&CK techniques
- Optional campaign metadata to support analyst interpretation

## Data Collection - Initial Query

Prepare a structured dataset of campaigns or reports and the techniques already observed in each one. The model is most useful when the input captures partial but credible technique observations rather than exhaustive labels.

## Input

Place structured CTI or ATT&CK-labeled data in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## Output

| File | Description |
|------|-------------|
| `output/` | Inferred related techniques and any supporting visualizations or ranking artifacts |

## How to Run

1. Prepare ATT&CK-labeled campaign or CTI data in `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write inferred-technique outputs to `output/` and review them as leads for further hunting.

## References

- https://arxiv.org/pdf/2503.04819

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
