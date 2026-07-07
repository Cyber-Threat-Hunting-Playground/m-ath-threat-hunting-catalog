# Similarity Analysis via Clustering and Text-vectorization

**Ref:** M07

## Description

This scenario uses similarity analysis and clustering to group related artifacts and surface outliers. Depending on the data source, this can include text vectorization, Levenshtein-style comparisons, cosine similarity, or hash-based approaches to find items that resemble known groups or stand apart from them.

## M-ATH Sub-process

**Clustering** - Convert artifacts into comparable feature vectors and group them to reveal related patterns and outliers.

## Method

1. **Load** - Read artifact data from `input/`.
2. **Encode** - Convert text, names, or other records into numerical or comparable representations.
3. **Compare** - Compute similarity signals such as cosine distance, edit distance, or hash similarity.
4. **Cluster** - Group related items and identify sparse clusters or isolated outliers.
5. **Investigate** - Review unusual clusters for suspicious or novel activity.

## Data Needed

- Artifact data that can be encoded numerically, such as command lines, file names, URLs, or other text-heavy fields
- Optional labels or enrichment to explain suspicious clusters during review

## Data Collection - Initial Query

Export the records you want to compare into a structured format, keeping the raw values needed for vectorization or similarity calculations. Consistent field quality matters more than volume alone for this scenario.

## Input

Place structured artifact exports in `input/`.

## Prerequisites

- Install shared dependencies from `install/requirements.txt`
- No scenario-specific notebook or helper script is currently checked in for this folder

## Output

| File | Description |
|------|-------------|
| `output/` | Clustered similarity results and prioritized outliers |

## How to Run

1. Export the artifacts to compare into `input/`.
2. Use this scenario README as the hunt design for the notebook or script you implement in this folder.
3. Write the clustering and outlier results to `output/` and review the most unusual groups.

## References

- https://github.com/THORCollective/HEARTH/blob/main/Alchemy/M007.md

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
