# Dictionary DGA detection via Supervised Classification

**Ref:** M06

## Description

This scenario detects dictionary-based DGA domains using a supervised LSTM classifier. It is adapted from the Splunk PEAK `dictionary_dga_classifier` workflow and is intended to prioritize domains that look algorithmically generated even when they resemble natural language.

## M-ATH Sub-process

**Model-Assisted Methods** - Apply a trained classifier to distinguish likely DGA domains from benign domains.

## PEAK Framework Alignment

This scenario follows the **PEAK Threat Hunting Framework** ([Splunk](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)) using **Model-Assisted Threat Hunting (M-ATH)**.

| Phase | Focus | Notebook sections |
|-------|-------|-------------------|
| **Prepare** | Select topic, research, identify datasets, select algorithms | Environment setup, imports, model/tokenizer loading |
| **Execute** | Gather data, pre-process, apply model, analyze, escalate | Domain loading, TLD stripping, LSTM prediction, flagging |
| **Act** | Document findings, preserve hunt, create detections/playbooks | Results export, DNS blocklist candidates |
| **Knowledge** | Continuous improvement, communicate findings, feed back into next run | Retrain model with new labels, tune threshold, share with DNS/firewall teams |

## Method

1. **Load** - Read DNS telemetry from `input/`.
2. **Normalize** - Extract the domain field from `domain` or `event.dns.request` columns.
3. **Classify** - Use the pretrained LSTM model and tokenizer assets from `models/`.
4. **Score** - Generate domain predictions and rounded prediction values for review.
5. **Output** - Write results to `output/dictionary_dga_results.csv`.

## Data Needed

- DNS logs with a domain column such as `domain` or `event.dns.request`
- Optional supporting context for analyst follow-up, such as source host or query volume

## Data Collection - Initial Query

Export DNS telemetry containing queried domain values and preserve enough context to investigate suspicious domains after classification. The classifier operates on domain values, so clean domain extraction is more important than broad enrichment.

## Input

Place domain CSV files in `input/`. Each CSV must contain a `domain` column or `event.dns.request`. A sample `validation_sample.csv` is included.

## Prerequisites

- Install scenario-specific dependencies with `pip install -r requirements-dga.txt`
- Ensure the following model assets are present in `models/`:
  - `m-ath_dict_dga_model/`
  - `m-ath_pretrain_tokenizer.pkl`
  - `m-ath_pretrain_word_list.pkl`
- If any assets are missing, retrieve them from the upstream Splunk PEAK project

## Output

| File | Description |
|------|-------------|
| `output/dictionary_dga_results.csv` | Classified domains with `orig_domain`, `prediction`, and `rounded_prediction` |

## How to Run

1. Add DNS input data to `input/`.
2. Open `dictionary_dga.ipynb` and run all cells.
3. Review the classifier output in `output/dictionary_dga_results.csv`.

## References

- https://github.com/THORCollective/HEARTH/blob/main/Alchemy/M006.md
- https://github.com/splunk/PEAK/tree/main/dictionary_dga_classifier

For pipeline execution (GitHub Actions), see the main [README](../../README.md).
