# Threat Hunting M-ATH Catalog

**Model-Assisted Threat Hunting (M-ATH)** — algorithmically-driven Cyber Threat Hunting topics, aligned with the [Splunk PEAK Threat Hunting Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html).

This repository manages threat hunting scenarios that use machine learning and statistical methods — such as classification, clustering, anomaly detection, and time-series analysis — to surface leads that simpler methods may miss.

## M-ATH & PEAK Framework

M-ATH is one of three hunt types in the PEAK Framework (*Prepare, Execute, and Act with Knowledge*). It uses algorithms to find leads for threat hunting, enabling more advanced and experimental hunts when:

- **Simpler methods aren't accurate enough** — e.g., dictionary-based DGA domains that blend in with legitimate traffic
- **Classes of behavior (benign/malicious) can be labeled** — enabling supervised classification
- **Data is high-volume or hard to summarize** — suited to dimensionality reduction and clustering
- **Identification is confident but classification is difficult** — analyst-in-the-loop for final decisions

> **Note:** Scenarios described in `scenarios/catalog.csv` must use one of the PEAK M-ATH sub-processes listed below (described in `PEAK/Splunk PEAK Threat Hunters Cookbook.pdf`):
> - **Forecasting and Anomaly Detection** (p. 11)
> - **Clustering** (p. 14)
> - **Model-Assisted Methods** (p. 30 and 40)

> 📖 **References**
> - [Introducing the PEAK Threat Hunting Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
> - [Model-Assisted Threat Hunting (M-ATH) with the PEAK Framework](https://www.splunk.com/en_us/blog/security/peak-framework-math-model-assisted-threat-hunting.html)
> - [The Threat Hunter's Cookbook - A practitioner’s guide to threat hunting by SURGe’s security experts](https://www.splunk.com/en_us/campaigns/threat-hunters-cookbook.html) 

## Scenarios (M-ATH Topics)

Scenarios are organized in `scenarios/` with a catalog in `scenarios/catalog.csv`. Examples include:

| Category | Examples |
|----------|----------|
| **Classification** | Dictionary DGA detection, malicious Base64 payloads, LOLBins (LLM) |
| **Clustering** | Process parent-child chains, similarity analysis, user-agent injection |
| **Anomaly detection** | DNS/URL anomaly analysis, network beaconing (jittered), rare process behavior |
| **Time-series** | C2 beaconing, compromised accounts, data exfiltration |

See `scenarios/catalog.csv` for the full list of use cases, models, and data sources.

## Detection Logics (Shared scoring & enrichment rules)

`detection_logics/` contains **modular “detection logic” rules** used by scenarios to:
- **Increase a risk score** when a hit occurs
- **Add standardized reason tags** (string identifiers) explaining *why* something was scored

These rules are intended to be reusable across multiple hunts, so scenario notebooks/scripts can focus on analytics (feature extraction, clustering, anomaly detection, ranking) while delegating common “rule hits” to this shared package.

### How detection logics are applied

Detection logics are executed via the helper functions exposed by the package:

- `detection_logics.apply_dns_logics(value: str, decoded_value: str) -> (score_delta: int, reasons: list[str])`
- `detection_logics.apply_url_logics(value: str, decoded_value: str) -> (score_delta: int, reasons: list[str])`

Each logic implements a simple contract:

- `apply(value: str, decoded_value: str) -> (score_delta: int, reason_name: str | None)`
- Return `(0, None)` if there is no hit.
- Return a positive score delta and a stable reason name if the rule hits.

**Inputs**
- `value`: the original/raw DNS or URL value
- `decoded_value`: a decoded/normalized version when applicable (for example values prefixed with `punycode:` or `base64:`)

**Outputs**
- `score_delta`: how much to increase the candidate’s score
- `reasons`: a list of reason names corresponding to rules that hit (for auditability and analyst triage)

### Current detection logic modules

At commit `62e72c5b475a51addb1a843a6a0bbb0df7da86e9`, the `detection_logics/` package includes:

- `detection_logics/dns_suspicious_string.py`
  - Detects known suspicious strings in raw DNS values (punycode labels) and/or decoded values.
  - Scoring: `+1` per unique suspicious string found
  - Reason: `dns_suspicious_string`

- `detection_logics/vt_verdict_not_clean.py`
  - Detects and weights non-clean VirusTotal verdict tokens embedded in text (e.g. `vt:malicious`, `vt_verdict=suspicious`, `[vt: suspicious]`).
  - Scoring:
    - `malicious` → `+2`
    - `suspicious` (and other non-clean verdicts) → `+1`
  - Reason: `vt_verdict_not_clean`

- `detection_logics/__init__.py`
  - Registers which logic functions run for DNS vs URL contexts and exposes:
    - `apply_dns_logics()`
    - `apply_url_logics()`

> If you add a new detection logic module, ensure it exports an `apply()` function with the same signature and (if applicable) register it in `detection_logics/__init__.py` so it is included in the DNS/URL logic pipelines.

## Project Structure

```
├── .devcontainer/                 # Codespaces/devcontainer configuration
├── .github/workflows/             # GitHub Actions automation
│   └── virustotal-high-confidence.yml
├── data_grabber/
│   └── sentinelone-powerquery/
│       ├── sentinelone_query.py   # SentinelOne PowerQuery collector
│       └── config.json            # Local query configuration
├── detection_logics/              # Shared scoring and enrichment helpers (reusable rule hits)
├── install/
│   ├── install_dependencies.ps1   # Local dependency bootstrap
│   ├── install_dependencies.sh    # Linux/macOS dependency bootstrap
│   └── requirements.txt           # Shared Python dependencies
├── PEAK/                          # Reference material for the PEAK framework
├── scenarios/
│   ├── catalog.csv                # M-ATH use case catalog
│   ├── */README.md                # Scenario documentation
│   ├── */input/                   # Source telemetry or exported datasets
│   ├── */output/                  # Analysis outputs and ranked findings
│   └── */*.ipynb                  # Scenario notebooks where implemented
├── scripts/
│   ├── add_virustotal_verdicts.py
│   ├── bootstrap_scenarios.py
│   ├── fetch_sentinelone.py
│   ├── json_to_csv.py
│   ├── run_analysis.py
│   └── update_catalog_folders.py
└── ...
```

## Architecture

| Component | Purpose |
|-----------|---------|
| **GitHub Actions** | VirusTotal enrichment and automated validation checks (catalog sync, folder checks, data transform compliance) |
| **GitHub Codespaces** | Interactive development and notebook editing on GitHub servers |
| **Local execution** | Not supported; use Codespaces for development |

## Setup

### Local/Notebook dependency install

Install Python dependencies before running notebooks or helper scripts. These installers expect Python 3 to already be available on your `PATH`.

```powershell
./install/install_dependencies.ps1
```

```bash
./install/install_dependencies.sh
```

Use the PowerShell script on Windows and the shell script on Linux or macOS. Both scripts will automatically bootstrap `pip` (using `ensurepip`) if it is missing, install packages from `install/requirements.txt`, and verify that `requests` is available after installation.

If needed, make the shell script executable first:

```bash
chmod +x ./install/install_dependencies.sh
```

For VirusTotal-enabled scenarios, set `VT_API_KEY` in your environment.

### GitHub Actions

To enable VirusTotal enrichment on high-confidence findings:
1. Add the `VT_API_KEY` secret in your repository settings (**Settings** → **Secrets and variables** → **Actions**).
2. The enrichment workflow will run automatically when high-confidence findings are updated or can be triggered manually (**Actions** → **Add VirusTotal verdicts** → **Run workflow**).

### GitHub Codespaces (development)

1. Open the repo in Codespaces (Code → Codespaces → Create codespace).
2. For SentinelOne queries, create `data_grabber/sentinelone-powerquery/config.json` from `config.json.example` and add your credentials.
3. Or set env vars: `SENTINELONE_URL`, `SENTINELONE_TOKEN`, `SENTINELONE_TEAM_EMAILS` (Codespaces secrets).

Each scenario README under `scenarios/*/README.md` now includes its own GitHub Codespaces guidance. Use the scenario-local README for the exact steps for that hunt, including input placement, notebook or script execution, optional secrets such as `VT_API_KEY`, and any scenario-specific dependencies.

### Git Pre-Commit Hooks (Development Security)

To prevent accidental commits of private datasets, virtual environments, or company-related data/mentions, a Git pre-commit hook is provided in the `.githooks/` directory.

To enable the hook in your local clone, configure your Git repository to use the versioned hook directory:

```bash
git config core.hooksPath .githooks
```

On Linux or macOS, make sure the hook script is executable:

```bash
chmod +x .githooks/pre-commit
```

## Workflows

- **Add VirusTotal verdicts** – Lightweight workflow to re-enrich high-confidence findings only.