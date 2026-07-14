# Custom Agentic Skills

This project leverages agentic custom skills to automate common workflows, check framework compliance, and enforce codebase standards. These skills are loaded by agentic assistants to guide development.

The active skills are defined in the [.agents/skills/](../.agents/skills/) directory.

---

## 🛠️ Available Project Skills

### 1. [create-m-ath-scenario](../.agents/skills/create-m-ath-scenario/SKILL.md)
*   **Purpose**: Bootstraps new Model-Assisted Threat Hunting (M-ATH) scenarios.
*   **Usage**: Triggered when initiating a new hunt scenario folder. It ensures the scenario follows the standard template (`input/`, `output/`, `models/`, local `README.md`) and updates [catalog.csv](../scenarios/catalog.csv).

### 2. [verify-m-ath-scenario](../.agents/skills/verify-m-ath-scenario/SKILL.md)
*   **Purpose**: Runs automated checks and validation on Jupyter notebooks.
*   **Usage**: Triggers headlessly executing notebooks with `jupyter nbconvert --execute` to verify there are no runtime exceptions, and checks output schema against local requirements.

### 3. [peak-compliance-check](../.agents/skills/peak-compliance-check/SKILL.md)
*   **Purpose**: Checks scenarios for alignment with the Splunk PEAK Threat Hunting Framework phases.
*   **Usage**: Audits the scenario's structure to make sure it explicitly plans the **Prepare**, **Execute**, **Act**, and **Knowledge** phases (including feedback loops and model retraining steps).

### 4. [shared-logic-integrator](../.agents/skills/shared-logic-integrator/SKILL.md)
*   **Purpose**: Integrates reusable scoring and enrichment rules from the `detection_logics` package.
*   **Usage**: Promotes importing modular logic (e.g. VirusTotal reputation, Punycode analysis, or SentinelOne triage) instead of hardcoding API integrations directly inside individual notebooks.

---

## 💡 How to Use Custom Skills with AI Assistants

When pair-programming with Agentic, the skills are loaded automatically. You can explicitly direct the assistant to execute them by typing commands or refering to them by name:
*   *"Use the `create-m-ath-scenario` skill to bootstrap a scenario for process injection."*
*   *"Run `verify-m-ath-scenario` on the dictionary DGA notebook."*
*   *"Perform a `peak-compliance-check` on our new scenario."*
*   *"Audit my notebook to verify we are using the `shared-logic-integrator` standards."*
