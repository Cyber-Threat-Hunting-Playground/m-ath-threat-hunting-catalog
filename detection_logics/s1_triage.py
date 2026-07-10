"""
Detection logic: s1_triage
Queries SentinelOne Singularity Data Lake/AI SIEM for raw telemetry context (process tree lineage,
network connections, file modifications) and uses an OpenAI-compatible LLM to explain the activity
and identify potential false positives.
"""
from __future__ import annotations

import os
import json
import logging
import requests
from pathlib import Path
from openai import OpenAI

REASON_NAME = "s1_triage"
log = logging.getLogger("s1_triage")

# Resolve repository root
def find_repo_root() -> Path:
    cur = Path(__file__).resolve().parent
    while cur != cur.parent:
        if (cur / "detection_logics").exists() and (cur / "scenarios").exists():
            return cur
        cur = cur.parent
    return Path(__file__).resolve().parent.parent


def load_scenario_config(scenario_name: str) -> dict:
    """
    Loads configuration from scenarios/[scenario_name]/config/.env.
    Supports USE_GLOBAL_AI_CONFIG=true fallback to system environment variables.
    """
    config = {
        "enabled": False,
        "llm_api_key": None,
        "llm_api_base": None,
        "llm_model_name": "gpt-4-turbo",  # default fallback
        "s1_url": None,
        "s1_url_verify": True,
        "s1_token": None,
        "s1_team_emails": [],
    }

    repo_root = find_repo_root()
    env_path = repo_root / "scenarios" / scenario_name / "config" / ".env"

    if not env_path.exists():
        log.info(f"S1 Triage: Config file not found at {env_path.relative_to(repo_root)}. Feature disabled.")
        return config

    # Parse .env file
    env_vars = {}
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    # Strip spaces and optional surrounding quotes
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    env_vars[k] = v
    except Exception as e:
        log.error(f"S1 Triage: Failed to read config file {env_path}: {e}")
        return config

    # Check for global config fallback
    use_global = env_vars.get("USE_GLOBAL_AI_CONFIG", "").lower() in ("true", "yes", "1")

    # Helper to resolve key (local .env first, then env vars if global fallback enabled)
    def resolve_key(key: str) -> str | None:
        val = env_vars.get(key)
        if val:
            return val
        if use_global:
            return os.environ.get(key)
        return None

    config["llm_api_key"] = resolve_key("LLM_API_KEY")
    config["llm_api_base"] = resolve_key("LLM_API_BASE")
    config["llm_model_name"] = resolve_key("LLM_MODEL_NAME") or config["llm_model_name"]
    config["s1_url"] = resolve_key("SENTINELONE_URL")
    config["s1_token"] = resolve_key("SENTINELONE_TOKEN")
    
    verify_raw = resolve_key("SENTINELONE_VERIFY_SSL")
    if verify_raw is not None:
        config["s1_url_verify"] = verify_raw.lower() not in ("false", "no", "0")

    # Load S1 Team Emails
    emails_raw = resolve_key("SENTINELONE_TEAM_EMAILS")
    if emails_raw:
        try:
            config["s1_team_emails"] = json.loads(emails_raw)
        except json.JSONDecodeError:
            config["s1_team_emails"] = [e.strip() for e in emails_raw.split(",") if e.strip()]

    # Validate that we have all required elements
    required_s1 = config["s1_url"] and config["s1_token"]
    required_llm = config["llm_api_key"] and config["llm_api_base"]

    if required_s1 and required_llm:
        config["enabled"] = True
        log.info(f"S1 Triage: Successfully enabled for scenario '{scenario_name}'.")
    else:
        missing = []
        if not required_s1:
            missing.append("SentinelOne credentials (SENTINELONE_URL, SENTINELONE_TOKEN)")
        if not required_llm:
            missing.append("LLM credentials (LLM_API_KEY, LLM_API_BASE)")
        log.warning(f"S1 Triage: Disabled for scenario '{scenario_name}'. Missing: {', '.join(missing)}")

    return config


class SentinelOneQueryClient:
    """Simple HTTP client to run queries on SentinelOne Singularity Data Lake."""
    def __init__(self, base_url: str, token: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        self.verify_ssl = verify_ssl

    def run_power_query(self, query: str, start_time: str = "24h", stop_time: str = "1min") -> list[dict]:
        """Runs a PowerQuery on S1 and returns events list."""
        url = f"{self.base_url}/powerQuery"
        payload = {
            "query": query,
            "endTime": stop_time,
            "startTime": start_time,
            "priority": "low"
        }
        try:
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=120
            )
            response.raise_for_status()
            res_data = response.json()
            columns = [col["name"] for col in res_data.get("columns", [])]
            values = res_data.get("values", [])
            events = [dict(zip(columns, row)) for row in values]
            return events
        except Exception as e:
            log.error(f"S1 Triage: SentinelOne PowerQuery request failed: {e}")
            return []


def fetch_process_context_tree(
    client: SentinelOneQueryClient,
    agent_uuid: str,
    process_unique_id: str | None = None,
    parent_unique_id: str | None = None,
    process_name: str | None = None,
    process_pid: int | None = None,
    time_window: str = "2h"
) -> list[dict]:
    """
    Fetch raw telemetry context (process tree, siblings, child processes, file, and network connections)
    associated with a specific process tree.
    """
    # Build filter conditions based on what identifiers we have
    filters = []
    if process_unique_id:
        filters.append(f"src.process.uniqueId = \"{process_unique_id}\"")
        filters.append(f"src.process.parent.uniqueId = \"{process_unique_id}\"")
        filters.append(f"tgt.process.uniqueId = \"{process_unique_id}\"")
    if parent_unique_id:
        filters.append(f"src.process.uniqueId = \"{parent_unique_id}\"")
        filters.append(f"src.process.parent.uniqueId = \"{parent_unique_id}\"")
    if process_name and process_pid:
        filters.append(f"(src.process.name = \"{process_name}\" and src.process.pid = {process_pid})")
        filters.append(f"(src.process.parent.name = \"{process_name}\" and src.process.parent.pid = {process_pid})")

    if not filters:
        log.warning("S1 Triage: No process identifiers provided. Skipping context fetch.")
        return []

    filter_str = " or ".join(filters)
    query = f"""
    agent.uuid = "{agent_uuid}"
    | filter {filter_str}
    | columns event.time, event.type, src.process.name, src.process.cmdline, src.process.uniqueId, src.process.parent.name, src.process.parent.uniqueId, tgt.process.name, tgt.process.cmdline, event.dns.request, connection.ip, connection.port, file.path
    | limit 200
    """
    log.debug(f"S1 Triage: Querying process context tree with query: {query}")
    return client.run_power_query(query, start_time=time_window)


def explain_activity(
    config: dict,
    candidate_event: dict,
    context_events: list[dict]
) -> dict:
    """
    Send candidate details and S1 telemetry context to the OpenAI-compatible LLM
    to generate an explanation and detect potential false positives.
    """
    # Ensure client settings are retrieved
    api_key = config["llm_api_key"]
    api_base = config["llm_api_base"]
    model_name = config["llm_model_name"]

    client = OpenAI(api_key=api_key, base_url=api_base)

    # Format inputs for LLM
    context_formatted = json.dumps(context_events, indent=2)
    candidate_formatted = json.dumps(candidate_event, indent=2)

    system_prompt = (
        "You are an expert Security Operations Center (SOC) analyst and Threat Hunter.\n"
        "Your task is to analyze a candidate alert/finding (M-ATH lead) alongside its surrounding "
        "SentinelOne telemetry context (process tree, siblings, children, file activity, and network connections).\n"
        "Determine if the candidate event is a False Positive (FP) or a True Positive (TP).\n"
        "False Positives typically include standard system updater activity, legitimate administrative tasks, "
        "known commercial software behavior running in standard locations, developer compilation scripts, or safe "
        "user-initiated operations.\n\n"
        "You must explain your reasoning clearly and provide a final verdict in JSON format.\n"
        "Output ONLY a raw JSON object matching this schema. Do not add markdown backticks, explanations outside "
        "the JSON, or formatting other than a standard JSON string:\n"
        "{\n"
        "  \"is_false_positive\": true/false,\n"
        "  \"fp_confidence\": 0-100,\n"
        "  \"explanation\": \"A concise, high-quality description explaining why this is or is not a false positive based on the process lineage and context.\"\n"
        "}"
    )

    user_prompt = (
        f"Candidate Finding:\n{candidate_formatted}\n\n"
        f"SentinelOne Process Context & Lineage:\n{context_formatted}\n"
    )

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1
        )
        content = response.choices[0].message.content.strip()
        
        # Clean potential markdown block wrappers if LLM still outputs them
        if content.startswith("```"):
            lines = content.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines[-1].startswith("```"):
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        result = json.loads(content)
        # Type and boundary checking
        result["is_false_positive"] = bool(result.get("is_false_positive", False))
        result["fp_confidence"] = max(0, min(100, int(result.get("fp_confidence", 0))))
        result["explanation"] = str(result.get("explanation", "Failed to parse explanation."))
        return result
    except Exception as e:
        log.error(f"S1 Triage: LLM explain request or parsing failed: {e}")
        return {
            "is_false_positive": False,
            "fp_confidence": 0,
            "explanation": f"Failed to triage lead due to error: {e}"
        }


def apply_s1_triage(
    leads: list[dict],
    scenario_name: str,
    score_column: str = "risk_score",
    threshold: int = 5,
    top_n: int = 15,
    time_window: str = "2h"
) -> list[dict]:
    """
    Enriches candidate leads using S1 PowerQuery and OpenAI-compatible LLM.
    Filters to top_n leads exceeding score threshold, queries context, runs LLM,
    updates risk score (reducing it if high FP confidence), and appends explanation tags.
    """
    config = load_scenario_config(scenario_name)
    if not config["enabled"]:
        # Triage is disabled or config file is missing; return list unmodified
        return leads

    # Filter candidates to run triage on
    candidates_to_triage = [
        (idx, lead) for idx, lead in enumerate(leads)
        if lead.get(score_column, 0) >= threshold
    ]

    # Sort by risk score descending, take top_n
    candidates_to_triage = sorted(
        candidates_to_triage,
        key=lambda x: x[1].get(score_column, 0),
        reverse=True
    )[:top_n]

    if not candidates_to_triage:
        log.info("S1 Triage: No candidate leads exceeded the score threshold for triage.")
        return leads

    client = SentinelOneQueryClient(
        base_url=config["s1_url"],
        token=config["s1_token"],
        verify_ssl=config["s1_url_verify"]
    )

    log.info(f"S1 Triage: Starting automated triage for {len(candidates_to_triage)} leads.")

    for idx, lead in candidates_to_triage:
        # Extract process and endpoint details
        agent_uuid = lead.get("agent.uuid") or lead.get("agent_uuid")
        if not agent_uuid:
            # Try to resolve from endpoint.name if agent.uuid is not present (requires S1 mapping)
            # For simplicity, we skip if agent identifier is totally missing
            log.warning(f"S1 Triage: Missing agent uuid for lead index {idx}. Skipping.")
            continue

        # Extract process identification details
        proc_uid = lead.get("src.process.uniqueId") or lead.get("process.uniqueId") or lead.get("uniqueId")
        parent_uid = lead.get("src.process.parent.uniqueId") or lead.get("process.parent.uniqueId")
        proc_name = lead.get("src.process.name") or lead.get("process.name") or lead.get("process_name")
        proc_pid = lead.get("src.process.pid") or lead.get("process.pid") or lead.get("process_pid")

        # Query surrounding context tree
        context = fetch_process_context_tree(
            client=client,
            agent_uuid=agent_uuid,
            process_unique_id=proc_uid,
            parent_unique_id=parent_uid,
            process_name=proc_name,
            process_pid=int(proc_pid) if proc_pid is not None else None,
            time_window=time_window
        )

        # Call LLM to triage
        triage_verdict = explain_activity(config, lead, context)

        # Apply score adjustment and details to the lead
        fp_confidence = triage_verdict.get("fp_confidence", 0)
        is_fp = triage_verdict.get("is_false_positive", False)
        explanation = triage_verdict.get("explanation", "")

        lead["s1_triage_explanation"] = explanation
        lead["s1_triage_fp_confidence"] = fp_confidence
        lead["s1_triage_verdict"] = "false_positive" if is_fp else "suspicious_true_positive"

        # Adjust score: reduce score if false positive confidence is high
        if is_fp and fp_confidence > 50:
            # Deduct score proportional to confidence
            score_reduction = int((fp_confidence / 100) * lead.get(score_column, 0))
            # Keep at least a score of 1 if originally non-zero, or reduce completely
            new_score = max(0, lead.get(score_column, 0) - score_reduction)
            lead[score_column] = new_score
            log.info(
                f"S1 Triage: Lead index {idx} triaged as FP (confidence: {fp_confidence}%). "
                f"Risk score reduced to {new_score}. Reason: {explanation[:60]}..."
            )
        else:
            log.info(
                f"S1 Triage: Lead index {idx} triaged as TP/Suspicious. "
                f"Risk score remains {lead.get(score_column)}. Reason: {explanation[:60]}..."
            )

    return leads
