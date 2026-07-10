import pytest
import json
from unittest.mock import MagicMock, patch, mock_open
from detection_logics.s1_triage import (
    load_scenario_config,
    SentinelOneQueryClient,
    fetch_process_context_tree,
    explain_activity,
    apply_s1_triage
)

@patch("detection_logics.s1_triage.Path.exists")
def test_load_scenario_config_no_file(mock_exists):
    mock_exists.return_value = False
    config = load_scenario_config("non_existent_scenario")
    assert config["enabled"] is False


@patch("detection_logics.s1_triage.Path.exists")
@patch("builtins.open", new_callable=mock_open, read_data="USE_GLOBAL_AI_CONFIG=false\nLLM_API_KEY=local_key\nLLM_API_BASE=local_base\nLLM_MODEL_NAME=local_model\nSENTINELONE_URL=https://s1.example.com\nSENTINELONE_TOKEN=local_token\nSENTINELONE_VERIFY_SSL=false\n")
def test_load_scenario_config_local_only(mock_file, mock_exists):
    mock_exists.return_value = True
    config = load_scenario_config("test_scenario")
    assert config["enabled"] is True
    assert config["llm_api_key"] == "local_key"
    assert config["llm_api_base"] == "local_base"
    assert config["llm_model_name"] == "local_model"
    assert config["s1_url"] == "https://s1.example.com"
    assert config["s1_token"] == "local_token"
    assert config["s1_url_verify"] is False


@patch.dict("os.environ", {
    "LLM_API_KEY": "global_key",
    "LLM_API_BASE": "global_base",
    "SENTINELONE_URL": "https://global.s1.example.com",
    "SENTINELONE_TOKEN": "global_token"
})
@patch("detection_logics.s1_triage.Path.exists")
@patch("builtins.open", new_callable=mock_open, read_data="USE_GLOBAL_AI_CONFIG=true\n")
def test_load_scenario_config_global_fallback(mock_file, mock_exists):
    mock_exists.return_value = True
    config = load_scenario_config("test_scenario")
    assert config["enabled"] is True
    assert config["llm_api_key"] == "global_key"
    assert config["llm_api_base"] == "global_base"
    assert config["s1_url"] == "https://global.s1.example.com"
    assert config["s1_token"] == "global_token"


@patch("requests.post")
def test_s1_client_query_success(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "columns": [{"name": "src.process.name"}, {"name": "event.type"}],
        "values": [["cmd.exe", "Process Creation"], ["powershell.exe", "Process Creation"]]
    }
    mock_post.return_value = mock_response

    client = SentinelOneQueryClient("https://s1.example.com", "my_token", verify_ssl=False)
    events = client.run_power_query("event.type = *")
    
    assert len(events) == 2
    assert events[0]["src.process.name"] == "cmd.exe"
    assert events[0]["event.type"] == "Process Creation"
    assert events[1]["src.process.name"] == "powershell.exe"


@patch.object(SentinelOneQueryClient, "run_power_query")
def test_fetch_process_context_tree(mock_run_pq):
    client = SentinelOneQueryClient("https://s1.example.com", "token")
    fetch_process_context_tree(
        client,
        agent_uuid="agent123",
        process_unique_id="proc555",
        time_window="1h"
    )
    # Ensure run_power_query was called
    assert mock_run_pq.called
    query_arg = mock_run_pq.call_args[0][0]
    assert "agent.uuid = \"agent123\"" in query_arg
    assert "src.process.uniqueId = \"proc555\"" in query_arg


@patch("detection_logics.s1_triage.OpenAI")
def test_explain_activity_fp(mock_openai_class):
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({
        "is_false_positive": True,
        "fp_confidence": 90,
        "explanation": "Legitimate Windows Update"
    })
    mock_client.chat.completions.create.return_value.choices = [mock_choice]
    mock_openai_class.return_value = mock_client

    config = {
        "llm_api_key": "key",
        "llm_api_base": "base",
        "llm_model_name": "model"
    }

    result = explain_activity(config, {"process": "cmd.exe"}, [])
    assert result["is_false_positive"] is True
    assert result["fp_confidence"] == 90
    assert result["explanation"] == "Legitimate Windows Update"


@patch("detection_logics.s1_triage.load_scenario_config")
@patch("detection_logics.s1_triage.fetch_process_context_tree")
@patch("detection_logics.s1_triage.explain_activity")
@patch("detection_logics.s1_triage.requests.post")
def test_apply_s1_triage_enabled(mock_post, mock_explain, mock_fetch, mock_load_config):
    # Enable config
    mock_load_config.return_value = {
        "enabled": True,
        "s1_url": "https://s1.example.com",
        "s1_token": "token",
        "s1_url_verify": False,
        "llm_api_key": "key",
        "llm_api_base": "base",
        "llm_model_name": "model"
    }

    # Mock context fetch to return some events
    mock_fetch.return_value = [{"event.type": "Process Creation"}]

    # Mock explain_activity to return false positive verdict
    mock_explain.return_value = {
        "is_false_positive": True,
        "fp_confidence": 80,
        "explanation": "Known benign updater script"
    }

    leads = [
        {"risk_score": 10, "agent.uuid": "agent-uuid-abc", "src.process.uniqueId": "proc-123"},
        {"risk_score": 2, "agent.uuid": "agent-uuid-def", "src.process.uniqueId": "proc-456"}  # below threshold (5)
    ]

    triaged_leads = apply_s1_triage(leads, "scenario_abc", threshold=5, score_column="risk_score")

    # Lead 1 (score 10 >= 5) should be triaged and score reduced
    assert triaged_leads[0]["s1_triage_verdict"] == "false_positive"
    assert triaged_leads[0]["s1_triage_fp_confidence"] == 80
    assert triaged_leads[0]["s1_triage_explanation"] == "Known benign updater script"
    # Reduction is 80% of 10 = 8. New score = 10 - 8 = 2
    assert triaged_leads[0]["risk_score"] == 2

    # Lead 2 (score 2 < 5) should NOT be triaged
    assert "s1_triage_verdict" not in triaged_leads[1]
    assert triaged_leads[1]["risk_score"] == 2
