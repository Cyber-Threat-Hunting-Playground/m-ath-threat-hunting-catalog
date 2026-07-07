#!/usr/bin/env python3
"""
Scan a scenario proposal issue. If 'Other Data Sources' was used,
create a tracking issue for the custom telemetry request if it doesn't already exist.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Add current folder to path to import generate_scenario_from_issue helper
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.append(str(SCRIPTS_DIR))

from generate_scenario_from_issue import parse_issue_body, clean_value, get_github_issue

LABEL = "new-telemetry-request"


def api_request(method: str, url: str, token: str, data: dict | None = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    req = urllib.request.Request(url, method=method, headers=headers)
    if data:
        req.data = json.dumps(data).encode("utf-8")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ensure_label_exists(repo: str, token: str) -> None:
    """Create the new-telemetry-request label if it does not exist."""
    url = f"https://api.github.com/repos/{repo}/labels"
    try:
        api_request(
            "POST",
            url,
            token,
            {
                "name": LABEL,
                "color": "5319e7",
                "description": "Request for supporting a new telemetry/data source",
            },
        )
        print(f"Created label: {LABEL}")
    except urllib.error.HTTPError as e:
        if e.code != 422:  # 422 = validation failed (label already exists)
            raise SystemExit(f"API error {e.code}: {e.read().decode()}")


def check_existing_issue(repo: str, token: str, title: str) -> bool:
    """Check if an issue with the specified title and label already exists (open or closed)."""
    # URL escape the query parameters
    q = f'repo:{repo} label:"{LABEL}" "{title}"'
    url = f"https://api.github.com/search/issues?q={urllib.parse.quote(q)}"
    try:
        result = api_request("GET", url, token)
        return result.get("total_count", 0) > 0
    except Exception as e:
        print(f"Warning: Failed to search existing issues: {e}. Falling back to listing issues.", file=sys.stderr)
        
    # Fallback: list issues with this label
    url = f"https://api.github.com/repos/{repo}/issues?state=all&labels={LABEL}"
    try:
        issues = api_request("GET", url, token)
        for issue in issues:
            if issue.get("title") == title:
                return True
    except Exception as ex:
        print(f"Error checking existing issues: {ex}", file=sys.stderr)
    return False


def create_tracking_issue(repo: str, token: str, title: str, proposal_issue_num: str, other_data: str) -> None:
    """Create the tracking issue on GitHub."""
    ensure_label_exists(repo, token)
    
    url = f"https://api.github.com/repos/{repo}/issues"
    body = (
        f"A new scenario proposal (issue #{proposal_issue_num}) has requested a custom telemetry source:\n\n"
        f"**{other_data}**\n\n"
        f"Please review if this telemetry source should be added to the standard choices, "
        f"or if a data parser/enrichment logic is required."
    )
    
    data = {
        "title": title,
        "body": body,
        "labels": [LABEL]
    }
    
    api_request("POST", url, token, data)
    print(f"Successfully created tracking issue: '{title}'")


def process_proposal_issue(repo: str, token: str, issue_number: str) -> None:
    _, body, _ = get_github_issue(repo, issue_number, token)
    
    sections = parse_issue_body(body)
    other_data = clean_value(sections.get("Other Data Sources", ""))
    
    if not other_data:
        print("No 'Other Data Sources' specified. No action needed.")
        return
        
    title = f"[Telemetry Request] Support for '{other_data}' (Proposed in #{issue_number})"
    
    if check_existing_issue(repo, token, title):
        print(f"Tracking issue already exists: '{title}'. Skipping creation.")
        return
        
    create_tracking_issue(repo, token, title, issue_number, other_data)


def main() -> int:
    # Use environment variables matching our GitHub actions workflow setup
    issue_number = os.environ.get("ISSUE_NUMBER")
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    
    if not issue_number:
        print("Error: ISSUE_NUMBER environment variable is required.", file=sys.stderr)
        return 1
    if not repo:
        print("Error: GITHUB_REPOSITORY environment variable is required.", file=sys.stderr)
        return 1
    if not token:
        print("Error: GH_TOKEN or GITHUB_TOKEN environment variable is required.", file=sys.stderr)
        return 1
        
    process_proposal_issue(repo, token, issue_number)
    return 0


if __name__ == "__main__":
    sys.exit(main())
