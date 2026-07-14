#!/usr/bin/env python3
"""
Create or update GitHub Issues for each threat hunting scenario that fails
the automated Splunk PEAK M-ATH compliance auditing in CI/CD.
Skips creating an issue if an open one with the same title and label already exists.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS_JSON = os.path.join(REPO_ROOT, "peak_compliance_results.json")
LABEL = "peak-non-compliance"


def get_headers() -> dict:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Warning: GH_TOKEN or GITHUB_TOKEN environment variable not set. Skipping GitHub Issue creation.")
        sys.exit(0)
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def api_request(method: str, url: str, data: dict | None = None) -> dict:
    req = urllib.request.Request(url, method=method, headers=get_headers())
    if data:
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"API request failed ({method} {url}): {e.code} - {e.read().decode()}", file=sys.stderr)
        raise


def search_existing_issue(owner: str, repo: str, title: str) -> bool:
    """Return True if an open issue with this title and label exists."""
    q = f'repo:{owner}/{repo} is:open label:"{LABEL}" "{title}"'
    url = f"https://api.github.com/search/issues?q={urllib.parse.quote(q)}"
    try:
        result = api_request("GET", url)
        return result.get("total_count", 0) > 0
    except Exception as e:
        print(f"Failed to search for existing issue: {e}", file=sys.stderr)
        return False


def ensure_label_exists(owner: str, repo: str) -> None:
    """Create the label if it does not exist."""
    url = f"https://api.github.com/repos/{owner}/{repo}/labels"
    try:
        api_request(
            "POST",
            url,
            {
                "name": LABEL,
                "color": "e11d48", # Rose/red color
                "description": "Scenarios failing Splunk PEAK M-ATH compliance audits",
            },
        )
        print(f"Created label: {LABEL}")
    except urllib.error.HTTPError as e:
        if e.code != 422: # 422 Unprocessable Entity means label already exists
            print(f"Warning: Failed to ensure label exists: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Failed to ensure label exists: {e}", file=sys.stderr)


def create_issue(owner: str, repo: str, title: str, folder_name: str, ref: str, failures: list, warnings: list) -> None:
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    
    body_lines = [
        f"The threat hunting scenario `{folder_name}` ({ref or 'unregistered'}) does not fully align with the **Splunk PEAK M-ATH Framework** standards.\n",
        "Please fix the compliance failures listed below to resolve this issue.\n",
    ]
    
    if failures:
        body_lines.append("### ❌ Critical Non-Compliance Failures")
        body_lines.append("These issues must be resolved before this scenario is considered compliant:\n")
        for f in failures:
            body_lines.append(f"- [ ] {f}")
        body_lines.append("")
        
    if warnings:
        body_lines.append("### ⚠️ Performance & Decoupling Recommendations")
        body_lines.append("These issues are best-practice warnings and do not block the build, but should be resolved:\n")
        for w in warnings:
            body_lines.append(f"- [ ] {w}")
        body_lines.append("")
        
    body_lines.extend([
        "### How to Fix Locally",
        "1. Pull the latest changes.",
        "2. Run the auditor locally on your scenario: `python scripts/audit_peak_compliance.py --scenario " + folder_name + "`",
        "3. Read the generated report in `scenarios/" + folder_name + "/.peak_compliance_report.md` for specific instructions.",
        "4. Fix the errors, verify they pass locally, and push the fixes."
    ])

    body = "\n".join(body_lines)
    data = {"title": title, "body": body, "labels": [LABEL]}
    try:
        api_request("POST", url, data)
        print(f"Created issue: {title}")
    except Exception as e:
        print(f"Failed to create issue for {folder_name}: {e}", file=sys.stderr)


def main() -> None:
    if not os.path.exists(RESULTS_JSON):
        print(f"No compliance results file found at {RESULTS_JSON}. Nothing to do.")
        return

    try:
        with open(RESULTS_JSON, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to parse compliance results JSON: {e}", file=sys.stderr)
        return

    scenarios = data.get("scenarios", {})
    non_compliant = []
    
    for folder, info in scenarios.items():
        if not info.get("compliant", True) or info.get("failures"):
            non_compliant.append((folder, info))
            
    if not non_compliant:
        print("All audited scenarios are PEAK M-ATH compliant. No issues to create.")
        return

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, repo = repo.split("/", 1)
    else:
        owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")

    if not owner or not repo:
        print("GITHUB_REPOSITORY environment variable not formatted correctly or missing. Skipping issue creation.")
        return

    ensure_label_exists(owner, repo)

    for folder_name, info in non_compliant:
        ref = info.get("ref", "")
        failures = info.get("failures", [])
        warnings = info.get("warnings", [])
        
        title = f"PEAK Non-Compliance: {folder_name} ({ref})"
        if search_existing_issue(owner, repo, title):
            print(f"Skipping (open issue already exists): {title}")
            continue
            
        create_issue(owner, repo, title, folder_name, ref, failures, warnings)


if __name__ == "__main__":
    main()
