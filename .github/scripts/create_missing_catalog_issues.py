#!/usr/bin/env python3
"""
Create GitHub Issues for each scenario folder missing from the catalog.
Skips creating an issue if one with the same title and label already exists.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MISSING_JSON = os.path.join(REPO_ROOT, "missing_scenarios.json")
LABEL = "missing_in_catalog"


def get_headers() -> dict:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN or GITHUB_TOKEN required")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def api_request(method: str, url: str, data: dict | None = None) -> dict:
    req = urllib.request.Request(url, method=method, headers=get_headers())
    if data:
        req.data = json.dumps(data).encode()
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def search_existing_issue(owner: str, repo: str, title: str) -> bool:
    """Return True if an open issue with this title and label exists."""
    q = f'repo:{owner}/{repo} is:open label:"{LABEL}" "{title}"'
    url = f"https://api.github.com/search/issues?q={urllib.parse.quote(q)}"
    result = api_request("GET", url)
    return result.get("total_count", 0) > 0


def ensure_label_exists(owner: str, repo: str) -> None:
    """Create the label if it does not exist."""
    url = f"https://api.github.com/repos/{owner}/{repo}/labels"
    try:
        api_request("POST", url, {"name": LABEL, "color": "d73a4a", "description": "Scenario folder exists but is not in catalog.csv"})
        print(f"Created label: {LABEL}")
    except urllib.error.HTTPError as e:
        if e.code != 422:  # 422 = validation failed (label already exists)
            raise SystemExit(f"API error {e.code}: {e.read().decode()}")


def create_issue(owner: str, repo: str, title: str, path: str) -> None:
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    body = f"The scenario folder `{path}` exists in the repository but is not listed in `scenarios/catalog.csv`.\n\nPlease add it to the catalog."
    data = {"title": title, "body": body, "labels": [LABEL]}
    api_request("POST", url, data)
    print(f"Created issue: {title}")


def main() -> None:
    if not os.path.exists(MISSING_JSON):
        print("No missing_scenarios.json found; nothing to do.")
        return

    with open(MISSING_JSON, encoding="utf-8") as f:
        data = json.load(f)

    missing = data.get("missing", [])
    if not missing:
        print("No missing scenarios.")
        return

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, repo = repo.split("/", 1)
    else:
        owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")

    ensure_label_exists(owner, repo)

    for path in missing:
        title = f"Missing in catalog - {path}"
        if search_existing_issue(owner, repo, title):
            print(f"Skipping (issue exists): {title}")
            continue
        create_issue(owner, repo, title, path)


if __name__ == "__main__":
    main()
