#!/usr/bin/env python3
"""
Scan python files in data_transform/ and perform quality checks.
If any script is non-compliant, create a GitHub Issue.
"""
import ast
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_TRANSFORM_DIR = REPO_ROOT / "data_transform"
LABEL = "data_transform_quality"


def get_headers() -> dict | None:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        return None
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def api_request(method: str, url: str, data: dict | None = None) -> dict:
    headers = get_headers()
    if not headers:
        raise SystemExit("GH_TOKEN or GITHUB_TOKEN required")
    req = urllib.request.Request(url, method=method, headers=headers)
    if data:
        req.data = json.dumps(data).encode()
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def search_existing_issue(owner: str, repo: str, title: str) -> bool:
    """Return True if an open issue with this title and label exists."""
    q = f'repo:{owner}/{repo} is:open label:"{LABEL}" "{title}"'
    url = f"https://api.github.com/search/issues?q={urllib.parse.quote(q)}"
    try:
        result = api_request("GET", url)
        return result.get("total_count", 0) > 0
    except Exception as e:
        print(f"Error searching existing issue: {e}", file=sys.stderr)
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
                "color": "cc317c",
                "description": "Failed quality check on data_transform scripts",
            },
        )
        print(f"Created label: {LABEL}")
    except urllib.error.HTTPError as e:
        if e.code != 422:  # 422 = validation failed (label already exists)
            raise SystemExit(f"API error {e.code}: {e.read().decode()}")


def create_issue(owner: str, repo: str, title: str, body: str) -> None:
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    data = {"title": title, "body": body, "labels": [LABEL]}
    try:
        api_request("POST", url, data)
        print(f"Created issue: {title}")
    except Exception as e:
        print(f"Error creating issue '{title}': {e}", file=sys.stderr)


def check_script_compliance(file_path: Path) -> list[str]:
    """
    Perform quality checks on a python script.
    Returns a list of failed check descriptions.
    """
    failures = []
    
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        return [f"Failed to read file: {e}"]

    # Check 1: Compiles successfully
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return [f"Syntax error / failed to parse AST: {e}"]

    # Check 2: Shebang #!/usr/bin/env python3
    lines = content.splitlines()
    if not lines or not lines[0].startswith("#!") or "python" not in lines[0]:
        failures.append("Missing or invalid shebang (expected e.g. `#!/usr/bin/env python3` on the first line)")

    # Check 3: Module docstring
    docstring = ast.get_docstring(tree)
    if not docstring or not docstring.strip():
        failures.append("Missing module-level docstring at the top of the file")

    # Check 4: --dry-run argument in argparse
    has_dry_run = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument':
                # Check positional arguments
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and arg.value == '--dry-run':
                        has_dry_run = True
                        break
                    elif hasattr(ast, 'Str') and isinstance(arg, getattr(ast, 'Str')) and arg.s == '--dry-run':
                        has_dry_run = True
                        break
                if not has_dry_run:
                    # Check keyword arguments, in case defined with options/option_strings
                    for kw in node.keywords:
                        if kw.arg == 'option_strings':
                            if isinstance(kw.value, (ast.List, ast.Tuple)):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == '--dry-run':
                                        has_dry_run = True
                                        break
                                    elif hasattr(ast, 'Str') and isinstance(elt, getattr(ast, 'Str')) and elt.s == '--dry-run':
                                        has_dry_run = True
                                        break
    if not has_dry_run:
        # Fallback: check raw text just in case AST walk missed some dynamic pattern
        if "--dry-run" not in content:
            failures.append("Missing `--dry-run` command line argument support in argparse")

    return failures


def main() -> None:
    if not DATA_TRANSFORM_DIR.exists():
        print(f"Error: {DATA_TRANSFORM_DIR} does not exist.", file=sys.stderr)
        sys.exit(1)

    py_files = sorted(list(DATA_TRANSFORM_DIR.glob("*.py")))
    if not py_files:
        print("No python files found in data_transform/.")
        sys.exit(0)

    non_compliant = {}
    for file_path in py_files:
        rel_path = file_path.relative_to(REPO_ROOT).as_posix()
        failures = check_script_compliance(file_path)
        if failures:
            non_compliant[rel_path] = failures

    if not non_compliant:
        print("All data_transform scripts are compliant!")
        sys.exit(0)

    print(f"Found {len(non_compliant)} non-compliant script(s):")
    for path, failures in non_compliant.items():
        print(f"\n{path}:")
        for f in failures:
            print(f"  - {f}")

    # Check if we should create GitHub issues
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("\nGH_TOKEN or GITHUB_TOKEN not found. Skipping issue creation.")
        sys.exit(1)

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, repo = repo.split("/", 1)
    else:
        owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")

    if not owner or not repo:
        print("\nCould not determine repository owner or name from environment. Skipping issue creation.")
        sys.exit(1)

    ensure_label_exists(owner, repo)

    for path, failures in non_compliant.items():
        filename = os.path.basename(path)
        title = f"Data Transform Quality check failed - {filename}"
        if search_existing_issue(owner, repo, title):
            print(f"Skipping (issue exists): {title}")
            continue

        # Build issue body
        body = (
            f"The data transform script `{path}` failed the quality check.\n\n"
            f"Please address the following compliance issues:\n"
        )
        for f in failures:
            body += f"- {f}\n"

        create_issue(owner, repo, title, body)

    sys.exit(1)


if __name__ == "__main__":
    main()
