#!/usr/bin/env python3
import os
import sys
import subprocess

# File extensions we want to scan for text matches (e.g. COMPANYNAME)
TEXT_EXTENSIONS = {
    ".txt", ".csv", ".md", ".py", ".ipynb", ".ps1", ".sh", ".json", 
    ".yml", ".yaml", ".conf", ".ini", ".xml", ".html", ".js", ".ts", 
    ".css", ".input", ".example"
}

def load_company_details():
    """Reads sensitive company details from config/.env if it exists, along with environment variables."""
    details = {}
    
    # 1. Load from config/.env
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(repo_root, "config", ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip()
                        # Strip surrounding quotes
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        details[key] = val
        except Exception as e:
            print(f"Warning: Could not read configuration file {env_path}: {e}", file=sys.stderr)

    # 2. Extract sensitive strings to block
    sensitive_strings = []
    keys_to_extract = ["COMPANY_NAMES", "COMPANY_DOMAINS", "COMPANY_URLS", "COMPANY_EMAILS"]
    
    for key in keys_to_extract:
        # Fallback to environment variables if set
        val = details.get(key) or os.environ.get(key)
        if val:
            for part in val.split(","):
                part = part.strip()
                # Ignore placeholders like <your-company-name> or empty parts
                if part and not (part.startswith("<") and part.endswith(">")):
                    sensitive_strings.append((key, part))
                    
    return sensitive_strings

def get_staged_files():
    try:
        # ACM: Added, Copied, Modified
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.CalledProcessError as e:
        print(f"Error checking staged files: {e}", file=sys.stderr)
        return []
    except FileNotFoundError:
        # Git is not installed or not in PATH (e.g. running in simple environments)
        return []

def main():
    staged_files = get_staged_files()
    if not staged_files:
        return 0

    sensitive_strings = load_company_details()

    failed = False
    print("Running pre-commit sanity checks...")

    for f in staged_files:
        norm_path = os.path.normpath(f)
        path_parts = norm_path.split(os.sep)
        base_name = os.path.basename(norm_path)
        ext = os.path.splitext(norm_path)[1].lower()

        # 1. Check for virtual env files
        if any(part in {"venv", ".venv", ".jupyter_venv"} or part.endswith("_venv") for part in path_parts):
            print(f"ERROR: Virtual environment file staged: {f}", file=sys.stderr)
            print("       Virtual environments must never be committed to Git.", file=sys.stderr)
            failed = True
            continue

        # 2. Check for scenario inputs and outputs
        # Block anything in input/output except for .gitkeep, *.py, and *.example
        if "scenarios" in path_parts:
            if "input" in path_parts or "output" in path_parts:
                if base_name != ".gitkeep" and not base_name.endswith(".py") and not base_name.endswith(".example"):
                    print(f"ERROR: Dataset or output file staged in scenario input/output folder: {f}", file=sys.stderr)
                    print("       Only .gitkeep, *.py scripts, and *.example templates are allowed inside scenario input/output folders.", file=sys.stderr)
                    failed = True
                    continue

        # 3. Check for .input files (must be example files only)
        if ext == ".input":
            print(f"ERROR: Configuration mapping file staged: {f}", file=sys.stderr)
            print("       Only .input.example templates are allowed to be committed.", file=sys.stderr)
            failed = True
            continue

        # 3b. Check for Jupyter notebook execution data / metadata
        if ext == ".ipynb":
            if os.path.exists(norm_path):
                try:
                    import json
                    with open(norm_path, "r", encoding="utf-8", errors="ignore") as fh:
                        nb = json.load(fh)
                    
                    has_execution_data = False
                    details = []
                    
                    for idx, cell in enumerate(nb.get("cells", []), start=1):
                        if cell.get("cell_type") == "code":
                            # Check execution count
                            if cell.get("execution_count") is not None:
                                has_execution_data = True
                                details.append(f"Cell #{idx} has execution count: {cell.get('execution_count')}")
                            
                            # Check outputs
                            if cell.get("outputs") != []:
                                has_execution_data = True
                                details.append(f"Cell #{idx} has non-empty outputs")
                                
                            # Check execution timing metadata
                            metadata = cell.get("metadata", {})
                            if "execution" in metadata:
                                has_execution_data = True
                                details.append(f"Cell #{idx} has execution timing metadata")
                                
                    if has_execution_data:
                        print(f"ERROR: Staged notebook contains execution data/metadata: {f}", file=sys.stderr)
                        for d in details[:5]:  # print first 5 issues to keep output clean
                            print(f"       - {d}", file=sys.stderr)
                        if len(details) > 5:
                            print(f"       - ... and {len(details) - 5} more issues", file=sys.stderr)
                        print(f"       Please run: python scripts/clean_notebook.py \"{f}\"", file=sys.stderr)
                        failed = True
                except Exception as e:
                    print(f"Warning: Could not parse {f} as JSON for notebook validation: {e}", file=sys.stderr)

        # 4. Check for company name (COMPANYNAME) and sensitive company details inside text-based files
        if ext in TEXT_EXTENSIONS and base_name not in {".env", ".env.example"}:
            if os.path.exists(norm_path):
                try:
                    with open(norm_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        content_lower = content.lower()
                        
                        # Check for hardcoded placeholder
                        if "companyname" in content_lower:
                            lines = content.splitlines()
                            print(f"ERROR: Company-related reference (COMPANYNAME) found in: {f}", file=sys.stderr)
                            for idx, line in enumerate(lines, start=1):
                                if "companyname" in line.lower():
                                    print(f"       Line {idx}: {line.strip()}", file=sys.stderr)
                            failed = True
                            
                        # Check for dynamically configured sensitive strings
                        for key, pattern in sensitive_strings:
                            pattern_lower = pattern.lower()
                            if pattern_lower in content_lower:
                                lines = content.splitlines()
                                print(f"ERROR: Sensitive company info ({key}: '{pattern}') found in: {f}", file=sys.stderr)
                                for idx, line in enumerate(lines, start=1):
                                    if pattern_lower in line.lower():
                                        print(f"       Line {idx}: {line.strip()}", file=sys.stderr)
                                failed = True
                except Exception as e:
                    print(f"Warning: Could not read {f} for content validation: {e}", file=sys.stderr)

        # 5. Check for sensitive local paths and username leaks (detected dynamically)
        if ext in TEXT_EXTENSIONS:
            if "pre_commit_check" in base_name:
                continue
            if os.path.exists(norm_path):
                try:
                    with open(norm_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        content_lower = content.lower()
                        has_sensitive = False
                        matched_triggers = []
                        
                        # 5a. Check for local file URLs
                        if "file:///" in content_lower:
                            has_sensitive = True
                            matched_triggers.append("file:///")
                        
                        # 5b. Detect and check local username dynamically (skip in CI to avoid false positives)
                        if os.environ.get("GITHUB_ACTIONS") != "true":
                            from pathlib import Path
                            local_user = None
                            try:
                                local_user = (os.environ.get("USERNAME") or os.environ.get("USER") or os.getlogin() or "").lower()
                            except Exception:
                                pass
                            
                            try:
                                home_name = Path.home().name.lower()
                            except Exception:
                                home_name = None
                                
                            detected_names = {name for name in [local_user, home_name] if name and len(name) > 2}
                            for name in detected_names:
                                if name in content_lower:
                                    has_sensitive = True
                                    matched_triggers.append("local username/home folder name")
                                    break

                        if has_sensitive:
                            lines = content.splitlines()
                            print(f"ERROR: Sensitive local system path or username leak found in: {f}", file=sys.stderr)
                            print(f"       Triggered by: {', '.join(matched_triggers)}", file=sys.stderr)
                            for idx, line in enumerate(lines, start=1):
                                line_lower = line.lower()
                                trigger_hit = "file:///" in line_lower
                                if not trigger_hit and os.environ.get("GITHUB_ACTIONS") != "true":
                                    trigger_hit = any(name in line_lower for name in detected_names)
                                if trigger_hit:
                                    print(f"       Line {idx}: {line.strip()}", file=sys.stderr)
                            failed = True
                except Exception as e:
                    print(f"Warning: Could not read {f} for sensitive path validation: {e}", file=sys.stderr)

    if failed:
        print("\nCommit ABORTED. Please fix the errors above and try again.", file=sys.stderr)
        return 1

    print("Pre-commit sanity checks passed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
