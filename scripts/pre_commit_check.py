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

        # 4. Check for company name (COMPANYNAME) inside text-based files
        if ext in TEXT_EXTENSIONS:
            if os.path.exists(norm_path):
                try:
                    with open(norm_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        if "COMPANYNAME" in content.lower():
                            # Find exact lines for helpful output
                            lines = content.splitlines()
                            print(f"ERROR: Company-related reference (COMPANYNAME) found in: {f}", file=sys.stderr)
                            for idx, line in enumerate(lines, start=1):
                                if "COMPANYNAME" in line.lower():
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
