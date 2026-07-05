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

    if failed:
        print("\nCommit ABORTED. Please fix the errors above and try again.", file=sys.stderr)
        return 1

    print("Pre-commit sanity checks passed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
