#!/usr/bin/env python3
"""
Find scenario folders in scenarios/ that are not listed in scenarios/catalog.csv.
Outputs JSON with the list of missing scenario paths.
"""
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIOS_DIR = REPO_ROOT / "scenarios"
CATALOG_PATH = SCENARIOS_DIR / "catalog.csv"

# Files to exclude from scenario folder list (not directories)
EXCLUDE_FILES = {"catalog.csv"}


def get_scenario_folders() -> set[str]:
    """Return set of directory names under scenarios/."""
    if not SCENARIOS_DIR.exists():
        return set()
    folders = set()
    for item in SCENARIOS_DIR.iterdir():
        if item.is_dir() and not item.name.startswith("#"):
            folders.add(item.name)
    return folders


def _use_case_to_folder(s: str) -> str:
    """Convert 'Use case' style to folder name: lowercase, spaces/special chars to underscore."""
    import re
    s = s.lower().strip().replace('"', "").replace("&", "_")
    s = re.sub(r"[^\w\s\-/]", "", s)
    s = re.sub(r"[\s\-/]+", "_", s)
    s = re.sub(r"_+", "_", s)  # Collapse multiple underscores
    return s.strip("_")


def get_catalog_folders() -> set[str]:
    """Return set of folder names from catalog.csv (Folder column or Use case fallback)."""
    if not CATALOG_PATH.exists():
        return set()
    folders = set()
    with open(CATALOG_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return set()
        fieldnames = [fn.strip() for fn in reader.fieldnames]
        use_folder_col = "Folder" in fieldnames
        use_case_col = "Use case" in fieldnames
        folder_col = "Folder" if use_folder_col else None
        use_case_col_name = "Use case" if use_case_col else None

        for row in reader:
            if folder_col:
                val = row.get(folder_col, "").strip()
                if val:
                    folders.add(val)
            elif use_case_col_name:
                val = row.get(use_case_col_name, "").strip()
                if val:
                    folders.add(_use_case_to_folder(val))
    return folders


def main() -> None:
    scenario_folders = get_scenario_folders()
    catalog_folders = get_catalog_folders()
    missing = sorted(scenario_folders - catalog_folders)
    # Full paths for issue titles
    missing_paths = [f"scenarios/{f}" for f in missing]
    result = {"missing": missing_paths, "missing_folders": missing}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
