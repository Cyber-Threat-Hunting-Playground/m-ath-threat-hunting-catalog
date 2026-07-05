#!/usr/bin/env python3
"""
Find catalog entries where the scenario folder is missing or does not contain
both input/ and output/ subfolders.
Outputs JSON with the list of catalog folder names that are missing or incomplete.
"""
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIOS_DIR = REPO_ROOT / "scenarios"
CATALOG_PATH = SCENARIOS_DIR / "catalog.csv"

REQUIRED_SUBFOLDERS = {"input", "output"}


def _use_case_to_folder(s: str) -> str:
    """Convert 'Use case' style to folder name: lowercase, spaces/special chars to underscore."""
    import re
    s = s.lower().strip().replace('"', "").replace("&", "_")
    s = re.sub(r"[^\w\s\-/]", "", s)
    s = re.sub(r"[\s\-/]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("_")


def get_catalog_folder_names() -> list[tuple[str, str]]:
    """
    Return list of (folder_name, display_name) from catalog.csv.
    Uses Folder column if present; otherwise derives from Use case.
    """
    if not CATALOG_PATH.exists():
        return []
    result = []
    with open(CATALOG_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []
        fieldnames = [fn.strip() for fn in reader.fieldnames]
        use_folder_col = "Folder" in fieldnames
        use_case_col = "Use case" in fieldnames

        for row in reader:
            if use_folder_col:
                val = row.get("Folder", "").strip()
                if val:
                    result.append((val, val))
            elif use_case_col:
                val = row.get("Use case", "").strip()
                if val:
                    folder_name = _use_case_to_folder(val)
                    result.append((folder_name, folder_name))
    return result


def folder_is_complete(folder_path: Path) -> bool:
    """Return True if folder exists and contains at least input/ and output/ subfolders."""
    if not folder_path.is_dir():
        return False
    subdirs = {d.name for d in folder_path.iterdir() if d.is_dir()}
    return REQUIRED_SUBFOLDERS.issubset(subdirs)


def main() -> None:
    catalog_folders = get_catalog_folder_names()
    missing = []
    for folder_name, display_name in catalog_folders:
        if not folder_name:
            continue
        folder_path = SCENARIOS_DIR / folder_name
        is_complete = folder_is_complete(folder_path)
        if not is_complete:
            missing.append(display_name)
    result = {"missing": sorted(missing)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
