#!/usr/bin/env python3
"""Add Folder column to catalog.csv (slugified from Use case). Run when catalog.csv is not locked."""
import csv
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CATALOG = PROJECT_ROOT / "scenarios" / "catalog.csv"


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def main() -> int:
    with open(CATALOG, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames)

    if "Folder" in fieldnames:
        print("Folder column already exists.")
        return 0

    idx = fieldnames.index("Ref") + 1
    new_fieldnames = fieldnames[:idx] + ["Folder"] + fieldnames[idx:]
    for row in rows:
        row["Folder"] = slugify(row.get("Use case", ""))

    with open(CATALOG, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=new_fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = {k: row.get(k, "") for k in new_fieldnames}
            writer.writerow(out)

    print(f"Added Folder column to {CATALOG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
