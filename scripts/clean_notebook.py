#!/usr/bin/env python3
"""
Utility script to strip execution counts, cell execution metadata (timing),
and outputs from Jupyter notebooks. This ensures notebook templates in the
catalog remain clean and do not leak environment details or cause Git diff noise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def clean_notebook(file_path: Path) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            nb = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return False

    modified = False

    for cell in nb.get("cells", []):
        if cell.get("cell_type") == "code":
            # Strip execution count
            if cell.get("execution_count") is not None:
                cell["execution_count"] = None
                modified = True

            # Strip cell-level execution timing/status metadata
            metadata = cell.get("metadata", {})
            if "execution" in metadata:
                metadata.pop("execution")
                modified = True

            # Strip outputs
            if cell.get("outputs") != []:
                cell["outputs"] = []
                modified = True

    if modified:
        try:
            with open(file_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(nb, f, indent=2, ensure_ascii=False)
                f.write("\n")
            print(f"Cleaned execution data, metadata, and outputs from: {file_path}")
            return True
        except Exception as e:
            print(f"Error writing {file_path}: {e}", file=sys.stderr)
            return False
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/clean_notebook.py <notebook_path1> [notebook_path2 ...]", file=sys.stderr)
        return 1

    success = True
    for arg in sys.argv[1:]:
        path = Path(arg)
        if not path.exists():
            print(f"File not found: {path}", file=sys.stderr)
            success = False
            continue
        clean_notebook(path)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
