#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
requirements_file="$script_dir/requirements.txt"

if [[ ! -f "$requirements_file" ]]; then
    echo "requirements.txt not found at: $requirements_file" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 was not found in PATH. Install Python 3 and ensure the 'python3' command is available before running this script." >&2
    exit 1
fi

echo "Using requirements file: $requirements_file"

# Ensure pip is available
python3 -m ensurepip --default-pip
python3 -m pip install --upgrade pip
python3 -m pip install -r "$requirements_file"
python3 -c "import requests; print('requests OK:', requests.__version__)"

echo "Dependency installation completed."