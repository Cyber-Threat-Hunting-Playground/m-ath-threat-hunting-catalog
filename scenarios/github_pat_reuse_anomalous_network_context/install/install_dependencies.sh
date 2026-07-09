#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../.." && pwd)"

# Install the shared dependencies used across all scenarios
bash "$repo_root/install/install_dependencies.sh"

# Install any additional dependencies required only by this scenario
scenario_requirements="$script_dir/requirements.txt"

if [[ -f "$scenario_requirements" ]] && grep -qE '^[^#[:space:]]' "$scenario_requirements"; then
    echo "Installing scenario-specific dependencies from: $scenario_requirements"
    python3 -m pip install -r "$scenario_requirements"
else
    echo "No scenario-specific dependencies to install."
fi

echo "Scenario dependency installation completed."
