#!/usr/bin/env bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bash "$SCRIPT_DIR/../../../install/bootstrap_scenario_venv.sh" "$SCRIPT_DIR/.."
