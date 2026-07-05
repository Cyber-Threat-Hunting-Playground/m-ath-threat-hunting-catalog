#!/usr/bin/env bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <scenario_path>"
    exit 1
fi

SCENARIO_PATH=$(cd "$1" && pwd)
SCENARIO_NAME=$(basename "$SCENARIO_PATH")
VENV_PATH="$SCENARIO_PATH/.venv"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

echo "========================================="
echo "Bootstrapping Virtual Environment for M-ATH"
echo "Scenario: $SCENARIO_NAME"
echo "Path: $SCENARIO_PATH"
echo "Venv: $VENV_PATH"
echo "========================================="

# Find python3 or python
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "Error: Python was not found in PATH. Please install Python 3." >&2
    exit 1
fi

# Create venv if it doesn't exist
if [ ! -d "$VENV_PATH" ]; then
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_PATH"
else
    echo "Virtual environment already exists."
fi

VENV_PYTHON="$VENV_PATH/bin/python"
if [ ! -f "$VENV_PYTHON" ]; then
    # Fallback for Windows-like environments under bash
    VENV_PYTHON="$VENV_PATH/Scripts/python"
fi

if [ ! -f "$VENV_PYTHON" ]; then
    echo "Error: Could not find python executable inside the virtual environment at: $VENV_PYTHON" >&2
    exit 1
fi

echo "Upgrading pip..."
"$VENV_PYTHON" -m pip install --upgrade pip

# Install base requirements
ROOT_REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
if [ -f "$ROOT_REQUIREMENTS" ]; then
    echo "Installing base requirements from root..."
    "$VENV_PYTHON" -m pip install -r "$ROOT_REQUIREMENTS"
else
    echo "Warning: Root requirements.txt not found at $ROOT_REQUIREMENTS"
fi

# Install detection_logics package in editable mode
DETECTION_LOGICS_PATH=$(cd "$SCRIPT_DIR/../detection_logics" && pwd)
echo "Installing detection_logics in editable mode..."
"$VENV_PYTHON" -m pip install -e "$DETECTION_LOGICS_PATH"

# Install scenario-specific requirements
SCENARIO_REQUIREMENTS="$SCENARIO_PATH/install/requirements.txt"
if [ -f "$SCENARIO_REQUIREMENTS" ]; then
    echo "Installing scenario-specific requirements..."
    "$VENV_PYTHON" -m pip install -r "$SCENARIO_REQUIREMENTS"
fi

# Register Jupyter kernel
echo "Registering Jupyter kernel 'math-$SCENARIO_NAME'..."
"$VENV_PYTHON" -m ipykernel install --user --name="math-$SCENARIO_NAME" --display-name="M-ATH: $SCENARIO_NAME"

echo "Virtual environment bootstrap completed successfully."
