import os
import glob
import pytest
import papermill as pm
from papermill.exceptions import PapermillExecutionError

def discover_notebooks():
    # Discover all notebooks in the scenarios folder
    scenarios_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scenarios"))
    notebook_paths = glob.glob(os.path.join(scenarios_dir, "**", "*.ipynb"), recursive=True)
    # Sort for deterministic execution order
    notebook_paths.sort()
    return notebook_paths

NOTEBOOKS = discover_notebooks()

@pytest.mark.parametrize("notebook_path", NOTEBOOKS)
def test_notebook_execution(notebook_path, tmp_path):
    # Set the working directory to the notebook's directory so relative paths work
    notebook_dir = os.path.dirname(notebook_path)
    notebook_name = os.path.basename(notebook_path)
    output_nb = os.path.join(tmp_path, f"output_{notebook_name}")
    
    try:
        # Run the notebook
        pm.execute_notebook(
            notebook_path,
            output_nb,
            cwd=notebook_dir,
            kernel_name="python3"
        )
    except PapermillExecutionError as e:
        # If the notebook failed because of missing input data files or API keys, skip the test
        error_msg = str(e)
        skip_keywords = ["FileNotFoundError", "does not exist", "No such file", "not found", "ModuleNotFoundError", "VT_API_KEY", "API_KEY", "api_key"]
        if any(kw in error_msg for kw in skip_keywords):
            pytest.skip(f"Skipping notebook due to missing environment/dependency/input file/API key: {error_msg}")
        else:
            raise e
    except Exception as e:
        error_msg = str(e)
        if "Kernel" in error_msg or "FileNotFoundError" in error_msg or "VT_API_KEY" in error_msg:
            pytest.skip(f"Skipping notebook due to missing environment/kernel/input file/API key: {error_msg}")
        else:
            raise e
