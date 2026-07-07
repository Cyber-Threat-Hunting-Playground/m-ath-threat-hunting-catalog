import csv
import sys
from pathlib import Path
import pytest

# Add .github/scripts to path to import generate_scenario_from_issue
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / ".github" / "scripts"))

import generate_scenario_from_issue


def test_slugify():
    assert generate_scenario_from_issue.slugify("Detection of compromised accounts") == "detection_of_compromised_accounts"
    assert generate_scenario_from_issue.slugify("DGA-detection-v2!") == "dga_detection_v2"
    assert generate_scenario_from_issue.slugify("   Spaces  And   Caps   ") == "spaces_and_caps"


def test_clean_value():
    assert generate_scenario_from_issue.clean_value("  hello  ") == "hello"
    assert generate_scenario_from_issue.clean_value("_No response_") == ""
    assert generate_scenario_from_issue.clean_value("None") == ""
    assert generate_scenario_from_issue.clean_value("n/a") == ""
    assert generate_scenario_from_issue.clean_value("Normal text") == "Normal text"


def test_parse_checkboxes():
    checkbox_text = """
- [ ] Supervised Classification (e.g. XGBoost)
- [x] Unsupervised Clustering (e.g. K-Means)
- [X] Anomaly Detection
- [ ] Graph Analysis
"""
    parsed = generate_scenario_from_issue.parse_checkboxes(checkbox_text)
    assert parsed == ["Unsupervised Clustering (e.g. K-Means)", "Anomaly Detection"]


def test_parse_issue_body():
    body = """
### Scenario Title / Use Case
My use case

### Scenario Description
My description

### Other Data Sources
_No response_
"""
    sections = generate_scenario_from_issue.parse_issue_body(body)
    assert sections.get("Scenario Title / Use Case") == "My use case"
    assert sections.get("Scenario Description") == "My description"
    assert sections.get("Other Data Sources") == "_No response_"


def test_get_next_ref(tmp_path):
    catalog_file = tmp_path / "catalog.csv"
    
    # Test empty catalog
    assert generate_scenario_from_issue.get_next_ref(catalog_file) == "M01"

    # Test existing entries
    catalog_file.write_text(
        "Ref,Folder,Use case\nM01,folder_1,Use Case 1\nM02,folder_2,Use Case 2\nM25,folder_25,Use Case 25\n",
        encoding="utf-8"
    )
    assert generate_scenario_from_issue.get_next_ref(catalog_file) == "M26"


def test_generate_scenario_integration(tmp_path, monkeypatch):
    catalog_file = tmp_path / "catalog.csv"
    catalog_file.write_text(
        "Ref,Folder,Use case,Description,Model used,Data needed,Source\nM01,compromised,Use Case 1,,AD logs,,",
        encoding="utf-8"
    )
    
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()

    # Apply monkeypatch for globals in generate_scenario_from_issue
    monkeypatch.setattr(generate_scenario_from_issue, "CATALOG_PATH", catalog_file)
    monkeypatch.setattr(generate_scenario_from_issue, "SCENARIOS_DIR", scenarios_dir)

    mock_issue_body = """### Scenario Title / Use Case

Detection of compromised accounts v2

### Scenario Description

Detecting compromised accounts v2...

### PEAK M-ATH Sub-process

Clustering

### Model or Statistical Method

- [ ] Supervised Classification (e.g. XGBoost, Random Forest)
- [x] Unsupervised Clustering (e.g. K-Means, DBSCAN)
- [ ] Anomaly Detection (e.g. Isolation Forest, Autoencoders)
- [x] Other (Specify details in the next section)

### Model Details / Specifics

Custom clustering

### Why does M-ATH apply?

Simple signatures are not enough because database query volumes naturally vary.

### Telemetry & Data Sources Needed

- [x] Active Directory (AD) logs
- [ ] Endpoint Detection & Response (EDR) logs
- [x] Windows Event logs

### Other Data Sources

Custom SIEM logs

### References / Source

https://github.com/example/ref
"""
    
    body_file = tmp_path / "issue_body.md"
    body_file.write_text(mock_issue_body, encoding="utf-8")

    # Run the generator main using body file
    monkeypatch.setattr(sys, "argv", [
        "generate_scenario_from_issue.py",
        "--body-file", str(body_file),
        "--submitter", "testsubmitter"
    ])
    
    exit_code = generate_scenario_from_issue.main()
    assert exit_code == 0

    # Verify folder bootstrapping
    folder_name = "detection_of_compromised_accounts_v2"
    folder_path = scenarios_dir / folder_name
    assert folder_path.exists()
    assert (folder_path / "input" / ".gitkeep").exists()
    assert (folder_path / "output" / ".gitkeep").exists()
    assert (folder_path / "install" / "requirements.txt").exists()
    assert (folder_path / "install" / "install_dependencies.sh").exists()
    assert (folder_path / "install" / "install_dependencies.ps1").exists()
    
    # Verify README.md contents
    readme_content = (folder_path / "README.md").read_text(encoding="utf-8")
    assert "## Why M-ATH Applies" in readme_content
    assert "Simple signatures are not enough because database query volumes naturally vary." in readme_content
    assert "**Ref:** M02" in readme_content

    # Verify catalog update
    with open(catalog_file, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        
    assert len(reader) == 2
    new_entry = reader[1]
    assert new_entry["Ref"] == "M02"
    assert new_entry["Folder"] == folder_name
    assert new_entry["Use case"] == "Detection of compromised accounts v2"
    assert new_entry["Description"] == "Detecting compromised accounts v2..."
    assert new_entry["Model used"] == "Unsupervised Clustering (e.g. K-Means, DBSCAN), Custom clustering"
    assert new_entry["Data needed"] == "Active Directory (AD) logs, Windows Event logs, Custom SIEM logs"
    assert new_entry["Source"] == "https://github.com/example/ref"
