import csv
import os
import re
import urllib.request
import yaml
from datetime import datetime, timezone

# URLs and Paths
ART_INDEX_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/Indexes/index.yaml"
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_PATH = os.path.join(WORKSPACE_DIR, "scenarios", "catalog.csv")

def fetch_art_index() -> dict:
    """Fetch and parse the YAML index from Atomic Red Team repository."""
    print(f"Fetching Atomic Red Team index from: {ART_INDEX_URL}")
    req = urllib.request.Request(
        ART_INDEX_URL,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    with urllib.request.urlopen(req) as response:
        content = response.read()
    
    print("Parsing YAML content...")
    yaml_data = yaml.safe_load(content)
    return yaml_data

def build_technique_map(yaml_data: dict) -> dict:
    """Build a mapping of MITRE Technique ID to its list of atomic tests."""
    technique_to_tests = {}
    
    if not isinstance(yaml_data, dict):
        print("Warning: YAML data is not a dictionary.")
        return technique_to_tests

    for tactic, techniques in yaml_data.items():
        if not isinstance(techniques, dict):
            continue
        for tech_id, tech_info in techniques.items():
            if not isinstance(tech_info, dict):
                continue
            tests = tech_info.get("atomic_tests", [])
            if not isinstance(tests, list):
                continue
            
            # Initialize technique ID key
            if tech_id not in technique_to_tests:
                technique_to_tests[tech_id] = []
                
            for t in tests:
                guid = t.get("auto_generated_guid")
                if not guid:
                    continue
                # Avoid duplicate tests if the technique is classified under multiple tactics
                if any(existing.get("guid") == guid for existing in technique_to_tests[tech_id]):
                    continue
                
                platforms = t.get("supported_platforms", [])
                platform_str = ", ".join(platforms) if isinstance(platforms, list) else str(platforms)
                
                technique_to_tests[tech_id].append({
                    "name": t.get("name", "Unnamed Test").strip(),
                    "guid": guid.strip(),
                    "platform": platform_str.strip()
                })
                
    return technique_to_tests

def read_catalog() -> list:
    """Read the scenarios and their mapped MITRE IDs from catalog.csv."""
    scenarios = []
    if not os.path.exists(CATALOG_PATH):
        print(f"Error: Catalog not found at {CATALOG_PATH}")
        return scenarios
        
    with open(CATALOG_PATH, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        headers = next(reader)
        
        # Determine MITRE ID column index
        try:
            mitre_col_idx = headers.index("MITRE ID")
            folder_col_idx = headers.index("Folder")
        except ValueError as e:
            print(f"Error parsing catalog headers: {e}")
            return scenarios
            
        for row in reader:
            if len(row) > max(mitre_col_idx, folder_col_idx):
                folder = row[folder_col_idx]
                mitre_val = row[mitre_col_idx].strip()
                if folder and mitre_val:
                    mitre_ids = [m.strip() for m in mitre_val.split(",") if m.strip()]
                    if mitre_ids:
                        scenarios.append({
                            "folder": folder,
                            "mitre_ids": mitre_ids
                        })
    return scenarios

def parse_existing_table(readme_content: str) -> dict:
    """Parse the existing ## Atomic Red Team Tests section and extract test status."""
    existing_tests = {}
    
    # Locate the ## Atomic Red Team Tests section
    # Matches ## Atomic Red Team Tests until the next ## section or end of file
    section_pattern = re.compile(
        r'^## Atomic Red Team Tests\s*\n(.*?)(?=\n## |\Z)', 
        re.DOTALL | re.MULTILINE
    )
    match = section_pattern.search(readme_content)
    if not match:
        return existing_tests
        
    section_text = match.group(1)
    lines = section_text.splitlines()
    for line in lines:
        if "|" in line and "---" not in line and "Test Name" not in line:
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 5:
                name = parts[0]
                test_id = parts[1]
                platform = parts[2]
                date = parts[3]
                confirmed = parts[4]
                
                existing_tests[test_id] = {
                    "name": name,
                    "platform": platform,
                    "date": date,
                    "confirmed": confirmed
                }
    return existing_tests

def generate_markdown_table(tests: list) -> str:
    """Generate the markdown table for Atomic Red Team tests."""
    lines = [
        "## Atomic Red Team Tests",
        "",
        "| Test Name | Test ID | Platform | Identified Date | Human Confirmed |",
        "| --- | --- | --- | --- | --- |"
    ]
    for t in tests:
        lines.append(f"| {t['name']} | {t['guid']} | {t['platform']} | {t['date']} | {t['confirmed']} |")
    return "\n".join(lines) + "\n"

def update_readme(readme_path: str, target_tests: list) -> bool:
    """Update the local README.md of a scenario with the merged tests list."""
    if not os.path.exists(readme_path):
        print(f"Warning: README.md not found at {readme_path}")
        return False
        
    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    existing_tests = parse_existing_table(content)
    
    # Merge tests
    merged_tests = []
    current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    for t in target_tests:
        guid = t["guid"]
        if guid in existing_tests:
            # Preserve existing entry including identified date and human confirmation status
            merged_tests.append({
                "name": t["name"],
                "guid": guid,
                "platform": t["platform"],
                "date": existing_tests[guid]["date"],
                "confirmed": existing_tests[guid]["confirmed"]
            })
        else:
            # New test found
            merged_tests.append({
                "name": t["name"],
                "guid": guid,
                "platform": t["platform"],
                "date": current_date,
                "confirmed": "No"
            })
            
    # Include any tests that were previously confirmed/present but are no longer in the latest YAML
    for guid, info in existing_tests.items():
        if not any(t["guid"] == guid for t in target_tests):
            merged_tests.append({
                "name": info["name"],
                "guid": guid,
                "platform": info["platform"],
                "date": info["date"],
                "confirmed": info["confirmed"]
            })
            
    # If no tests are mapped or found, we don't generate the section/table
    if not merged_tests:
        return False
        
    # Generate new markdown table content
    new_table_str = generate_markdown_table(merged_tests)
    
    section_pattern = re.compile(
        r'^## Atomic Red Team Tests\s*\n.*?(?=\n## |\Z)', 
        re.DOTALL | re.MULTILINE
    )
    
    if section_pattern.search(content):
        # Replace the existing section
        new_content = section_pattern.sub(new_table_str, content)
    else:
        # Append to the end of the file, making sure there is a nice spacing
        if not content.endswith("\n\n"):
            if content.endswith("\n"):
                content += "\n"
            else:
                content += "\n\n"
        new_content = content + new_table_str
        
    if content.strip() == new_content.strip():
        return False
        
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    return True

def main():
    try:
        yaml_data = fetch_art_index()
    except Exception as e:
        print(f"Error fetching ART index: {e}")
        return
        
    tech_map = build_technique_map(yaml_data)
    scenarios = read_catalog()
    
    modified_count = 0
    print(f"\nProcessing {len(scenarios)} mapped scenarios...")
    for s in scenarios:
        folder = s["folder"]
        mitre_ids = s["mitre_ids"]
        
        # Collect tests for all mapped MITRE technique IDs
        tests = []
        for m_id in mitre_ids:
            tests.extend(tech_map.get(m_id, []))
            
        if not tests:
            print(f"No tests found for {mitre_ids} ({folder})")
            continue
            
        readme_path = os.path.join(WORKSPACE_DIR, "scenarios", folder, "README.md")
        if update_readme(readme_path, tests):
            print(f"Updated README for {folder} with {len(tests)} tests.")
            modified_count += 1
        else:
            print(f"No changes for {folder}.")
            
    print(f"\nCompleted! Modified {modified_count} README.md files.")

if __name__ == "__main__":
    main()
