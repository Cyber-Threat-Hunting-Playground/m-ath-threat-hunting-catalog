import os
import sys
import pytest
from pathlib import Path

# Add project root and scripts directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "scripts"))

from audit_peak_compliance import PEAKAuditor

def get_scenarios():
    auditor = PEAKAuditor(repo_root=PROJECT_ROOT)
    catalog_scenarios = auditor.get_catalog_scenarios()
    # Return folder and expected Ref
    return [(s["folder"], s["ref"]) for s in catalog_scenarios]

SCENARIOS = get_scenarios()

@pytest.mark.parametrize("folder_name,expected_ref", SCENARIOS)
def test_scenario_peak_compliance(folder_name, expected_ref):
    """
    Test that the threat hunting scenario complies with Splunk PEAK M-ATH standards.
    Critical compliance failures are treated as test failures.
    """
    auditor = PEAKAuditor(repo_root=PROJECT_ROOT)
    
    # Audit the scenario
    failures, warnings = auditor.audit_scenario(folder_name, expected_ref)
    
    # Also write local reports during test runs so developers see them locally
    auditor.write_local_report(folder_name, failures, warnings)
    
    # Assert there are no critical compliance failures
    if failures:
        msg = f"Scenario '{folder_name}' ({expected_ref}) is not compliant with PEAK M-ATH:\n"
        for idx, f in enumerate(failures, 1):
            msg += f"  {idx}. {f}\n"
        if warnings:
            msg += "Compliance Warnings:\n"
            for idx, w in enumerate(warnings, 1):
                msg += f"  {idx}. {w}\n"
        raise AssertionError(msg)
