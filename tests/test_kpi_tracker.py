import pytest
import os
import csv
import time
from pathlib import Path
from kpi_tracker import KPITracker

def test_kpi_tracker_basic_timing():
    tracker = KPITracker(scenario_name="test_scenario")
    time.sleep(0.05)
    tracker.stop_and_report(registry_path="/dev/null") # Mock write
    assert tracker.duration >= 0.05

def test_kpi_tracker_rows():
    tracker = KPITracker(scenario_name="test_scenario")
    tracker.record_rows(100)
    tracker.record_rows(50)
    assert tracker.rows_processed == 150

def test_kpi_tracker_input_size(tmp_path):
    # Create mock input files
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    
    file1 = input_dir / "file1.txt"
    file1.write_text("a" * 1024 * 1024) # 1 MB
    
    file2 = input_dir / "file2.txt"
    file2.write_text("b" * 512 * 1024)  # 0.5 MB

    tracker = KPITracker(scenario_name="test_size", input_dir=str(input_dir))
    size_mb = tracker._get_input_size_mb()
    assert pytest.approx(size_mb, rel=1e-3) == 1.5

def test_kpi_tracker_registry_write(tmp_path):
    registry = tmp_path / "kpis.csv"
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    
    file1 = input_dir / "test.csv"
    file1.write_text("x" * 100) # small file
    
    tracker = KPITracker(scenario_name="test_scenario_reg", input_dir=str(input_dir))
    tracker.record_rows(500)
    time.sleep(0.01)
    tracker.stop_and_report(registry_path=str(registry))
    
    assert registry.exists()
    
    # Verify contents of CSV
    with open(registry, "r", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        
    assert reader[0] == ["Timestamp", "Scenario", "ExecutionTimeSec", "InputMB", "ThroughputMBs", "RowsProcessed", "RowsPerSec"]
    assert reader[1][1] == "test_scenario_reg"
    assert reader[1][5] == "500"
