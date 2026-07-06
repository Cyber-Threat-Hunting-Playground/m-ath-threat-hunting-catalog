import os
import time
import csv
from datetime import datetime
from pathlib import Path

class KPITracker:
    def __init__(self, scenario_name: str, input_dir: str | Path | None = None):
        self.scenario_name = scenario_name
        self.input_dir = Path(input_dir) if input_dir else None
        self.start_time = time.time()
        self.rows_processed = 0
        self.end_time = None
        self.duration = 0.0

    def record_rows(self, count: int):
        """Record the number of telemetry rows processed."""
        if count > 0:
            self.rows_processed += count

    def _get_input_size_mb(self) -> float:
        """Calculate the total size of files in input_dir in MB."""
        if not self.input_dir or not self.input_dir.exists():
            return 0.0
        
        total_bytes = 0
        if self.input_dir.is_file():
            total_bytes = self.input_dir.stat().st_size
        else:
            for p in self.input_dir.rglob("*"):
                if p.is_file():
                    total_bytes += p.stat().st_size
                    
        return total_bytes / (1024.0 * 1024.0)

    def stop_and_report(self, registry_path: str | Path | None = None):
        """Stop timing, calculate stats, write to registry, and report to screen."""
        self.end_time = time.time()
        self.duration = max(self.end_time - self.start_time, 0.001) # Avoid division by zero
        
        input_mb = self._get_input_size_mb()
        throughput_mbs = input_mb / self.duration
        rows_per_sec = self.rows_processed / self.duration

        # Determine path for the registry
        if not registry_path:
            # Default to scenarios/kpis.csv in workspace root (one directory up from scripts/)
            current_file_dir = Path(__file__).resolve().parent.parent
            registry_path = current_file_dir / "scenarios" / "kpis.csv"
        else:
            registry_path = Path(registry_path)

        # Ensure directory exists
        registry_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to central registry
        headers = ["Timestamp", "Scenario", "ExecutionTimeSec", "InputMB", "ThroughputMBs", "RowsProcessed", "RowsPerSec"]
        file_exists = registry_path.exists()
        
        try:
            with open(registry_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(headers)
                writer.writerow([
                    datetime.now().isoformat(timespec="seconds"),
                    self.scenario_name,
                    f"{self.duration:.4f}",
                    f"{input_mb:.4f}",
                    f"{throughput_mbs:.4f}",
                    self.rows_processed,
                    f"{rows_per_sec:.2f}"
                ])
        except Exception as e:
            print(f"Warning: Failed to write to KPI registry: {e}")

        # Render report
        try:
            from IPython.display import display, HTML
            
            html_report = f"""
            <div style="
                border: 1px solid #1f2937;
                border-radius: 8px;
                padding: 16px;
                background-color: #111827;
                color: #f3f4f6;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin-top: 15px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            ">
                <h3 style="margin-top: 0; color: #10b981; border-bottom: 1px solid #374151; padding-bottom: 8px;">📊 Performance KPIs: {self.scenario_name}</h3>
                <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                    <tr>
                        <td style="padding: 6px 0; color: #9ca3af;">⏱️ Execution Time:</td>
                        <td style="padding: 6px 0; text-align: right; font-weight: bold; color: #60a5fa;">{self.duration:.3f} s</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #9ca3af;">📂 Processed Input Size:</td>
                        <td style="padding: 6px 0; text-align: right; font-weight: bold; color: #34d399;">{input_mb:.3f} MB</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #9ca3af;">⚡ Throughput:</td>
                        <td style="padding: 6px 0; text-align: right; font-weight: bold; color: #a78bfa;">{throughput_mbs:.3f} MB/s</td>
                    </tr>
                    {" " if not self.rows_processed else f'''
                    <tr>
                        <td style="padding: 6px 0; color: #9ca3af;">📝 Rows Processed:</td>
                        <td style="padding: 6px 0; text-align: right; font-weight: bold; color: #fbbf24;">{self.rows_processed:,}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #9ca3af;">🚀 Processing Speed:</td>
                        <td style="padding: 6px 0; text-align: right; font-weight: bold; color: #f59e0b;">{rows_per_sec:,.1f} rows/s</td>
                    </tr>
                    '''}
                </table>
            </div>
            """
            display(HTML(html_report))
        except ImportError:
            # Fallback to console print
            print(f"=== KPI REPORT: {self.scenario_name} ===")
            print(f"Execution Time:   {self.duration:.3f} s")
            print(f"Processed Size:   {input_mb:.3f} MB")
            print(f"Throughput:       {throughput_mbs:.3f} MB/s")
            if self.rows_processed:
                print(f"Rows Processed:   {self.rows_processed:,}")
                print(f"Processing Speed: {rows_per_sec:,.1f} rows/s")
            print("=========================================")
