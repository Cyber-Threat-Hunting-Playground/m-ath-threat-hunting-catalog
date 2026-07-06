import pytest
import tempfile
import os
import csv
from data_transform.data_deduplication import (
    detect_csv_and_columns,
    deduplicate_file,
    format_stats
)

def test_detect_csv_and_columns_not_csv(tmp_path):
    f = tmp_path / "simple_text.txt"
    f.write_text("Hello World\nLine 2\n", encoding="utf-8")
    
    is_csv, delimiter, header, agg_indices, non_agg_indices = detect_csv_and_columns(str(f))
    assert not is_csv
    assert delimiter is None

def test_detect_csv_and_columns_with_occurrence(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("domain,occurrence,country\ngoogle.com,12,US\n", encoding="utf-8")
    
    is_csv, delimiter, header, agg_indices, non_agg_indices = detect_csv_and_columns(str(f))
    assert is_csv
    assert delimiter == ","
    assert header == ["domain", "occurrence", "country"]
    assert agg_indices == [1]
    assert non_agg_indices == [0, 2]

def test_deduplicate_file_plain(tmp_path):
    infile = tmp_path / "input.txt"
    infile.write_text("Line 1\nline 1\n\nLine 2\n  \nLine 1\n", encoding="utf-8")
    outfile = tmp_path / "output.txt"
    
    deleted_lines, start, stop, duration = deduplicate_file(str(infile), str(outfile))
    
    # 2 blank lines (empty line, space line) + 2 duplicate line 1s = 4 deleted lines
    assert deleted_lines == 4
    
    content = outfile.read_text(encoding="utf-8").splitlines()
    assert content == ["Line 1", "Line 2"]

def test_deduplicate_file_csv_agg(tmp_path):
    infile = tmp_path / "input.csv"
    infile.write_text(
        "domain,prevalence,country\n"
        "google.com,10,US\n"
        "GOOGLE.COM,5,US\n"
        "yahoo.com,3,US\n"
        "google.com,2,US\n",
        encoding="utf-8"
    )
    outfile = tmp_path / "output.csv"
    
    deleted_lines, start, stop, duration = deduplicate_file(str(infile), str(outfile))
    
    # 2 duplicate google.com rows deleted/merged
    assert deleted_lines == 2
    
    with open(outfile, "r", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        
    assert reader[0] == ["domain", "prevalence", "country"]
    # First row is google.com. Its prevalence sum is 10 + 5 + 2 = 17
    assert reader[1] == ["google.com", "17", "US"]
    assert reader[2] == ["yahoo.com", "3", "US"]
