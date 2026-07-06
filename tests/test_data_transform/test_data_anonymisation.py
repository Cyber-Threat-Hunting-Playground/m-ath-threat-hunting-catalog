import pytest
import re
import tempfile
import os
from data_transform.data_anonymisation import (
    load_mappings,
    compile_patterns,
    is_valid_username,
    anonymise_line
)

def test_load_mappings_nonexistent():
    # If file doesn't exist, returns empty list
    assert load_mappings("nonexistent_file.csv") == []

def test_load_mappings_valid(tmp_path):
    mapping_file = tmp_path / "mappings.csv"
    mapping_file.write_text(
        "# Comment line\n"
        "Data type,Value\n"
        "USERNAME,john.doe\n"
        "COMPANYNAME,Acme Corp\n"
        "COMPANYNAME,Acme Corp France\n", # Longer first check
        encoding="utf-8"
    )
    
    mappings = load_mappings(str(mapping_file))
    
    # Should sort by length of Value descending
    assert len(mappings) == 3
    assert mappings[0] == ("COMPANYNAME", "Acme Corp France")
    assert mappings[1] == ("COMPANYNAME", "Acme Corp")
    assert mappings[2] == ("USERNAME", "john.doe")

def test_compile_patterns():
    mappings = [
        ("COMPANYNAME", "Acme Corp France"),
        ("COMPANYNAME", "Acme Corp"),
        ("USERNAME", "john.doe")
    ]
    compiled = compile_patterns(mappings)
    
    # We expect one compiled pattern group per replacement type
    assert len(compiled) == 2
    types = [replacement for _, replacement in compiled]
    assert "COMPANYNAME" in types
    assert "USERNAME" in types

def test_is_valid_username():
    # Check simple exclusions
    assert not is_valid_username("public", "C:\\Users\\public\\Desktop", 9, 15)
    # Check executables
    assert not is_valid_username("test.exe", "C:\\Users\\test.exe\\Desktop", 9, 17)
    # Check slash boundaries
    assert not is_valid_username("users", "C:\\Users\\john", 3, 8)
    # Valid domain/user check
    assert is_valid_username("john.doe", "MYDOMAIN\\john.doe", 0, 17)

def test_anonymise_line_auto():
    # Test profile path replacement
    line = "The path is C:\\Users\\jane.doe\\Documents\\file.txt"
    anonymised = anonymise_line(line, [], auto_username=True, auto_computer=False)
    assert "C:\\Users\\USERNAME\\Documents\\file.txt" in anonymised

    # Test domain user format
    line2 = "Executing command as MYDOMAIN\\john.smith on some system"
    anonymised2 = anonymise_line(line2, [], auto_username=True, auto_computer=False)
    assert "MYDOMAIN\\USERNAME" in anonymised2

    # Test computer name discovery
    line3 = "Error reported from DESKTOP-A1B2C3D on subnet"
    anonymised3 = anonymise_line(line3, [], auto_username=False, auto_computer=True)
    assert "COMPUTERNAME" in anonymised3

def test_anonymise_line_static():
    mappings = [("COMPANYNAME", "Acme Corp")]
    compiled = compile_patterns(mappings)
    
    line = "Welcome to Acme Corp customer portal"
    anonymised = anonymise_line(line, compiled, auto_username=False, auto_computer=False)
    assert anonymised == "Welcome to COMPANYNAME customer portal"
