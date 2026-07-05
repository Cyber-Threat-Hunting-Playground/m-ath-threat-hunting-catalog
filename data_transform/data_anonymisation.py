#!/usr/bin/env python3
"""
Utility script to anonymise sensitive fields (e.g. usernames, company names)
in text/CSV files based on mappings from a configuration file.
"""

import argparse
import csv
import os
import re
import sys
import tempfile
from typing import List, Tuple, Pattern

# Patterns to dynamically discover usernames in user profile paths.
# E.g. C:\Users\<username>, /home/<username>, /Users/<username>
USERNAME_DISCOVERY_PATTERNS = [
    re.compile(r'(?i)[Cc]:[/\\][Uu]sers[/\\]([^/\\]+)'),
    re.compile(r'(?i)[/\\][Hh]ome[/\\]([^/\\]+)'),
    re.compile(r'(?i)[/\\][Uu]sers[/\\]([^/\\]+)'),
]

# Pattern to dynamically discover domain/machine usernames.
# E.g. DESKTOP-1A2BCDE\jane.doe, COMPANYNAME\jane.doe, etc.
DOMAIN_USER_PATTERN = re.compile(r'(?i)([a-z0-9_-]{2,20})[/\\]([a-z0-9._-]+)')

# Patterns to dynamically discover Windows computer/host names.
# E.g. DESKTOP-1A2BCDE, LAPTOP-88EBFEE, etc.
COMPUTER_DISCOVERY_PATTERNS = [
    re.compile(r'(?i)\b(?:DESKTOP|LAPTOP|WIN)-[a-z0-9]{5,15}\b'),
]

EXCLUSIONS = {
    # System accounts and groups
    "public", "default", "all users", "default user", "desktop.ini",
    "administrator", "system", "network service", "local service",
    "allusers", "defaultuser", "nt authority", "authority", "local system",
    "localsystem", "networkservice", "localservice",
    
    # Common Windows directories and structures to avoid relative path false matches
    "windows", "system32", "syswow64", "users", "appdata", "local", "roaming",
    "temp", "microsoft", "onedrive", "google", "chrome", "edge", "program files",
    "programdata", "desktop", "documents", "downloads", "music", "pictures", "videos",
    "winreg", "software", "sam", "security", "components"
}


def load_mappings(mapping_path: str) -> List[Tuple[str, str]]:
    """
    Load mappings from the configuration input file.
    
    The file is expected to be a CSV file where:
    - Row format: Data type, Value
    - Lines starting with '#' are treated as comments and ignored.
    - Rows with 'Data type' and 'Value' as headers are ignored.
    """
    mappings: List[Tuple[str, str]] = []
    
    if not os.path.exists(mapping_path):
        print(f"Warning: Mapping file '{mapping_path}' not found.", file=sys.stderr)
        return mappings
        
    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for line_no, row in enumerate(reader, start=1):
                if not row:
                    continue
                # Remove leading/trailing spaces from cells
                row = [cell.strip() for cell in row]
                
                # Check for comments
                if row[0].startswith("#"):
                    continue
                
                # Check for header
                if len(row) >= 2 and row[0].lower() == "data type" and row[1].lower() == "value":
                    continue
                
                data_type = row[0]
                value = row[1] if len(row) > 1 else ""
                
                if not value:
                    # Skip empty values but warn the user if it's not a commented/blank line
                    if data_type:
                        print(f"Warning: Line {line_no} has an empty value for '{data_type}'. Skipping.", file=sys.stderr)
                    continue
                
                mappings.append((data_type, value))
    except Exception as e:
        print(f"Error reading mapping file '{mapping_path}': {e}", file=sys.stderr)
        sys.exit(1)
        
    # Sort mappings by the length of the Value in descending order.
    # This prevents shorter sub-strings from being replaced before longer ones
    mappings.sort(key=lambda x: len(x[1]), reverse=True)
    return mappings


def compile_patterns(mappings: List[Tuple[str, str]]) -> List[Tuple[Pattern[str], str]]:
    """
    Group mapping values by replacement (data type), sort them by length descending
    to avoid sub-string replacement issues, and compile them into a single regex per group.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for data_type, value in mappings:
        groups[data_type].append(value)
        
    patterns: List[Tuple[Pattern[str], str]] = []
    for data_type, values in groups.items():
        # Sort values by length descending within the group
        values.sort(key=len, reverse=True)
        # Escape each value and filter out empty values
        escaped_values = [re.escape(val) for val in values if val]
        if not escaped_values:
            continue
        # Join into a single regex string with alternation
        regex_str = "(?i)" + "|".join(escaped_values)
        compiled = re.compile(regex_str)
        patterns.append((compiled, data_type))
        
    return patterns


def is_valid_username(user: str, line: str, start_pos: int, end_pos: int) -> bool:
    """
    Validate if a candidate string is likely a username rather than a file path component.
    """
    if user.lower() in EXCLUSIONS:
        return False
    if any(user.lower().endswith(ext) for ext in [
        ".exe", ".dll", ".hta", ".zip", ".tmp", ".sys", ".ini", 
        ".xml", ".config", ".png", ".jpg", ".lnk", ".json", ".manifest"
    ]):
        return False
    # Check if preceded by a slash or backslash (which means DOMAIN is actually a directory)
    if start_pos > 0 and line[start_pos - 1] in "\\/":
        return False
    # Check if followed by a slash or backslash (which means USER is actually a directory)
    if end_pos < len(line) and line[end_pos] in "\\/":
        return False
    # Check if preceded by a drive letter (e.g. C:DOMAIN\user)
    if start_pos >= 2 and line[start_pos - 2] == ":" and line[start_pos - 3].isalpha():
        return False
    return True


def anonymise_line(
    line: str,
    compiled_patterns: List[Tuple[Pattern[str], str]],
    auto_username: bool = True,
    auto_computer: bool = True
) -> str:
    """
    Anonymise a single line of text using both dynamic username discovery and compiled patterns.
    """
    # 1. Dynamic username discovery (single-pass extraction and replacement)
    if auto_username:
        users_to_replace = set()
        # A. Profile paths (e.g. C:\Users\jane.doe)
        for pat in USERNAME_DISCOVERY_PATTERNS:
            for match in pat.finditer(line):
                user = match.group(1).strip()
                if user and user.lower() not in EXCLUSIONS:
                    users_to_replace.add(user)
                    
        # B. Domain/Computer username patterns (e.g. DESKTOP-1A2BCDE\jane.doe)
        for match in DOMAIN_USER_PATTERN.finditer(line):
            user = match.group(2).strip()
            start_pos = match.start()
            end_pos = match.end()
            if user and is_valid_username(user, line, start_pos, end_pos):
                users_to_replace.add(user)
                
        for user in users_to_replace:
            line = re.sub(re.escape(user), "USERNAME", line, flags=re.IGNORECASE)
            
    # 2. Dynamic computer name discovery (e.g. DESKTOP-1A2BCDE)
    if auto_computer:
        computers_to_replace = set()
        for pat in COMPUTER_DISCOVERY_PATTERNS:
            for match in pat.finditer(line):
                comp = match.group(0).strip()
                if comp.upper() != "COMPUTERNAME":
                    computers_to_replace.add(comp)
                    
        for comp in computers_to_replace:
            line = re.sub(re.escape(comp), "COMPUTERNAME", line, flags=re.IGNORECASE)
                    
    # 3. Static configuration replacements
    for pattern, replacement in compiled_patterns:
        line = pattern.sub(replacement, line)
        
    return line


def anonymise_file(
    input_file: str,
    output_file: str,
    compiled_patterns: List[Tuple[Pattern[str], str]],
    auto_username: bool = True,
    auto_computer: bool = True
) -> None:
    """
    Process a single file line by line to keep memory usage low.
    Writes to a temporary file first, then moves it to the output destination
    to guarantee atomic write (in case of script interruption).
    """
    temp_dir = os.path.dirname(output_file) or None
    fd, temp_path = tempfile.mkstemp(dir=temp_dir, prefix="anonymise_tmp_", suffix=".tmp")
    
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as outfile:
            with open(input_file, "r", encoding="utf-8", errors="replace") as infile:
                for line in infile:
                    outfile.write(anonymise_line(line, compiled_patterns, auto_username, auto_computer))
                    
        # Atomic replace or move
        if os.path.exists(output_file):
            os.remove(output_file)
        os.rename(temp_path, output_file)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e


def anonymise_file_dry_run(
    input_file: str,
    compiled_patterns: List[Tuple[Pattern[str], str]],
    auto_username: bool = True,
    auto_computer: bool = True
) -> int:
    """
    Simulate processing a single file line by line.
    Returns the number of lines that would have been modified.
    """
    modified_lines = 0
    try:
        with open(input_file, "r", encoding="utf-8", errors="replace") as infile:
            for line in infile:
                anonymised = anonymise_line(line, compiled_patterns, auto_username, auto_computer)
                if anonymised != line:
                    modified_lines += 1
    except Exception as e:
        print(f"Error reading {input_file} during dry-run: {e}", file=sys.stderr)
    return modified_lines


def process_path(
    input_path: str,
    output_path: str | None,
    output_suffix: str,
    in_place: bool,
    compiled_patterns: List[Tuple[Pattern[str], str]],
    auto_username: bool = True,
    auto_computer: bool = True,
    dry_run: bool = False,
) -> None:
    """
    Process the input path (which can be a single file or a directory).
    """
    if not os.path.exists(input_path):
        print(f"Error: Input path '{input_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # 1. Processing a Single File
    if os.path.isfile(input_path):
        if in_place:
            dest = input_path
            msg = f"Anonymising file in-place: {input_path}"
        elif output_path:
            dest = output_path
            msg = f"Anonymising file: {input_path} -> {dest}"
        else:
            root, ext = os.path.splitext(input_path)
            dest = f"{root}{output_suffix}{ext}"
            msg = f"Anonymising file: {input_path} -> {dest}"
            
        if dry_run:
            print(f"[DRY-RUN] {msg}")
            modified = anonymise_file_dry_run(input_path, compiled_patterns, auto_username, auto_computer)
            print(f"[DRY-RUN] Success. {modified} line(s) would be modified.")
            return
            
        print(msg)
        # Ensure parent directory of destination exists
        dest_dir = os.path.dirname(dest)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
            
        anonymise_file(input_path, dest, compiled_patterns, auto_username, auto_computer)
        print("Success.")
        return

    # 2. Processing a Directory
    if os.path.isdir(input_path):
        if in_place:
            print(f"Anonymising directory in-place: {input_path}")
        elif output_path:
            print(f"Anonymising directory: {input_path} -> {output_path}")
            if not dry_run:
                os.makedirs(output_path, exist_ok=True)
        else:
            print(f"Anonymising directory files with suffix '{output_suffix}' in: {input_path}")

        # Walk the directory tree
        for dirpath, _, filenames in os.walk(input_path):
            for filename in filenames:
                file_src = os.path.join(dirpath, filename)
                
                # Determine destination file path
                if in_place:
                    file_dest = file_src
                elif output_path:
                    # Maintain the sub-directory structure inside the output directory
                    rel_path = os.path.relpath(file_src, input_path)
                    file_dest = os.path.join(output_path, rel_path)
                else:
                    # Construct name with suffix in the same directory
                    root, ext = os.path.splitext(file_src)
                    
                    # Safety check: skip files that are already anonymised with this suffix
                    if output_suffix and file_src.endswith(f"{output_suffix}{ext}"):
                        continue
                        
                    file_dest = f"{root}{output_suffix}{ext}"

                if dry_run:
                    modified = anonymise_file_dry_run(file_src, compiled_patterns, auto_username, auto_computer)
                    print(f"[DRY-RUN] Would process: {file_src} -> {file_dest} ({modified} line(s) would be modified)")
                    continue

                # Ensure parent directory of file_dest exists
                dest_dir = os.path.dirname(file_dest)
                if dest_dir:
                    os.makedirs(dest_dir, exist_ok=True)

                try:
                    anonymise_file(file_src, file_dest, compiled_patterns, auto_username, auto_computer)
                    print(f"Processed: {file_src} -> {file_dest}")
                except Exception as e:
                    print(f"Error processing {file_src}: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Anonymise sensitive patterns in text files using a data type mapping configuration."
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Path to the input file or directory to anonymise."
    )
    parser.add_argument(
        "-o", "--output", help="Path to write the output file or directory. Ignored if --in-place is specified."
    )
    parser.add_argument(
        "-os",
        "--output_suffix",
        default="_anonymised",
        help="Suffix to append to the filename before the extension (default: '_anonymised').",
    )
    parser.add_argument(
        "-m",
        "--mapping",
        help="Path to the mapping configuration file. Defaults to 'data_anonymisation.input' in the script's directory.",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Modify files directly (in-place). Overrides --output and --output_suffix.",
    )
    parser.add_argument(
        "--no-auto-username",
        action="store_true",
        help="Disable automatic username discovery from user profile paths (e.g. C:\\Users\\<username>).",
    )
    parser.add_argument(
        "--no-auto-computer",
        action="store_true",
        help="Disable automatic computer name discovery (e.g. DESKTOP-1A2BCDE).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without modifying or creating files.",
    )

    args = parser.parse_args()

    # Determine mapping file path
    if args.mapping:
        mapping_path = args.mapping
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        mapping_path = os.path.join(script_dir, "data_anonymisation.input")

    print(f"Loading mapping from: {mapping_path}")
    raw_mappings = load_mappings(mapping_path)
    if raw_mappings:
        print(f"Loaded {len(raw_mappings)} pattern mappings.")
    else:
        print("No static pattern mappings loaded.")

    compiled_patterns = compile_patterns(raw_mappings)

    process_path(
        input_path=args.input,
        output_path=args.output,
        output_suffix=args.output_suffix,
        in_place=args.in_place,
        compiled_patterns=compiled_patterns,
        auto_username=not args.no_auto_username,
        auto_computer=not args.no_auto_computer,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
