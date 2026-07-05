#!/usr/bin/env python3
"""
Utility script to delete duplicate lines from text/CSV files.
The check is case-insensitive, keeping only the first occurrence of each unique line.
All empty and blank lines (lines containing only whitespace) are completely removed.
"""

import argparse
import csv
import datetime
import os
import sys
import tempfile
import time
from typing import Set, Tuple


def detect_csv_and_columns(file_path: str) -> Tuple[bool, str | None, list[str] | None, list[int] | None, list[int] | None]:
    """
    Read the first line of the file to:
    1. Detect if it is a CSV/TSV with delimiter ',' or ';'.
    2. Check if any column contains 'occurence', 'occurrence', or 'prevalence' (case-insensitive).
    
    Returns:
        (is_csv, delimiter, header, agg_col_indices, non_agg_col_indices)
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()
    except Exception:
        return False, None, None, None, None
        
    if not first_line or not first_line.strip():
        return False, None, None, None, None
        
    # Count commas and semicolons to determine the delimiter
    semi_count = first_line.count(';')
    comma_count = first_line.count(',')
    delimiter = ';' if semi_count > comma_count else ','
    
    try:
        reader = csv.reader([first_line.rstrip("\r\n")], delimiter=delimiter)
        header = next(reader)
    except Exception:
        return False, None, None, None, None
        
    if not header:
        return False, None, None, None, None
        
    agg_col_indices = []
    non_agg_col_indices = []
    has_agg_col = False
    
    for idx, col in enumerate(header):
        col_lower = col.lower()
        if "occurence" in col_lower or "occurrence" in col_lower or "prevalence" in col_lower:
            has_agg_col = True
            agg_col_indices.append(idx)
        else:
            non_agg_col_indices.append(idx)
            
    if has_agg_col:
        return True, delimiter, header, agg_col_indices, non_agg_col_indices
        
    return False, None, None, None, None


def deduplicate_file(
    input_file: str,
    output_file: str
) -> Tuple[int, datetime.datetime, datetime.datetime, float]:
    """
    Process a single file. If it's a CSV with occurrence or prevalence columns,
    sums the values for duplicates and merges them. Otherwise, performs
    line-by-line case-insensitive deduplication.
    
    Writes to a temporary file first, then moves it to the output destination
    to guarantee an atomic write.
    
    Returns a tuple: (deleted_lines_count, start_time, stop_time, duration_in_seconds)
    """
    start_time = datetime.datetime.now()
    start_t = time.time()
    
    is_csv, delimiter, header, agg_col_indices, non_agg_col_indices = detect_csv_and_columns(input_file)
    
    deleted_lines = 0
    temp_dir = os.path.dirname(output_file) or None
    fd, temp_path = tempfile.mkstemp(dir=temp_dir, prefix="dedup_tmp_", suffix=".tmp")
    
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as outfile:
            if is_csv and delimiter is not None and header is not None and agg_col_indices is not None and non_agg_col_indices is not None:
                with open(input_file, "r", encoding="utf-8", errors="replace") as infile:
                    infile.readline() # skip header
                    reader = csv.reader(infile, delimiter=delimiter)
                    writer = csv.writer(outfile, delimiter=delimiter, lineterminator="\n")
                    writer.writerow(header)
                    
                    seen_dict = {}
                    
                    for row in reader:
                        if not row or not any(field.strip() for field in row):
                            deleted_lines += 1
                            continue
                            
                        if len(row) < len(header):
                            row = row + [""] * (len(header) - len(row))
                        elif len(row) > len(header):
                            row = row[:len(header)]
                            
                        key = tuple(row[idx].lower() for idx in non_agg_col_indices)
                        
                        parsed_vals = {}
                        is_val_float = {}
                        for idx in agg_col_indices:
                            val_str = row[idx].strip()
                            is_f = False
                            try:
                                val_float = float(val_str)
                                if not val_float.is_integer():
                                    is_f = True
                            except ValueError:
                                val_float = 0.0
                            parsed_vals[idx] = val_float
                            is_val_float[idx] = is_f
                            
                        if key in seen_dict:
                            deleted_lines += 1
                            for idx in agg_col_indices:
                                seen_dict[key]['sums'][idx] += parsed_vals[idx]
                                if is_val_float[idx]:
                                    seen_dict[key]['is_float'][idx] = True
                        else:
                            seen_dict[key] = {
                                'original_row': row,
                                'sums': parsed_vals,
                                'is_float': is_val_float
                            }
                            
                    for key in seen_dict:
                        data = seen_dict[key]
                        orig_row = list(data['original_row'])
                        for idx in agg_col_indices:
                            sum_val = data['sums'][idx]
                            if not data['is_float'][idx]:
                                orig_row[idx] = str(int(sum_val))
                            else:
                                orig_row[idx] = str(sum_val)
                        writer.writerow(orig_row)
            else:
                seen: Set[str] = set()
                with open(input_file, "r", encoding="utf-8", errors="replace") as infile:
                    for line in infile:
                        line_content = line.rstrip("\r\n")
                        
                        if not line_content.strip():
                            deleted_lines += 1
                            continue
                        
                        line_lower = line_content.lower()
                        if line_lower in seen:
                            deleted_lines += 1
                        else:
                            seen.add(line_lower)
                            outfile.write(line)
                            
        # Atomic replace or move
        if os.path.exists(output_file):
            os.remove(output_file)
        os.rename(temp_path, output_file)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e
        
    stop_time = datetime.datetime.now()
    duration = time.time() - start_t
    
    return deleted_lines, start_time, stop_time, duration


def format_stats(
    file_path: str,
    deleted_count: int,
    start_time: datetime.datetime,
    stop_time: datetime.datetime,
    duration: float
) -> str:
    """
    Format statistics for a single file.
    """
    return (
        f"--- Statistics for {file_path} ---\n"
        f"Start Time:       {start_time.isoformat(sep=' ', timespec='seconds')}\n"
        f"Stop Time:        {stop_time.isoformat(sep=' ', timespec='seconds')}\n"
        f"Execution Time:   {duration:.4f} seconds\n"
        f"Deleted Lines:    {deleted_count}\n"
    )


def format_aggregated_stats(
    total_files: int,
    total_deleted: int,
    start_time: datetime.datetime,
    stop_time: datetime.datetime,
    duration: float
) -> str:
    """
    Format final aggregated statistics.
    """
    return (
        f"\n=========================================\n"
        f"=== FINAL AGGREGATED SUMMARY ===\n"
        f"=========================================\n"
        f"Total Files Processed: {total_files}\n"
        f"Total Start Time:      {start_time.isoformat(sep=' ', timespec='seconds')}\n"
        f"Total Stop Time:       {stop_time.isoformat(sep=' ', timespec='seconds')}\n"
        f"Total Execution Time:  {duration:.4f} seconds\n"
        f"Total Deleted Lines:   {total_deleted}\n"
        f"=========================================\n"
    )


def deduplicate_file_dry_run(
    input_file: str
) -> Tuple[int, datetime.datetime, datetime.datetime, float]:
    """
    Simulate processing a single file.
    If it's a CSV with occurrence or prevalence columns,
    sums the values for duplicates and merges them. Otherwise, performs
    line-by-line case-insensitive deduplication.
    Does NOT write any files to disk.
    
    Returns a tuple: (deleted_lines_count, start_time, stop_time, duration_in_seconds)
    """
    start_time = datetime.datetime.now()
    start_t = time.time()
    
    is_csv, delimiter, header, agg_col_indices, non_agg_col_indices = detect_csv_and_columns(input_file)
    
    deleted_lines = 0
    
    try:
        if is_csv and delimiter is not None and header is not None and agg_col_indices is not None and non_agg_col_indices is not None:
            with open(input_file, "r", encoding="utf-8", errors="replace") as infile:
                infile.readline() # skip header
                reader = csv.reader(infile, delimiter=delimiter)
                seen_keys = set()
                
                for row in reader:
                    if not row or not any(field.strip() for field in row):
                        deleted_lines += 1
                        continue
                        
                    if len(row) < len(header):
                        row = row + [""] * (len(header) - len(row))
                    elif len(row) > len(header):
                        row = row[:len(header)]
                        
                    key = tuple(row[idx].lower() for idx in non_agg_col_indices)
                    if key in seen_keys:
                        deleted_lines += 1
                    else:
                        seen_keys.add(key)
        else:
            seen: Set[str] = set()
            with open(input_file, "r", encoding="utf-8", errors="replace") as infile:
                for line in infile:
                    line_content = line.rstrip("\r\n")
                    
                    if not line_content.strip():
                        deleted_lines += 1
                        continue
                    
                    line_lower = line_content.lower()
                    if line_lower in seen:
                        deleted_lines += 1
                    else:
                        seen.add(line_lower)
    except Exception as e:
        print(f"Error reading {input_file} during dry-run: {e}", file=sys.stderr)
        
    stop_time = datetime.datetime.now()
    duration = time.time() - start_t
    
    return deleted_lines, start_time, stop_time, duration


def process_path(
    input_path: str,
    output_path: str | None,
    output_suffix: str,
    in_place: bool,
    show_stats: bool,
    dry_run: bool = False,
) -> None:
    """
    Process the input path (which can be a single file or a directory).
    """
    if not os.path.exists(input_path):
        print(f"Error: Input path '{input_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    global_start_time = datetime.datetime.now()
    global_start_t = time.time()
    total_deleted = 0
    processed_files_count = 0

    # 1. Processing a Single File
    if os.path.isfile(input_path):
        if in_place:
            dest = input_path
            msg = f"Deduplicating file in-place: {input_path}"
        elif output_path:
            dest = output_path
            msg = f"Deduplicating file: {input_path} -> {dest}"
        else:
            root, ext = os.path.splitext(input_path)
            dest = f"{root}{output_suffix}{ext}"
            msg = f"Deduplicating file: {input_path} -> {dest}"
            
        if dry_run:
            print(f"[DRY-RUN] {msg}")
            try:
                deleted_count, start_time, stop_time, duration = deduplicate_file_dry_run(input_path)
                print(f"[DRY-RUN] Success. {deleted_count} line(s) would be deleted.")
                if show_stats:
                    print(format_stats(input_path, deleted_count, start_time, stop_time, duration))
            except Exception as e:
                print(f"Error processing {input_path}: {e}", file=sys.stderr)
                sys.exit(1)
            return

        print(msg)
        # Ensure parent directory of destination exists
        dest_dir = os.path.dirname(dest)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
            
        try:
            deleted_count, start_time, stop_time, duration = deduplicate_file(input_path, dest)
            print("Success.")
            if show_stats:
                print(format_stats(input_path, deleted_count, start_time, stop_time, duration))
        except Exception as e:
            print(f"Error processing {input_path}: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # 2. Processing a Directory
    if os.path.isdir(input_path):
        if in_place:
            print(f"Deduplicating directory in-place: {input_path}")
        elif output_path:
            print(f"Deduplicating directory: {input_path} -> {output_path}")
            if not dry_run:
                os.makedirs(output_path, exist_ok=True)
        else:
            print(f"Deduplicating directory files with suffix '{output_suffix}' in: {input_path}")

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
                    
                    # Safety check: skip files that are already deduplicated with this suffix
                    if output_suffix and file_src.endswith(f"{output_suffix}{ext}"):
                        continue
                        
                    file_dest = f"{root}{output_suffix}{ext}"

                if dry_run:
                    try:
                        deleted_count, start_time, stop_time, duration = deduplicate_file_dry_run(file_src)
                        processed_files_count += 1
                        total_deleted += deleted_count
                        print(f"[DRY-RUN] Would process: {file_src} -> {file_dest} ({deleted_count} line(s) would be deleted)")
                        if show_stats:
                            print(format_stats(file_src, deleted_count, start_time, stop_time, duration))
                    except Exception as e:
                        print(f"Error processing {file_src}: {e}", file=sys.stderr)
                    continue

                # Ensure parent directory of file_dest exists
                dest_dir = os.path.dirname(file_dest)
                if dest_dir:
                    os.makedirs(dest_dir, exist_ok=True)

                try:
                    deleted_count, start_time, stop_time, duration = deduplicate_file(file_src, file_dest)
                    processed_files_count += 1
                    total_deleted += deleted_count
                    print(f"Processed: {file_src} -> {file_dest}")
                    if show_stats:
                        print(format_stats(file_src, deleted_count, start_time, stop_time, duration))
                except Exception as e:
                    print(f"Error processing {file_src}: {e}", file=sys.stderr)

        if show_stats and processed_files_count > 0:
            global_stop_time = datetime.datetime.now()
            global_duration = time.time() - global_start_t
            print(format_aggregated_stats(
                processed_files_count,
                total_deleted,
                global_start_time,
                global_stop_time,
                global_duration
            ))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Delete duplicate lines case-insensitively, keeping the first occurrence. Removes empty/blank lines."
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Path to the input file or directory to deduplicate."
    )
    parser.add_argument(
        "-o", "--output", help="Path to write the output file or directory. Ignored if --in-place is specified."
    )
    parser.add_argument(
        "-os",
        "--output_suffix",
        default="_nodups",
        help="Suffix to append to the filename before the extension (default: '_nodups').",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Modify files directly (in-place). Overrides --output and --output_suffix.",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Provide cleanup statistics (number of deleted lines, start/stop time, execution time).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without modifying or creating files.",
    )

    args = parser.parse_args()

    process_path(
        input_path=args.input,
        output_path=args.output,
        output_suffix=args.output_suffix,
        in_place=args.in_place,
        show_stats=args.stats,
        dry_run=args.dry_run
    )


if __name__ == "__main__":
    main()
