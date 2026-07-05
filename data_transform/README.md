# Data Transformation Utilities

This directory contains scripts and configuration templates for transforming and cleaning data used in threat hunting scenarios.

## Contents

- [data_anonymisation.py](./data_anonymisation.py): The main Python utility script to search and replace sensitive information (like usernames and company names) in text or CSV files.
- [data_anonymisation.input.example](./data_anonymisation.input.example): The example configuration template for the anonymisation mappings.
- [data_deduplication.py](./data_deduplication.py): Python utility script to delete duplicate lines case-insensitively, keeping the first occurrence and completely removing blank lines.

---

## Data Anonymisation Tool

The `data_anonymisation.py` script reads pattern replacement mappings from a CSV-formatted configuration file and performs case-insensitive replacements in files or folders.

### Setup

To use the tool, copy the example mapping file to create your own configuration file (which is git-ignored by default):

```bash
copy data_anonymisation.input.example data_anonymisation.input
```

Open `data_anonymisation.input` and define your mappings. The file should have a header `Data type,Value`. Lines starting with `#` are ignored as comments.

#### Example Configuration:
```csv
Data type,Value
USERNAME,john.doe
USERNAME,jane.doe
COMPANYNAME,My Company Inc.
```

*Note: The script automatically sorts your values by length in descending order before executing the replacements, which ensures that longer terms (e.g. `My Company Inc. France`) are replaced before sub-terms (e.g. `My Company Inc.`).*

### Usage

Run the script from the command line:

```bash
python data_anonymisation.py -i <input_path> [options]
```

### Features

1. **Static Configuration Mappings**: Replaces custom defined values (e.g., `MyCompany` -> `COMPANYNAME`) loaded from the configuration file.
2. **Automatic Username Discovery**: Scans on-the-fly for user profile paths (`C:\Users\<username>`, `/home/<username>`) or domain login formats (`DOMAIN\username`) and replaces them with `USERNAME` using smart heuristic validation (ignoring system accounts, folder structures, or executables).
3. **Automatic Computer Name Discovery**: Scans on-the-fly for standard Windows hostnames (e.g., `DESKTOP-XXXXXXX`, `LAPTOP-XXXXXXX`, `WIN-XXXXXXX`) and replaces them with `COMPUTERNAME`.

#### CLI Parameters:
- `-i`, `--input`: (Required) Path to the file or directory to process.
- `-o`, `--output`: (Optional) Path to write the output file/directory. If not provided, a suffix is appended to the original filename.
- `-os`, `--output_suffix`: (Optional) Suffix to append to the filename before the extension (default: `_anonymised`).
- `-m`, `--mapping`: (Optional) Path to the mapping configuration file. (Defaults to `data_anonymisation.input` in the script's directory).
- `--in-place`: (Optional flag) Overwrite input files directly (in-place). Overrides `--output` and `--output_suffix`.
- `--no-auto-username`: (Optional flag) Disable automatic username discovery.
- `--no-auto-computer`: (Optional flag) Disable automatic computer name discovery.
- `--dry-run`: (Optional flag) Perform a dry run without modifying or creating files.

#### Command Examples:

1. **Anonymise a single file (produces `data_anonymised.csv`):**
   ```bash
   python data_anonymisation.py -i data.csv
   ```

2. **Anonymise a single file with custom output suffix (produces `data_clean.csv`):**
   ```bash
   python data_anonymisation.py -i data.csv -os _clean
   ```

3. **Anonymise in-place (modifies `data.csv` directly):**
   ```bash
   python data_anonymisation.py -i data.csv --in-place
   ```

4. **Anonymise all files in a directory recursively and output to a new directory:**
   ```bash
   python data_anonymisation.py -i ./input_logs -o ./output_logs
   ```

5. **Run anonymisation dry-run:**
   ```bash
   python data_anonymisation.py -i data.csv --dry-run
   ```

---

## Data Deduplication Tool

The `data_deduplication.py` script removes duplicate lines from text or CSV files case-insensitively, keeping the first occurrence and removing all empty/blank lines. It provides detailed statistics on processing when requested.

### Usage

Run the script from the command line:

```bash
python data_deduplication.py -i <input_path> [options]
```

### CLI Parameters:
- `-i`, `--input`: (Required) Path to the file or directory to process.
- `-o`, `--output`: (Optional) Path to write the output file/directory. If not provided, a suffix is appended to the original filename.
- `-os`, `--output_suffix`: (Optional) Suffix to append to the filename before the extension (default: `_nodups`).
- `--in-place`: (Optional flag) Overwrite input files directly (in-place). Overrides `--output` and `--output_suffix`.
- `--stats`: (Optional flag) Provide cleanup statistics (number of deleted lines, start/stop time, execution time).
- `--dry-run`: (Optional flag) Perform a dry run without modifying or creating files.

### Command Examples:

1. **Deduplicate a single file (produces `data_nodups.csv`):**
   ```bash
   python data_deduplication.py -i data.csv
   ```

2. **Deduplicate in-place with stats:**
   ```bash
   python data_deduplication.py -i data.csv --in-place --stats
   ```

3. **Deduplicate directory files and output to a new folder:**
   ```bash
   python data_deduplication.py -i ./input_logs -o ./output_logs --stats
   ```

4. **Run deduplication dry-run with stats:**
   ```bash
   python data_deduplication.py -i data.csv --stats --dry-run
   ```

