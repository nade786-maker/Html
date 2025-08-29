#!/usr/bin/env python3

"""
find_secrets_unified.py: Finds sensitive files using fd with parallel processing.

Usage:
    python3 find_secrets_unified.py [SEARCH_PATH]
    python3 find_secrets_unified.py --path /path/to/search
    python3 find_secrets_unified.py -p /path/to/search

Arguments:
    SEARCH_PATH    Directory to search (default: home directory)

Options:
    --path, -p     Alternative way to specify search path
    --help, -h     Show help message
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from shutil import which
from typing import Dict, Iterator, List, Tuple

PATTERNS_FILE = "file_secrets_patterns.jsonl"

# --- Configuration ---

# Directories and patterns to exclude from scanning
EXCLUSIONS = [
    "node_modules",  # JavaScript/Node.js dependencies
    ".git",  # Git repository data
    "__pycache__",  # Python cache files
    "*.pyc",  # Python compiled files
    "dist",  # Build output directories
    "build",  # Build output directories
    "target",  # Rust/Java build directories
    ".DS_Store",  # macOS system files
]


def get_exclusion_args() -> List[str]:
    """Build the exclusion arguments for fd commands."""
    exclusion_args = []
    for exclusion in EXCLUSIONS:
        exclusion_args.extend(["--exclude", exclusion])
    return exclusion_args


def check_dependencies() -> None:
    """Verify that fd and jq are installed and the patterns file exists."""
    if not which("fd"):
        print("Error: 'fd' is not installed or not in your PATH.", file=sys.stderr)
        sys.exit(1)
    if not Path(PATTERNS_FILE).is_file():
        print(f"Error: Pattern file '{PATTERNS_FILE}' not found.", file=sys.stderr)
        sys.exit(1)


def yield_jsonl_file(file_path: str) -> Iterator[Dict[str, str]]:
    """Read a JSONL file and return a list of dictionaries."""
    with open(file_path, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                yield data
            except json.JSONDecodeError:
                print(f"Warning: Skipping malformed JSON line: {line.strip()}", file=sys.stderr)


def parse_patterns() -> Tuple[List[str], List[str]]:
    """Read the JSONL file and sort patterns into lists."""
    file_patterns = []
    extensions = []
    for data in yield_jsonl_file(PATTERNS_FILE):
        pattern_type = data.get("type")
        pattern = data.get("pattern")
        if pattern_type == "file":
            file_patterns.append(pattern)
        elif pattern_type == "extension":
            extensions.append(pattern.lstrip("*."))
    return file_patterns, extensions


def count_total_files(search_path: str) -> int:
    """Count total number of files in the search path using fd."""
    try:
        # Use fd to count all files with same flags as scanning functions
        num_cores = os.cpu_count()
        exclusion_args = get_exclusion_args()
        cmd = (
            ["fd", "--type", "f", "--hidden", "--no-ignore"] + exclusion_args + ["-j", str(num_cores), ".", search_path]
        )
        result = subprocess.run(cmd, check=False, text=True, capture_output=True)

        if result.stdout:
            file_count = len([line for line in result.stdout.strip().split("\n") if line.strip()])
            return file_count
        return 0
    except FileNotFoundError:
        print("Error: 'fd' command not found for file counting.", file=sys.stderr)
        return 0
    except Exception:
        return 0  # Return 0 if we can't count files


def run_unified_scan(file_patterns: List[str], extensions: List[str], search_path: str) -> List[str]:
    """Run unified fd scan for both file patterns and extensions in a single pass."""
    if not file_patterns and not extensions:
        return []

    try:
        # Combine all patterns into a single brace expansion for OR logic
        all_patterns = []

        # Add extension patterns (convert to *.ext format)
        for ext in extensions:
            all_patterns.append(f"*.{ext}")

        for pattern in file_patterns:
            all_patterns.append(pattern)

        # Create single brace expansion pattern for OR logic
        if len(all_patterns) > 1:
            combined_pattern = "{" + ",".join(all_patterns) + "}"
        else:
            combined_pattern = all_patterns[0]

        # Add parallel processing using all CPU cores and get absolute paths
        num_cores = os.cpu_count()
        exclusion_args = get_exclusion_args()
        base_cmd = (
            ["fd", "--type", "f", "--hidden", "--no-ignore"]
            + exclusion_args
            + ["-j", str(num_cores), "--absolute-path"]
        )
        full_cmd = base_cmd + ["--glob", combined_pattern, ".", search_path]

        total_patterns = len(extensions) + len(file_patterns)
        print(
            f"🔍 Scanning for files ({len(extensions)} extensions, {len(file_patterns)} patterns, {total_patterns} total)..."
        )
        result = subprocess.run(full_cmd, check=False, text=True, capture_output=True)

        # Parse the output to get the list of absolute file paths (remove duplicates)
        matched_files = []
        if result.stdout:
            files = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
            # Remove duplicates while preserving order
            matched_files = list(dict.fromkeys(files))

        # Print stderr to show progress
        if result.stderr:
            print(result.stderr, file=sys.stderr)

        print(f"✅ Unified scan complete. Found {len(matched_files)} files.")
        return matched_files

    except FileNotFoundError:
        print("Error: 'fd' command not found. Is it installed and in your PATH?", file=sys.stderr)
        return []
    except Exception as e:
        print(f"An unexpected error occurred in unified scan: {e}", file=sys.stderr)
        return []


def find_matching_files(
    file_patterns: List[str], extensions: List[str], search_path: str = str(Path.home())
) -> List[str]:
    """Run unified fd scan for both extensions and file patterns in a single pass."""
    if not file_patterns and not extensions:
        print("No patterns to search for.")
        return []

    # Run unified scan that handles both extensions and file patterns
    matched_files = run_unified_scan(file_patterns, extensions, search_path)

    return matched_files


def main() -> None:
    """Main execution function."""
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Find sensitive files using fd with parallel processing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 find_secrets_unified.py                    # Search in home directory
  python3 find_secrets_unified.py /path/to/search    # Search in specific directory
  python3 find_secrets_unified.py --path /usr/local  # Search with --path flag
        """,
    )
    parser.add_argument(
        "search_path",
        nargs="?",
        default=str(Path.home()),
        help="Directory to search for sensitive files (default: home directory)",
    )
    parser.add_argument("--path", "-p", dest="search_path_alt", help="Alternative way to specify search path")

    args = parser.parse_args()

    # Use --path flag if provided, otherwise use positional argument
    search_path = args.search_path_alt if args.search_path_alt else args.search_path

    check_dependencies()

    print(f"🔍 Starting unified scan for files potential containing secrets in '{search_path}'...")
    print("---")

    # Start timing the scan
    start_time = time.time()

    # Count total files for progress reporting

    file_patterns, extensions = parse_patterns()
    matched_files = find_matching_files(file_patterns, extensions, search_path)

    # Calculate elapsed time
    end_time = time.time()
    elapsed_time = end_time - start_time

    print("---")
    print(f"✅ Scan complete. Found {len(matched_files)} matching files.")
    print(f"⏱️  Scan completed in {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    main()
