#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# ///

import argparse
import json
import os
import re
import shutil
import subprocess as sp
import sys
import time
from enum import Enum
from pathlib import Path

if sys.version_info < (3, 9):
    print("Invalid python version, use a version >= 3.9")
    sys.exit(1)

SECRETS_FILE_NAME = "gg_gathered_values"
PRIVATE_KEYS_FILENAMES = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "server.key",
    "private.key",
    "ssl.key",
    "mydomain.key",
    "certificate.pfx",
    "certificate.p12",
    "secring.gpg",
    "private.key",
    ".gnupg/private-keys-v1.d",
    "aws_private.pem",
    "my-key.pem",
    "ta.key",
    "server.key",
    "client.key",
    "private.pem",
    "user.key",
    "private_key.dat",
)


class Source(Enum):
    ENV_VAR = "ENVIRONMENT_VAR"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    NPMRC = "NPMRC_HOME"
    ENV_FILE = "ENV_FILE"
    PRIVATE_KEY = "PRIVATE_KEY"


SCAN_METHOD = {Source.NPMRC: "parse", Source.ENV_FILE: "parse", Source.PRIVATE_KEY: "full_text"}
# Source tracking constants
SOURCE_SEPARATOR = "__"


assignment_regex = re.compile(
    r"""
    ^\s*
    [a-zA-Z_]\w*
    \s*=\s*
    (?P<value>.{1,5000})
""",
    re.VERBOSE,
)

json_assignment_regex = re.compile(
    r"""
    "[a-zA-Z_]\w*"
    \s*:\s*
    "(?P<value>.{1,5000}?)"
""",
    re.VERBOSE,
)


def remove_quotes(value: str) -> str:
    if len(value) > 1 and value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]
    return value


def extract_assigned_values(text: str) -> set[str]:
    res = []
    for line in text.splitlines():
        for m in re.finditer(assignment_regex, line):
            pwd_value = m.group("value")
            res.append(pwd_value.strip())
            if "#" in pwd_value:
                res.append(pwd_value.split("#")[0].strip())

        for m in re.finditer(json_assignment_regex, line):
            pwd_value = m.group("value")
            res.append(pwd_value)

    return {remove_quotes(val) for val in res}


def handle_file_command(args):
    text = Path(args.file).read_text()
    values = extract_assigned_values(text)

    for value in values:
        print(value)


def handle_github_token_command(*args) -> str | None:
    if shutil.which("gh"):
        try:
            result = sp.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                stdin=sp.DEVNULL,
            )
            if result.returncode == 0 and result.stdout:
                token = result.stdout.strip()
                if re.match(r"^(gho_|ghp_)", token):
                    return token
        except (sp.TimeoutExpired, sp.SubprocessError):
            pass
    return None


def indices_to_delete(dirs: list[str]) -> list[int]:
    """Return indices of directories to skip during os.walk traversal."""
    indices = []
    for i, dirname in enumerate(dirs):
        if dirname.startswith(".") and dirname not in {".env", ".ssh"} and not dirname.startswith(".env"):
            indices.append(i)
        elif dirname == "node_modules":
            indices.append(i)
    return indices


def select_file(fpath: Path) -> str | None:
    """Return the file key prefix if this file should be processed."""
    safe_path = str(fpath).replace("/", "_").replace(".", "_")
    if fpath.name == ".npmrc":
        return f"{Source.NPMRC.value}{SOURCE_SEPARATOR}{safe_path}"
    elif fpath.name.startswith(".env") and not "example" in fpath.name:
        return f"{Source.ENV_FILE.value}{SOURCE_SEPARATOR}{safe_path}"
    elif fpath.name in PRIVATE_KEYS_FILENAMES or any(
        fpath.name.endswith(suffix) for suffix in [".key", ".pem", ".p12", ".pfx"]
    ):
        return f"{Source.PRIVATE_KEY.value}{SOURCE_SEPARATOR}{safe_path}"

    return None


class FileGatherer:
    """Handles file scanning and progress display for gathering secrets from files."""

    def __init__(self, timeout: int, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.home = Path.home()
        self.results = {}
        self.start_time = time.time()
        self.files_processed = 0
        self.last_progress_time = self.start_time
        self.last_spinner_time = self.start_time
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"]
        self.spinner_index = 0

    def _count_file_types_and_show_final_counts(self, current_time: float):
        """Count values by file type and show final counts."""
        npmrc_values = sum(1 for k in self.results.keys() if k.startswith(Source.NPMRC.value))
        env_files = sum(1 for k in self.results.keys() if k.startswith(Source.ENV_FILE.value))
        private_keys = sum(1 for k in self.results.keys() if k.startswith(Source.PRIVATE_KEY.value))
        elapsed = int(current_time - self.start_time)

        if self.verbose:
            print(
                f"\r   ├─ Configuration files: {npmrc_values} values found ({self.files_processed} files processed, {elapsed}s)"
            )
            print(f"   ├─ Environment files: {env_files} values found")
            print(f"   └─ Private key files: {private_keys} values found")
        else:
            print(
                f"\r   ├─ Configuration files: {npmrc_values} values found ({self.files_processed} files processed, {elapsed}s)",
                end="",
                flush=True,
            )
            print()
            print(f"   ├─ Environment files: {env_files} values found")
            print(f"   └─ Private key files: {private_keys} values found")

    def _show_timeout_message_and_counts(self, current_time: float):
        """Show timeout message and final counts."""
        if self.files_processed > 0:
            if self.verbose:
                print(
                    f"⏰ Timeout of {self.timeout}s reached after processing {self.files_processed} files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option"
                )
            else:
                print(
                    f"\r⏰ Timeout reached after {self.files_processed} files ({self.timeout}s)" + " " * 20 + "\n",
                    end="",
                )
        else:
            if self.verbose:
                print(
                    f"⏰ Timeout of {self.timeout}s reached while searching for files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option"
                )

        self._count_file_types_and_show_final_counts(current_time)

    def _update_spinner_progress(self, current_time: float):
        """Update and show spinner progress during scanning."""
        if (current_time - self.last_spinner_time) >= 0.2:
            self.spinner_index += 1
            spinner = self.spinner_chars[self.spinner_index % len(self.spinner_chars)]
            elapsed = int(current_time - self.start_time)

            if self.files_processed == 0:
                print(f"\r{spinner} Searching directories... ({elapsed}s)", end="", flush=True)
            else:
                print(
                    f"\r{spinner} Scanning... {self.files_processed} files processed ({elapsed}s)", end="", flush=True
                )

            self.last_spinner_time = current_time

    def _show_file_progress_if_needed(self, current_time: float):
        """Show progress update when processing files if conditions are met."""
        should_show_progress = (
            self.files_processed % 3 == 0 or self.files_processed == 1 or (current_time - self.last_progress_time) >= 1
        )

        if should_show_progress:
            spinner = self.spinner_chars[self.spinner_index % len(self.spinner_chars)]
            elapsed = int(current_time - self.start_time)
            print(f"\r{spinner} Scanning... {self.files_processed} files processed ({elapsed}s)", end="", flush=True)
            self.last_progress_time = current_time

    def _process_file_and_extract_values(self, fpath: Path, filekey: str):
        """Process a single file, extract values, and show results."""
        self.files_processed += 1
        try:
            text = fpath.read_text()
        except Exception:
            if self.verbose:
                print(f"Failed reading {fpath}")
            return

        # Handle private key files differently - use full content as single value
        if filekey.startswith(Source.PRIVATE_KEY.value):
            # For private keys, use "PRIVATE_KEY" as the value name and full content as value
            key = f"{filekey}{SOURCE_SEPARATOR}PRIVATE_KEY"
            self.results[key] = text.strip()

            if self.verbose:
                print(f"\r   Found private key in {fpath}" + " " * 20)
        else:
            # For other files, extract assigned values as before
            values = extract_assigned_values(text)

            if self.verbose:
                if values:
                    print(f"\r   Found {len(values)} values in {fpath}" + " " * 20)
                else:
                    print(f"\r   No values found in {fpath}" + " " * 20)

            for value in values:
                key = f"{filekey}{SOURCE_SEPARATOR}{value}"
                self.results[key] = value

    def gather(self) -> dict[str, str]:
        """Main method to gather files and return results."""
        # Show initial progress immediately
        spinner = self.spinner_chars[0]
        if self.verbose:
            print(f"\r{spinner} Starting filesystem scan...", end="", flush=True)
        else:
            print(f"\r{spinner} Starting scan...", end="", flush=True)

        try:
            for root, dirs, files in os.walk(self.home):
                current_time = time.time()

                # Check timeout before processing directory - fix for timeout 0 bug
                if self.timeout > 0 and (current_time - self.start_time) > self.timeout:
                    self._show_timeout_message_and_counts(current_time)
                    return self.results

                # Update spinner during directory traversal to show we're alive
                self._update_spinner_progress(current_time)

                # Remove unwanted directories during traversal (performance optimization)
                nb_deleted = 0
                for ind in indices_to_delete(dirs):
                    del dirs[ind - nb_deleted]
                    nb_deleted += 1

                # Process files in current directory
                for filename in files:
                    fpath = Path(root) / filename
                    filekey = select_file(fpath)

                    if filekey is None:
                        continue

                    self._process_file_and_extract_values(fpath, filekey)

                    # Show progress update when we find files
                    current_time = time.time()
                    self._show_file_progress_if_needed(current_time)

                    # Check timeout after processing file
                    if self.timeout > 0 and (current_time - self.start_time) > self.timeout:
                        self._show_timeout_message_and_counts(current_time)
                        return self.results

        except KeyboardInterrupt:
            print("\nScan interrupted by user")
            return self.results

        # Show final completion counts
        self._count_file_types_and_show_final_counts(time.time())
        return self.results


def gather_files_by_patterns(timeout: int, verbose: bool = False) -> dict[str, str]:
    """Gather secrets from files using os.walk (performance optimized)."""
    gatherer = FileGatherer(timeout, verbose)
    return gatherer.gather()


def get_source_description(source_part: str) -> str:
    """Convert source prefix to human-readable description."""
    source_mapping = {
        Source.ENV_VAR.value: "Environment variable",
        Source.GITHUB_TOKEN.value: "GitHub Token (gh auth token)",
        Source.NPMRC.value: "~/.npmrc",
    }

    if source_part.startswith(Source.ENV_FILE.value):
        return source_part.replace(f"{Source.ENV_FILE.value}{SOURCE_SEPARATOR}", "").replace("_", "/")
    elif source_part.startswith(Source.PRIVATE_KEY.value):
        return source_part.replace(f"{Source.PRIVATE_KEY.value}{SOURCE_SEPARATOR}", "").replace("_", "/")

    return source_mapping.get(source_part, source_part)


def display_leak(i: int, leak: dict, source_desc: str, secret_part: str) -> None:
    """Display a single leaked secret with formatting."""
    print(f"🔑 Secret #{i}")
    print(f"   Name: {secret_part}")
    print(f"   Source: {source_desc}")
    print(f"   Hash: {leak.get('hash', '')}")
    count = leak.get("count", 0)
    print(f"   Locations: {count} distinct Public GitHub repositories")
    if leak.get("url"):
        print(f"   First seen: {leak.get('url')} (only first location shown for security)")
    print()


def gather_all_secrets(timeout: int, verbose: bool = False) -> dict[str, str]:
    all_values = {}

    # Collect environment variables
    env_vars = 0
    for value in os.environ.values():
        key = f"{Source.ENV_VAR.value}{SOURCE_SEPARATOR}{value}"
        all_values[key] = value
        env_vars += 1

    # Show environment variables progress
    if verbose:
        print(f"   ├─ Environment variables: {env_vars} found")
    else:
        print(f"\r   ├─ Environment variables: {env_vars} found", end="", flush=True)
        print()  # Move to next line for next output

    # Collect GitHub token
    gh_token = handle_github_token_command()
    github_found = False
    if gh_token:
        key = f"{Source.GITHUB_TOKEN.value}{SOURCE_SEPARATOR}{gh_token}"
        all_values[key] = gh_token
        github_found = True

    # Show GitHub token progress
    if github_found:
        if verbose:
            print(f"   ├─ GitHub token: found")
        else:
            print(f"\r   ├─ GitHub token: found", end="", flush=True)
            print()  # Move to next line for next output
    else:
        if verbose:
            print(f"   ├─ GitHub token: not found")
        else:
            print(f"\r   ├─ GitHub token: not found", end="", flush=True)
            print()  # Move to next line for next output

    # Collect files using optimized os.walk method
    file_values = gather_files_by_patterns(timeout, verbose)
    all_values.update(file_values)

    return all_values


def find_leaks(args):
    if shutil.which("ggshield") is None:
        print("Please install ggshield first, see https://github.com/GitGuardian/ggshield#installation")
        sys.exit(1)

    print("🔍 S1ngularity Scanner - Detecting leaked secrets")
    print("🔒 All processing occurs locally, no secrets transmitted")
    if args.verbose:
        print()
        timeout_desc = f"{args.timeout}s" if args.timeout > 0 else "unlimited"
        keep_desc = "yes" if args.keep_temp_file else "no"
        print(f"⚙️  Settings: min-chars={args.min_chars}, timeout={timeout_desc}, keep-temp-file={keep_desc}")
        print()

    # Display scanning progress
    if args.verbose:
        timeout_desc = f"timeout: {args.timeout}s" if args.timeout > 0 else "no timeout"
        print(f"📁 Scanning system ({timeout_desc})...")

    values_with_sources = gather_all_secrets(args.timeout, args.verbose)

    if args.verbose:
        print()  # Extra spacing after tree display

    selected_items = [(k, v) for k, v in values_with_sources.items() if v is not None and len(v) >= args.min_chars]
    total_values = len(values_with_sources)
    filtered_count = total_values - len(selected_items)

    if filtered_count > 0:
        print(
            f"🔍 Checking {len(selected_items)} values against public leak database ({filtered_count} filtered, < {args.min_chars} chars)..."
        )
    else:
        print(f"🔍 Checking {len(selected_items)} values against public leak database...")

    secrets_file = Path(SECRETS_FILE_NAME)
    env_content = "\n".join([f"{k}={v}" for k, v in selected_items])
    secrets_file.write_text(env_content)
    result = sp.run(
        ["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "--type", "env", "-n", "key", "--json"],
        stdout=sp.PIPE,
        stderr=sp.DEVNULL,
        text=True,
    )

    if result.stdout:
        try:
            data = json.loads(result.stdout)
            total_leak_count = data.get("leaks_count", 0)
            selected_leaks = [
                leak for leak in data.get("leaks", []) if leak.get("count", 0) < args.max_public_occurrences
            ]
            leak_count = len(selected_leaks)
            filtered_count = total_leak_count - leak_count

            if filtered_count > 0:
                print(
                    f"ℹ️  Filtered out {filtered_count} leak{'s' if filtered_count > 1 else ''} with high public occurrence count (≥{args.max_public_occurrences})"
                )

            if leak_count > 0:
                print(f"⚠️  Found {leak_count} leaked secret{'s' if leak_count > 1 else ''}")
                print()
                for i, leak in enumerate(selected_leaks, 1):
                    key_name = leak.get("name", "")
                    if SOURCE_SEPARATOR in key_name:
                        source_part, secret_part = key_name.split(SOURCE_SEPARATOR, 1)
                        source_desc = get_source_description(source_part)
                        display_leak(i, leak, source_desc, secret_part)
                print("💡 Note: Results may include false positives (non-secret values matching leak patterns).")
                print("   Always verify results before taking action. If confirmed as real secrets:")
                print("   1. Immediately revoke and rotate the credential")
                print("   2. Review when the leak occurred and what systems may be compromised")
            else:
                print("✅ All clear! No leaked secrets found.")

        except (json.JSONDecodeError, KeyError) as e:
            if args.verbose:
                print("Error parsing results, showing raw output:")
                sp.run(["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "-n", "cleartext"])
            else:
                print("⚠️  Error checking secrets - run with --verbose for details")

    if not args.keep_temp_file:
        try:
            os.remove(SECRETS_FILE_NAME)
            if args.verbose:
                print(f"Cleaned up temporary file {SECRETS_FILE_NAME}")
        except FileNotFoundError:
            pass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--min-chars",
        type=int,
        help="Values with less chars than this are not considered",
        default=5,
    )
    parser.add_argument(
        "--keep-temp-file",
        action="store_true",
        help="Keep the temporary file containing gathered values instead of deleting it",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Number of seconds before aborting discovery of files on hard drive. Use 0 for unlimited scanning (default: 0).",
        default=0,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed scanning progress and debug information"
    )
    parser.add_argument(
        "--max-public-occurrences",
        type=int,
        help="Maximum number of public occurrences for a leak to be reported (default: 10)",
        default=10,
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    find_leaks(args)
