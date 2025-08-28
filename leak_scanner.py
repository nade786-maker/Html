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
from pathlib import Path

if sys.version_info < (3, 9):
    print("Invalid python version, use a version >= 3.9")
    sys.exit(1)

SECRETS_FILE_NAME = "gg_gathered_values"

# Source tracking constants
SOURCE_SEPARATOR = "__"
ENV_VAR_PREFIX = "ENVIRONMENT_VAR"
GITHUB_TOKEN_PREFIX = "GITHUB_TOKEN"
NPMRC_PREFIX = "NPMRC_HOME"
ENV_FILE_PREFIX = "ENV_FILE"

assignment_regex = re.compile(
    r"""
    ^\s*
    [a-zA-Z_]\w*
    \s*=\s*
    (?P<value>.+)
""",
    re.VERBOSE,
)

json_assignment_regex = re.compile(
    r"""
    "[a-zA-Z_]\w*"
    \s*:\s*
    "(?P<value>.+?)"
""",
    re.VERBOSE,
)


def remove_quotes(value: str):
    if len(value) > 1 and value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]


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

    return {remove_quotes(val) for val in res if val is not None}


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


def should_skip_path(fpath: Path) -> bool:
    """Check if a file path should be skipped based on directory exclusions."""
    parts = fpath.parts
    for part in parts:
        if part.startswith('.') and part not in {'.env', '.npmrc'} and not part.startswith('.env'):
            return True
        if part == 'node_modules':
            return True
    return False


def gather_files_by_patterns(timeout: int) -> dict[str, str]:
    """Gather secrets from files matching known patterns using rglob."""
    home = Path.home()
    res = {}
    start_time = time.time()
    
    # Define patterns we're looking for
    patterns = [
        '.env*',    # All .env files
        '.npmrc'    # NPM configuration files
    ]
    
    processed_files = set()  # Avoid processing same file multiple times
    
    for pattern in patterns:
        if time.time() - start_time > timeout:
            print(f"Timeout of {timeout}s reached while searching for files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option")
            return res
            
        for fpath in home.rglob(pattern):
            if fpath in processed_files:
                continue
            if should_skip_path(fpath):
                continue
            if not fpath.is_file():
                continue
                
            processed_files.add(fpath)
            
            try:
                text = fpath.read_text()
            except Exception:
                print(f"Failed reading {fpath}")
                continue
                
            values = extract_assigned_values(text)
            for value in values:
                if fpath.name == '.npmrc':
                    key = f"{NPMRC_PREFIX}{SOURCE_SEPARATOR}{value}"
                elif fpath.name.startswith('.env'):
                    safe_path = str(fpath).replace('/', '_').replace('.', '_')
                    key = f"{ENV_FILE_PREFIX}{SOURCE_SEPARATOR}{safe_path}{SOURCE_SEPARATOR}{value}"
                else:
                    key = f"FILE_{fpath.name}{SOURCE_SEPARATOR}{value}"
                res[key] = value
            
            print(f"Read values from {fpath}")
            
            # Check timeout after processing each file
            if time.time() - start_time > timeout:
                print(f"Timeout of {timeout}s reached while searching for files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option")
                return res
    
    return res


def get_source_description(source_part: str) -> str:
    """Convert source prefix to human-readable description."""
    source_mapping = {
        ENV_VAR_PREFIX: "Environment variable",
        GITHUB_TOKEN_PREFIX: "GitHub Token (gh auth token)",
        NPMRC_PREFIX: "~/.npmrc",
    }
    
    if source_part.startswith(ENV_FILE_PREFIX):
        return source_part.replace(f"{ENV_FILE_PREFIX}{SOURCE_SEPARATOR}", "").replace("_", "/")
    
    return source_mapping.get(source_part, source_part)


def display_leak(i: int, leak: dict, source_desc: str, secret_part: str) -> None:
    """Display a single leaked secret with formatting."""
    print(f"> Secret {i}")
    print(f'Secret name: "{secret_part}"')
    print(f"Source: {source_desc}")
    print(f'Secret hash: "{leak.get("hash", "")}"')
    print(f'Distinct locations: {leak.get("count", 0)}')
    if leak.get("url"):
        print("First location:")
        print(f'    URL: "{leak.get("url")}"')
    print()


def gather_all_secrets(timeout: int) -> dict[str, str]:
    all_values = {}
    for value in os.environ.values():
        key = f"{ENV_VAR_PREFIX}{SOURCE_SEPARATOR}{value}"
        all_values[key] = value
    gh_token = handle_github_token_command()
    if gh_token:
        key = f"{GITHUB_TOKEN_PREFIX}{SOURCE_SEPARATOR}{gh_token}"
        all_values[key] = gh_token
    all_values.update(gather_files_by_patterns(timeout))
    return all_values


def find_leaks(args):
    if shutil.which("ggshield") is None:
        print(
            "Please install ggshield first, see https://github.com/GitGuardian/ggshield#installation"
        )
        sys.exit(1)

    print("Collecting potential values, this may take some time...")
    print("Privacy note: All processing happens locally on your machine. No secrets are transmitted.")

    values_with_sources = gather_all_secrets(args.timeout)

    selected_items = [(k, v) for k, v in values_with_sources.items() if v is not None and len(v) >= args.min_chars]

    print(f"Found {len(selected_items)} values to check for potential leaks")
    secrets_file = Path(SECRETS_FILE_NAME)
    env_content = "\n".join([f"{k}={v}" for k, v in selected_items])
    secrets_file.write_text(env_content)
    print(f"Saved values to temporary file {SECRETS_FILE_NAME}")
    print("Checking values against GitGuardian database using secure hashing (no secrets transmitted)...")
    result = sp.run(["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "--type", "env", "-n", "key", "--json"], stdout=sp.PIPE, stderr=sp.DEVNULL, text=True)
    
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            leak_count = data.get("leaks_count", 0)
            
            if leak_count > 0:
                print(f"Warning: Found {leak_count} leaked secret{'s' if leak_count > 1 else ''}.")
                print()
                for i, leak in enumerate(data.get("leaks", []), 1):
                    key_name = leak.get("name", "")
                    if SOURCE_SEPARATOR in key_name:
                        source_part, secret_part = key_name.split(SOURCE_SEPARATOR, 1)
                        source_desc = get_source_description(source_part)
                        display_leak(i, leak, source_desc, secret_part)
            else:
                print("All right! No leaked secret has been found.")
                
        except (json.JSONDecodeError, KeyError) as e:
            print("Error parsing results, showing raw output:")
            sp.run(["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "-n", "cleartext"])
    
    
    if not args.keep_found_values:
        os.remove(SECRETS_FILE_NAME)
        print(f"Deleted temporary file {SECRETS_FILE_NAME}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--min-chars",
        type=int,
        help="Values with less chars than this are not considered",
        default=5,
    )
    parser.add_argument(
        "--keep-found-values",
        action="store_true",
        help="Do not delete the file that holds found values (potentially secrets)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Number of seconds before aborting discovery of files on hard drive.",
        default=30
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    find_leaks(args)
