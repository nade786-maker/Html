#!/usr/bin/env uv run --script
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


def should_skip_path(fpath: Path) -> bool:
    """Check if a file path should be skipped based on directory exclusions."""
    parts = fpath.parts
    for part in parts:
        if part.startswith('.') and part not in {'.env', '.npmrc'} and not part.startswith('.env'):
            return True
        if part == 'node_modules':
            return True
    return False


def indices_to_delete(dirs: list[str]) -> list[int]:
    """Return indices of directories to skip during os.walk traversal."""
    indices = []
    for i, dirname in enumerate(dirs):
        if dirname.startswith('.') and dirname not in {'.env'} and not dirname.startswith('.env'):
            indices.append(i)
        elif dirname == 'node_modules':
            indices.append(i)
    return indices


def select_file(fpath: Path) -> str | None:
    """Return the file key prefix if this file should be processed."""
    if fpath.name == '.npmrc':
        return NPMRC_PREFIX
    elif fpath.name.startswith('.env') and not "example" in fpath.name:
        # Encode path to preserve special characters in env var keys
        safe_path = str(fpath).replace('/', '__SLASH__').replace('.', '__DOT__')
        return f"{ENV_FILE_PREFIX}{SOURCE_SEPARATOR}{safe_path}"
    return None


def gather_files_by_patterns(timeout: int, verbose: bool = False) -> dict[str, str]:
    """Gather secrets from files using os.walk (performance optimized)."""
    home = Path.home()
    res = {}
    start_time = time.time()
    files_processed = 0
    npmrc_files_found = 0
    npmrc_files_with_secrets = 0
    env_files_found = 0
    env_files_with_secrets = 0
    last_progress_time = start_time
    last_spinner_time = start_time
    
    spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧']
    spinner_index = 0
    
    if not verbose:
        print(f"\r{spinner_chars[0]} Starting scan...", end="", flush=True)
    elif verbose:
        print(f"\r{spinner_chars[0]} Starting filesystem scan...", end="", flush=True)
    
    try:
        for root, dirs, files in os.walk(home):
            current_time = time.time()
            
            # Check timeout before processing directory
            if timeout > 0 and (current_time - start_time) > timeout:
                if files_processed > 0:
                    if verbose:
                        print(f"⏰ Timeout of {timeout}s reached after processing {files_processed} files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option")
                    else:
                        print(f"\r⏰ Timeout reached after {files_processed} files ({timeout}s)" + " " * 20 + "\n", end="")
                else:
                    if verbose:
                        print(f"⏰ Timeout of {timeout}s reached while searching for files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option")
                npmrc_values = sum(1 for k in res.keys() if k.startswith(NPMRC_PREFIX))
                env_values = sum(1 for k in res.keys() if k.startswith(ENV_FILE_PREFIX))
                elapsed = int(current_time - start_time)
                if verbose:
                    print(f"\r   ├─ Configuration files ({npmrc_files_found} files): {npmrc_values} values found ({files_processed} total files processed, {elapsed}s)")
                    print(f"   └─ Environment files ({env_files_found} files): {env_values} values found")
                else:
                    print(f"\r   ├─ Configuration files ({npmrc_files_found} files): {npmrc_values} values found ({files_processed} total files processed, {elapsed}s)", end="", flush=True)
                    print()
                    print(f"   └─ Environment files ({env_files_found} files): {env_values} values found")
                return res
            
            # Update spinner to show progress
            if (current_time - last_spinner_time) >= 0.2:
                spinner_index += 1
                spinner = spinner_chars[spinner_index % len(spinner_chars)]
                elapsed = int(current_time - start_time)
                if files_processed == 0:
                    if verbose:
                        print(f"\r{spinner} Searching directories... ({elapsed}s)", end="", flush=True)
                    else:
                        print(f"\r{spinner} Searching directories... ({elapsed}s)", end="", flush=True)
                else:
                    if verbose:
                        print(f"\r{spinner} Scanning... {files_processed} files processed ({elapsed}s)", end="", flush=True)
                    else:
                        print(f"\r{spinner} Scanning... {files_processed} files processed ({elapsed}s)", end="", flush=True)
                last_spinner_time = current_time
            
            # Skip unwanted directories during traversal (performance optimization)
            nb_deleted = 0
            for ind in indices_to_delete(dirs):
                del dirs[ind - nb_deleted]
                nb_deleted += 1
            
            for filename in files:
                fpath = Path(root) / filename
                filekey = select_file(fpath)
                
                if filekey is not None:
                    files_processed += 1
                    
                    if filekey.startswith(NPMRC_PREFIX):
                        npmrc_files_found += 1
                    elif filekey.startswith(ENV_FILE_PREFIX):
                        env_files_found += 1
                    
                    try:
                        text = fpath.read_text()
                    except Exception:
                        if verbose:
                            print(f"Failed reading {fpath}")
                        continue
                    
                    values = extract_assigned_values(text)
                    
                    if values:
                        if filekey.startswith(NPMRC_PREFIX):
                            npmrc_files_with_secrets += 1
                        elif filekey.startswith(ENV_FILE_PREFIX):
                            env_files_with_secrets += 1
                            
                        if verbose:
                            print(f"\r   Found {len(values)} values in {fpath}" + " " * 20)
                    elif verbose:
                        print(f"\r   No values found in {fpath}" + " " * 20)
                        
                    for value in values:
                        key = f"{filekey}{SOURCE_SEPARATOR}{value}"
                        res[key] = value
                    
                    should_show_progress = (
                        files_processed % 3 == 0 or 
                        files_processed == 1 or 
                        (current_time - last_progress_time) >= 1
                    )
                    
                    if should_show_progress:
                        spinner = spinner_chars[spinner_index % len(spinner_chars)]
                        elapsed = int(current_time - start_time)
                        if verbose:
                            print(f"\r{spinner} Scanning... {files_processed} files processed ({elapsed}s)", end="", flush=True)
                        else:
                            print(f"\r{spinner} Scanning... {files_processed} files processed ({elapsed}s)", end="", flush=True)
                        last_progress_time = current_time
                    
                    # Check timeout after processing each file
                    current_time = time.time()
                    if timeout > 0 and (current_time - start_time) > timeout:
                        if verbose:
                            print(f"⏰ Timeout of {timeout}s reached after processing {files_processed} files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option")
                        else:
                            print(f"\r⏰ Timeout reached after {files_processed} files ({timeout}s)" + " " * 20 + "\n", end="")
                        npmrc_values = sum(1 for k in res.keys() if k.startswith(NPMRC_PREFIX))
                        env_values = sum(1 for k in res.keys() if k.startswith(ENV_FILE_PREFIX))
                        elapsed = int(current_time - start_time)
                        if verbose:
                            print(f"\r   ├─ Configuration files: {npmrc_files_found} found, {npmrc_files_with_secrets} with secrets ({npmrc_values} values, {elapsed}s)")
                            print(f"   └─ Environment files: {env_files_found} found, {env_files_with_secrets} with secrets ({env_values} values)")
                        else:
                            print(f"\r   ├─ Configuration files: {npmrc_files_found} found, {npmrc_files_with_secrets} with secrets ({npmrc_values} values, {elapsed}s)", end="", flush=True)
                            print()
                            print(f"   └─ Environment files: {env_files_found} found, {env_files_with_secrets} with secrets ({env_values} values)")
                        return res
    
    except KeyboardInterrupt:
        if verbose:
            print("Scan interrupted by user")
        return res
    
    npmrc_values = sum(1 for k in res.keys() if k.startswith(NPMRC_PREFIX))
    env_values = sum(1 for k in res.keys() if k.startswith(ENV_FILE_PREFIX))
    
    elapsed = int(time.time() - start_time)
    if verbose:
        print(f"\r   ├─ Configuration files: {npmrc_files_found} found, {npmrc_files_with_secrets} with secrets ({npmrc_values} values, {elapsed}s)")
        print(f"   └─ Environment files: {env_files_found} found, {env_files_with_secrets} with secrets ({env_values} values)")
    else:
        print(f"\r   ├─ Configuration files: {npmrc_files_found} found, {npmrc_files_with_secrets} with secrets ({npmrc_values} values, {elapsed}s)", end="", flush=True)
        print()
        print(f"   └─ Environment files: {env_files_found} found, {env_files_with_secrets} with secrets ({env_values} values)")
    
    return res


def get_source_description(source_part: str) -> tuple[str, str]:
    """Convert source prefix to human-readable type and path/description."""
    source_mapping = {
        ENV_VAR_PREFIX: ("Environment variable", "os.environ"),
        GITHUB_TOKEN_PREFIX: ("GitHub Token", "gh auth token"),
        NPMRC_PREFIX: ("Configuration file", "~/.npmrc"),
    }
    
    if source_part == ENV_FILE_PREFIX:
        # Path will be extracted from secret_part in display_leak function
        return ("Environment file", "")
    elif source_part.startswith(ENV_FILE_PREFIX):
        # source_part format is: ENV_FILE__path_with_encoded_chars
        prefix_with_sep = f"{ENV_FILE_PREFIX}{SOURCE_SEPARATOR}"
        if source_part.startswith(prefix_with_sep):
            encoded_path = source_part[len(prefix_with_sep):]
            filepath = encoded_path.replace("__SLASH__", "/").replace("__DOT__", ".")
        else:
            filepath = source_part.replace(ENV_FILE_PREFIX, "").replace("_", "/")
        return ("Environment file", filepath)
    
    # Handle GitGuardian key name truncation with encoded paths
    if "__SLASH__" in source_part or "__DOT__" in source_part:
        decoded_part = source_part.replace("__SLASH__", "/").replace("__DOT__", ".")
        if not decoded_part.startswith("/"):
            decoded_part = "/" + decoded_part
        
        env_pattern = "/.env"
        if env_pattern in decoded_part:
            env_idx = decoded_part.rfind(env_pattern)
            if env_idx != -1:
                next_part_idx = env_idx + len(env_pattern)
                if next_part_idx < len(decoded_part):
                    remaining = decoded_part[next_part_idx:]
                    if remaining.startswith(".") or remaining.startswith("_"):  # .production or _production
                        next_separator = remaining.find("_", 1) if remaining.startswith("_") else remaining.find("_")
                        if next_separator != -1:
                            filepath = decoded_part[:next_part_idx + next_separator]
                            return ("Environment file", filepath)
                        else:
                            return ("Environment file", decoded_part[:next_part_idx + len(remaining)])
                    else:
                        return ("Environment file", decoded_part[:next_part_idx])
        
        return ("Environment file", decoded_part)
    
    if source_part.startswith("_Users_"):
        filepath = source_part[1:].replace("_", "/")
        return ("Environment file", filepath)
    
    return source_mapping.get(source_part, ("Unknown", source_part))


def display_leak(i: int, leak: dict, source_type: str, source_path: str, secret_part: str, show_secrets: bool = False) -> None:
    """Display a single leaked secret with formatting."""
    print(f"🔑 Secret #{i}")
    print(f"   Name: {secret_part}")
    
    if show_secrets:
        print(f"   ⚠️  Secret Value: {secret_part}")
    
    print(f"   Source: {source_type}")
    print(f"   Path: {source_path}")
    print(f"   Hash: {leak.get('hash', '')}")
    count = leak.get('count', 0)
    print(f"   Locations: {count} distinct Public GitHub repositories")
    if leak.get("url"):
        print(f"   First seen: {leak.get('url')} (only first location shown for security)")
    print()


def gather_all_secrets(timeout: int, verbose: bool = False) -> dict[str, str]:
    all_values = {}
    
    env_vars = 0
    for value in os.environ.values():
        key = f"{ENV_VAR_PREFIX}{SOURCE_SEPARATOR}{value}"
        all_values[key] = value
        env_vars += 1
    
    if verbose:
        print(f"   ├─ Environment variables: {env_vars} found")
    else:
        print(f"\r   ├─ Environment variables: {env_vars} found", end="", flush=True)
        print()
    
    gh_token = handle_github_token_command()
    github_found = False
    if gh_token:
        key = f"{GITHUB_TOKEN_PREFIX}{SOURCE_SEPARATOR}{gh_token}"
        all_values[key] = gh_token
        github_found = True
    
    if github_found:
        if verbose:
            print(f"   ├─ GitHub token: found")
        else:
            print(f"\r   ├─ GitHub token: found", end="", flush=True)
            print()
    else:
        if verbose:
            print(f"   ├─ GitHub token: not found")
        else:
            print(f"\r   ├─ GitHub token: not found", end="", flush=True)
            print()
    
    file_values = gather_files_by_patterns(timeout, verbose)
    all_values.update(file_values)
    
    return all_values


def find_leaks(args):
    if shutil.which("ggshield") is None:
        print(
            "Please install ggshield first, see https://github.com/GitGuardian/ggshield#installation"
        )
        sys.exit(1)

    print("🔍 S1ngularity Scanner - Detecting leaked secrets")
    print("🔒 All processing occurs locally, no secrets transmitted")
    
    if args.show_secrets:
        print()
        print("⚠️  🚨 SECURITY WARNING 🚨")
        print("⚠️  --show-secrets is enabled: actual secret values will be displayed!")
        print("⚠️  These values will remain in your terminal history and logs.")
        print("⚠️  Only use this option in secure environments for debugging purposes.")
        print("⚠️  Consider clearing your terminal history after use.")
        print()
    if args.verbose:
        print()
        timeout_desc = f"{args.timeout}s" if args.timeout > 0 else "unlimited"
        keep_desc = "yes" if args.keep_temp_file else "no"
        show_secrets_desc = "yes" if args.show_secrets else "no"
        print(f"⚙️  Settings: min-chars={args.min_chars}, timeout={timeout_desc}, keep-temp-file={keep_desc}, max-public-occurrences={args.max_public_occurrences}, show-secrets={show_secrets_desc}")
        print()

    if args.verbose:
        timeout_desc = f"timeout: {args.timeout}s" if args.timeout > 0 else "no timeout"
        print(f"📁 Scanning system ({timeout_desc})...")
    
    values_with_sources = gather_all_secrets(args.timeout, args.verbose)
    
    if args.verbose:
        print()

    selected_items = [(k, v) for k, v in values_with_sources.items() if v is not None and len(v) >= args.min_chars]
    total_values = len(values_with_sources)
    filtered_count = total_values - len(selected_items)

    if filtered_count > 0:
        print(f"🔍 Checking {len(selected_items)} values against public leak database ({filtered_count} filtered, < {args.min_chars} chars)...")
    else:
        print(f"🔍 Checking {len(selected_items)} values against public leak database...")
    
    secrets_file = Path(SECRETS_FILE_NAME)
    env_content = "\n".join([f"{k}={v}" for k, v in selected_items])
    secrets_file.write_text(env_content)
    result = sp.run(["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "--type", "env", "-n", "key", "--json"], stdout=sp.PIPE, stderr=sp.DEVNULL, text=True)
    
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            total_leak_count = data.get("leaks_count", 0)
            selected_leaks = [
                leak for leak in data.get("leaks", [])
                if leak.get("count", 0) < args.max_public_occurrences
            ]
            leak_count = len(selected_leaks)
            filtered_count = total_leak_count - leak_count

            if filtered_count > 0:
                print(f"ℹ️  Filtered out {filtered_count} leak{'s' if filtered_count > 1 else ''} with high public occurrence count (≥{args.max_public_occurrences})")

            if leak_count > 0:
                print(f"⚠️  Found {leak_count} leaked secret{'s' if leak_count > 1 else ''}")
                print()
                for i, leak in enumerate(selected_leaks, 1):
                    key_name = leak.get("name", "")
                    if SOURCE_SEPARATOR in key_name:
                        source_part, secret_part = key_name.split(SOURCE_SEPARATOR, 1)
                        source_type, source_path = get_source_description(source_part)
                        
                        
                        # Special handling for ENV_FILE where encoded path+secret is in secret_part
                        if source_part == ENV_FILE_PREFIX and source_path == "":
                            encoded_patterns = [
                                "__SLASH____DOT__env__DOT__production__",
                                "__SLASH____DOT__env__DOT__test__", 
                                "__SLASH____DOT__env__"
                            ]
                            
                            for pattern in encoded_patterns:
                                if pattern in secret_part:
                                    parts = secret_part.split(pattern, 1)
                                    if len(parts) == 2:
                                        filepath_encoded = parts[0] + pattern.rstrip("__")  # Keep the .env part
                                        actual_secret = parts[1]
                                        
                                        # Decode the filepath
                                        decoded_filepath = filepath_encoded.replace("__SLASH__", "/").replace("__DOT__", ".")
                                        if not decoded_filepath.startswith("/"):
                                            decoded_filepath = "/" + decoded_filepath
                                        
                                        source_path = decoded_filepath
                                        secret_part = actual_secret
                                        break
                        display_leak(i, leak, source_type, source_path, secret_part, args.show_secrets)
                print("💡 Note: Results may include false positives (non-secret values matching leak patterns).")
                print("   Always verify results before taking action. If confirmed as real secrets:")
                print("   1. Immediately revoke and rotate the credential")
                print("   2. Review when the leak occurred and what systems may be compromised")
                
                if args.show_secrets:
                    print()
                    print("⚠️  🚨 SECURITY REMINDER 🚨")
                    print("⚠️  Actual secret values were displayed above!")
                    print("⚠️  Consider clearing your terminal history: history -c && history -w")
                    print("⚠️  Be careful when sharing terminal output or logs.")
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
        default=0
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed scanning progress and debug information"
    )
    parser.add_argument(
        "--max-public-occurrences",
        type=int,
        help="Maximum number of public occurrences for a leak to be reported (default: 10)",
        default=10,
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="⚠️  SECURITY WARNING: Show actual secret values in output (leaves secrets in terminal history)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    find_leaks(args)
