import re
import os
import argparse
import subprocess as sp
import shutil
from pathlib import Path
import sys
import glob
import time

if sys.version_info < (3, 9):
    print("Invalid python version, use a version >= 3.9")
    sys.exit(1)

SECRETS_FILE_NAME = "gg_gathered_values"

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


def indices_to_delete(dirnames: list[str]):
    res = []
    for i, name in enumerate(dirnames):
        if name.startswith("."):
            res.append(i)
        if name == "node_modules":
            res.append(i)
    return res


def gather_dotenv_values_with_walk(timeout: int) -> set[str]:
    home = Path().home()
    res = set()
    start_time = time.time()
    for root, dirs, files in os.walk(home):
        nb_deleted = 0
        for ind in indices_to_delete(dirs):
            del dirs[ind - nb_deleted]
            nb_deleted += 1
        for file in files:
            if file.startswith('.env'):
                fpath = Path(root) / file
                try:
                    text = fpath.read_text()
                except Exception:
                    print(f"Failed reading {fpath}")
                    continue
                res.update(extract_assigned_values(text))
                print(f"Read values from {fpath}")
        if time.time() - start_time > timeout:
            print(f"Timeout of {timeout}s reached while searching for .env files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option")
            return res
    return res


def gather_specific_files_values() -> set[str]:
    res = set()
    home = Path().home()
    for path in [home / ".npmrc"]:
        if not path.is_file():
            continue
        try:
            text = path.read_text()
        except Exception:
            continue
        res.update(extract_assigned_values(text))
    return res


def gather_all_secrets(timeout: int):
    all_values = set(os.environ.values())
    gh_token = handle_github_token_command()
    if gh_token:
        all_values.add(gh_token)
    all_values.update(gather_specific_files_values())
    all_values.update(gather_dotenv_values_with_walk(timeout))
    return all_values


def find_leaks(args):
    if shutil.which("ggshield") is None:
        print(
            "Please install ggshield first, see https://github.com/GitGuardian/ggshield#installation"
        )
        sys.exit(1)

    print("Collecting potential values, this may take some time...")

    values = gather_all_secrets(args.timeout)

    selected_values = [v for v in values if v is not None and len(v) >= args.min_chars]

    print(f"Found {len(selected_values)} values")
    secrets_file = Path(SECRETS_FILE_NAME)
    secrets_file.write_text("\n".join(selected_values))
    print(f"Saved values to file {SECRETS_FILE_NAME}")
    sp.run(["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "-n", "cleartext"])
    if not args.keep_found_values:
        os.remove(SECRETS_FILE_NAME)
        print(f"Deleted file {SECRETS_FILE_NAME}")


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
