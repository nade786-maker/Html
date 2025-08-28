# S1ngularity Scanner

A defensive security tool to detect potential compromise from the Nx "s1ngularity" supply chain attack.

## About the Attack

The [Nx s1ngularity attack](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/) was a sophisticated supply chain attack that compromised JavaScript developers through malicious packages in the Nx ecosystem. The attack targeted valuable credentials including:

- GitHub tokens and SSH keys
- npm authentication tokens  
- Environment variables containing API keys
- Cryptocurrency wallet files
- LLM client configurations (Claude, Gemini, ChatGPT)

Stolen credentials were exfiltrated to public GitHub repositories, resulting in over 2,300 distinct secrets being leaked from more than 1,000 compromised systems.

## Scanner Purpose

This project does not rely on the GitGuardian Secrets API, ensuring that no secrets are transmitted to GitGuardian or any third-party service. As a result, you maintain full control over your data. However, this may lead to a higher rate of false positives. Instead, this project relies on [HasMySecretLeaked](https://www.gitguardian.com/hasmysecretleaked). To learn more about how this works, visit our [What happens under the hood](https://docs.gitguardian.com/ggshield-docs/reference/hmsl/overview#what-happens-under-the-hood) page.

## Requirements

- **Python ≥3.9** (enforced at runtime)
- **[ggshield](https://github.com/GitGuardian/ggshield)** - GitGuardian's CLI tool for secret scanning
- **[GitHub CLI](https://cli.github.com/)** (optional) - for extracting GitHub tokens

## Installation

### Install ggshield

**macOS:**
```bash
# Using Homebrew (recommended)
brew install ggshield

# Or download standalone .pkg from GitHub releases (no Python required)
```
📦 [Download .pkg from GitHub releases](https://github.com/GitGuardian/ggshield/releases)

**Linux:**
```bash
# Using pipx (recommended)
pipx install ggshield

# Or use distribution packages (deb/rpm) from Cloudsmith
```
📦 [Download packages from Cloudsmith](https://cloudsmith.io/~gitguardian/repos/ggshield/setup/)

**Windows:**
```bash
# Using Chocolatey
choco install ggshield

# Or download standalone .zip from GitHub releases (no Python required)
```
📦 [Download .zip from GitHub releases](https://github.com/GitGuardian/ggshield/releases)

For more installation options, see the [ggshield documentation](https://github.com/GitGuardian/ggshield#installation).

### Run the Scanner

**macOS/Linux:**
```bash
git clone https://github.com/GitGuardian/s1ngularity-scanner
cd s1ngularity-scanner

# With uv (if available)
./leak_scanner.py

# Or with Python directly
python3 leak_scanner.py
```

**Windows:**
```bash
git clone https://github.com/GitGuardian/s1ngularity-scanner
cd s1ngularity-scanner
python leak_scanner.py
```

## Command Line Options

- `--min-chars <number>` - Minimum character length for values to consider (default: 5)
- `--keep-found-values` - Keep the temporary file containing gathered values instead of deleting it
- `--timeout <seconds>` - Maximum time to spend scanning filesystem for .env files (default: 30)

## How it works

Singularity Scanner uses environment variables and files, including files known to be used by the original exploit. We don't reuse the prompt as our analysis showed the AI didn't actually provide many files. Instead, the scanner directly targets known file locations and scans them for secrets. These secrets are hashed and compared against what GitGuardian found on GitHub.

The scanner collects potential secrets from these sources:
- **All environment variables** from the current shell session
- **GitHub token** from `gh auth token` command (if GitHub CLI is installed)
- **NPM configuration** from `$HOME/.npmrc`
- **Environment files** - all `.env*` files recursively found in your home directory
  - Skips hidden directories (starting with `.`) and `node_modules` for performance
  - Has a configurable timeout to prevent long scans on large filesystems

## Security & Privacy

- **No data transmission**: Secrets are never sent to GitGuardian or any external service
- **Local processing**: All scanning happens locally on your machine
- **Hash comparison**: Only SHA-256 hashes of potential secrets are compared against GitGuardian's database
- **Temporary files**: A temporary file `gg_gathered_values` is created during scanning and automatically deleted (unless `--keep-found-values` is used)

## Examples

Basic scan with default settings:
```bash
./leak_scanner.py
# or: python3 leak_scanner.py
```

Scan with longer timeout for large filesystems:
```bash
./leak_scanner.py --timeout 120
```

Keep the temporary file for inspection:
```bash
./leak_scanner.py --keep-found-values
```

Only consider longer values (reduces noise):
```bash
./leak_scanner.py --min-chars 10
```

## Limitations

- **No AI queries**: Unlike the original exploit, we don't ask Claude, Gemini or Q for files that may contain secrets
- **Filesystem timeout**: Large filesystems may not be fully scanned within the default 30-second timeout
- **Directory exclusions**: Hidden directories (`.git`, `.cache`, etc.) and `node_modules` are skipped for performance
- **Pattern matching**: Only detects key-value assignments in standard formats (may miss unconventional secret storage)
- **False positives**: May flag legitimate non-secret values that happen to match secret patterns
