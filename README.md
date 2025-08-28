# S1ngularity Scanner

This is a simple tool to scan for files compromised ["s1ngularity" attack](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/). 

This project does not rely on the GitGuardian Secrets API, ensuring that no secrets are transmitted to GitGuardian or any third-party service. As a result, you maintain full control over your data. However, this may lead to a higher rate of false positives. Instead, this project relies on [HasMySecretLeaked](https://www.gitguardian.com/hasmysecretleaked). To learn more about how this works, visit our [What happens under the hood](https://docs.gitguardian.com/ggshield-docs/reference/hmsl/overview#what-happens-under-the-hood) page.

## Usage

You need [ggshield](https://github.com/GitGuardian/ggshield) and Python >=3.9 to run this script.

```bash
git clone https://github.com/gitguardian/s1ngularity-scanner
python s1ngularity-scanner/leak_scanner.py
```

## How it works

Singularity Scanner reuses the prompt from the attack to extract compromised files. It then scans the files found for secrets. These secrets are hashed compared against what GitGuardian found on GitHub.
Singularity Scanner scans your laptop for the following files and tokens:
- GitHub token from `gh auth token` command
- `$HOME/.npmrc`
- `$HOME/**/.env*`

## Limitations

Unlike the original exploit, we don't ask Claude, Gemini or Q for the files that may contain secrets.
