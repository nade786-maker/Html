# Agent Development Guide

This document contains essential knowledge for AI agents working effectively with the s1ngularity-scanner codebase.

## Project Overview

A defensive security tool to detect credentials compromised in the Nx "s1ngularity" supply chain attack. The scanner uses GitGuardian's HasMySecretLeaked (HMSL) API to check for leaked secrets without transmitting actual secret values.

## Architecture

### Core Components
- **Environment scanning**: Collects values from `os.environ`
- **GitHub token extraction**: Uses `gh auth token` if available
- **File discovery**: `os.walk()` traversal with directory pruning for `.env*` and `.npmrc` files
- **Secret detection**: Pattern matching with `extract_assigned_values()`
- **Leak checking**: `ggshield hmsl check` with secure hashing (GitGuardian's HasMySecretLeaked API)

### Key Functions
- `gather_all_secrets()`: Orchestrates collection from all sources
- `gather_files_by_patterns()`: Optimized filesystem traversal using `os.walk()`
- `indices_to_delete()` + `select_file()`: Performance helpers for directory pruning
- `find_leaks()`: Main entry point with UX orchestration

### HMSL (HasMySecretLeaked) Technical Details
- **Database**: 22+ million unique secrets from GitHub public repositories since 2017
- **Privacy-preserving**: Only SHA-256 hash prefixes (first 5 hex chars) are sent to GitGuardian
- **Result interpretation**: "Locations: X distinct" means X different GitHub repositories, but only first location shown for security
- **False positives**: Legitimate values matching secret patterns are common - always require manual verification
- **Limitations**: Only detects leaks from GitHub public repositories, not other platforms
- **Rate limits**: 5 queries/day for unauthenticated users

## Development Practices

### Performance Optimization
- Use `os.walk()` with dynamic directory pruning instead of `rglob()` (72% faster)
- Skip hidden directories (`.git`, `.cache`) and `node_modules` during traversal
- Check timeouts efficiently: `timeout > 0 and elapsed > timeout` (fixes timeout=0 bug)

### UX Implementation
- **Progress indicators**: Use Unicode spinner chars `['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧']`
- **Real-time feedback**: Update every 0.2s during directory traversal, every 3 files for progress
- **Tree-style output**: `├─` and `└─` for hierarchical progress display
- **Dual modes**: Compact (carriage return `\r`) vs verbose (newlines) output

### Code Organization
- Keep function signatures compatible for upstream merging
- Use existing naming conventions (`gather_files_by_patterns` not `gather_files_with_walk`)
- Integrate performance optimizations into existing function structure
- Follow defensive security principles: no actual secrets transmitted

## Testing & QA

### Terminal Output Validation
**Challenge**: AI agents cannot directly observe real-time terminal animations (spinners, carriage return updates).

**Solution**: Use the `script` command to capture and analyze terminal behavior:
```bash
script typescript.log ./leak_scanner.py --timeout 5
# Fallback: script typescript.log python3 leak_scanner.py --timeout 5
```

**Key insight**: Carriage return (`\r`) animations work correctly in real terminals but appear concatenated in captured output. This is expected behavior - the animations are working properly for end users.

### Performance Testing
```bash
time ./leak_scanner.py --timeout 0  # Unlimited scan
# Fallback: time python3 leak_scanner.py --timeout 0
```

### Test Cases for Agents
- `--timeout 0`: Unlimited scanning (verify no immediate exit)
- `--timeout 5`: Short timeout (verify graceful timeout handling)
- `--verbose`: Detailed output mode
- Both modes should show identical final counts
- Terminal animation testing using `script` command

## Command Line Interface

### Arguments
- `--timeout N`: Seconds before timeout (0 = unlimited, default: 30)
- `--verbose, -v`: Show detailed scanning progress
- `--min-chars N`: Minimum value length (default: 5)
- `--keep-found-values`: Retain temporary file

### Help Format
Follow pattern: `-v, --verbose` (short first, matches `-h, --help`)

## Security Considerations

### Data Privacy
- **No secrets transmitted**: Only SHA-256 hashes sent to GitGuardian
- **Local processing**: All scanning happens on user's machine
- **Temporary files**: Auto-cleanup unless `--keep-found-values` specified
- **Source tracking**: Encode source info in dictionary keys for traceability

### Error Handling
- Graceful file read failures (permissions, encoding issues)
- Timeout handling without data loss
- Clean exit on Ctrl+C (`KeyboardInterrupt`)

## Common Patterns

### Progress Display Pattern
```python
# Non-verbose: carriage return for in-place updates (appears animated to users)
print(f"\r{spinner} Status...", end="", flush=True)

# Verbose: newlines for detailed logging (better for agents to parse)
print(f"{spinner} Detailed status...")
```

### Timeout Pattern
```python
if timeout > 0 and (time.time() - start_time) > timeout:
    # Handle timeout gracefully
    return results  # Don't lose partial results
```

### Source Tracking Pattern
```python
key = f"{SOURCE_PREFIX}{SOURCE_SEPARATOR}{value}"
all_values[key] = value
```

## Agent-Specific Considerations

### Task Management
- Use appropriate task tracking tools when available (e.g., TodoWrite for Claude)
- Break complex changes into discrete, testable steps
- Mark tasks completed only when fully verified

### Commit Message Guidelines
- Use conventional commit format: `type(scope): description` (e.g., `feat: add timeout handling`, `fix: resolve timeout=0 bug`)
- Never mention yourself as an AI agent in commit messages - write as if authored by a human developer
- Focus on what the change accomplishes, not who or what created it

### Code Modification Strategy
- Prefer enhancing existing functions over creating new ones for merge compatibility
- Test both `--verbose` and default modes after changes
- Verify timeout handling with `--timeout 0` and short timeout values
- Use performance testing to validate optimizations

### Terminal Output Interpretation
- Concatenated spinner output in captured logs indicates working animations
- Focus on final results and completion messages for validation
- Use verbose mode for detailed operation verification

## Dependencies

- **Python ≥3.9**: Enforced at runtime
- **ggshield**: Required for HMSL checking
- **gh CLI**: Optional for GitHub token extraction
- **Standard library only**: No external Python dependencies

## Execution Commands for Agents

**Preferred: Use uv when available**
```bash
./leak_scanner.py --timeout 5
./leak_scanner.py --verbose
```

**Fallback: Direct Python execution**
```bash
python3 leak_scanner.py --timeout 5    # macOS/Linux
python leak_scanner.py --timeout 5     # Windows
```

**Why prefer uv:**
- Automatic dependency isolation and Python version management
- Consistent execution environment across systems
- Modern Python tooling standard
- Handles PEP 723 script metadata automatically

### Standard Testing (prefer uv)
```bash
# Basic functionality tests
./leak_scanner.py --timeout 5
./leak_scanner.py --timeout 0    # Unlimited scanning
./leak_scanner.py --verbose      # Detailed output

# Performance testing
time ./leak_scanner.py --timeout 0

# Terminal behavior testing
script typescript.log ./leak_scanner.py --timeout 5

# Code formatting
uv tool run black leak_scanner.py
```

### Fallback Commands (when uv unavailable)
```bash
# macOS/Linux
python3 leak_scanner.py --timeout 5
python3 leak_scanner.py --verbose
time python3 leak_scanner.py --timeout 0

# Windows
python leak_scanner.py --timeout 5
python leak_scanner.py --verbose
```
