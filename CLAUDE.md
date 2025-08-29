# Claude Development Guide

This document contains Claude-specific guidance for the s1ngularity-scanner project.

## Agent Documentation

For comprehensive development guidance, see [AGENTS.md](./AGENTS.md) which contains detailed information about:

- Project architecture and core components
- Development practices and optimization techniques  
- Testing strategies including terminal output validation
- Security considerations and best practices
- Common code patterns and CLI conventions

## Claude-Specific Notes

When working with this codebase:

1. **Use TodoWrite tool** for task tracking during multi-step implementations
2. **Test terminal animations** using the `script` command technique documented in AGENTS.md
3. **Prefer existing function names** when adding optimizations for easier upstream merging
4. **Follow defensive security principles** - never transmit actual secrets, only hashes

## Quick Commands

```bash
# Standard scan
python3 leak_scanner.py

# Performance test
time python3 leak_scanner.py --timeout 0

# Debug mode
python3 leak_scanner.py --verbose

# Terminal output testing  
script test.log python3 leak_scanner.py --timeout 5
```