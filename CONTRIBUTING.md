# Contributing to PsyLinks 360° Security

Thank you for helping improve this security skill. Contributions should make the skill more accurate, more actionable, or easier to install and verify.

## Before opening an issue

Please search existing issues first. Do not disclose secrets, private vulnerability details, or information about systems you do not own. Use the private reporting process in [`SECURITY.md`](./SECURITY.md) for vulnerabilities in this tool.

## Development setup

The scanner uses only the Python standard library:

```bash
python3 -m py_compile scripts/scan.py
python3 scripts/scan.py . --no-network --no-audit --json
```

If you change the scanner, also verify that the packaged skill remains valid:

```bash
unzip -t psylinks-360-security.skill
```

## Pull requests

Explain the problem, the user impact, the change, and how you tested it. Keep security claims specific. Do not describe the tool as a replacement for a professional audit or penetration test.

Changes to detection rules should include a reproducible example or a clear explanation of the expected match and false-positive trade-off. Changes to the skill instructions should preserve the distinction between scanner evidence, manual review, and items outside the skill's coverage.

By submitting a contribution, you agree that it may be used under the repository's [`LICENSE.md`](./LICENSE.md).
