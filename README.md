# PsyLinks 360° Security

**A security skill for Claude, Claude Code, and other AI-assisted development workflows, with a built-in static scanner for common application-security problems.**

Built by **PsyLinks Security Private Limited** — [psylinksssecurity.com](https://psylinksssecurity.com)

> This repository contains the skill source, reference checklists, scanner, and a packaged `.skill` artifact. Read the license before using or redistributing the contents.

## What it does

PsyLinks 360° Security makes security review a default part of AI-assisted software development. The skill is designed to trigger when work involves authentication, APIs, databases, backend services, secrets, payments, file uploads, dependencies, deployment, or AI-agent/MCP workflows with file, shell, or network access.

It provides:

- Secure-by-default guidance for login, signup, password reset, sessions, APIs, databases, and backend services.
- An adversarial self-audit gate for authorization, business-logic abuse, prompt injection, and tool-permission risks.
- A standard security report format that distinguishes verified controls from items requiring follow-up.
- A Python 3 static scanner for high-signal patterns including hardcoded secrets, insecure configuration, weak cryptography, injection sinks, unsafe cookie handling, dependency audits, and package-existence checks.
- Reference checklists for authentication, API security, backend and infrastructure security, AI-agent risks, and OWASP Top 10:2025 mapping.

The scanner is evidence-gathering support, not a full SAST product, penetration test, threat model, or compliance assessment.

## Installation

### Option A: Install the packaged skill in Claude

1. Download [`psylinks-360-security.skill`](./psylinks-360-security.skill) from this repository. On GitHub, open the file and use **Download raw**, or download it from the repository's Releases page when a release is published.
2. In Claude, open the skills management interface and choose **Add skill** or **Upload skill**.
3. Select the downloaded `.skill` file.
4. Start a new coding task. The skill will apply when the task matches its security triggers.

If your Claude client does not accept `.skill` uploads, use Option B and add the repository's `SKILL.md` as project or workspace instructions.

### Option B: Use the source with Claude Code or another AI coding tool

Clone the repository and place the skill directory where your tool loads project skills or instructions:

```bash
git clone https://github.com/PsylinksSecurityWeb/PsyLinks-360-Security.git
cd PsyLinks-360-Security
```

The skill definition is [`SKILL.md`](./SKILL.md). Keep the `references/` directory and `scripts/` directory alongside it; the skill links to those files. For tools that load skills from a directory, use the repository root as the skill directory. For tools that use project instructions, include the contents of `SKILL.md` and preserve the linked paths.

Because AI tools differ in how they discover instructions, consult the documentation for your specific tool. Do not assume that copying `SKILL.md` into an arbitrary folder automatically activates it.

### Option C: Use only the scanner

The scanner is stdlib-only and needs Python 3. Run it from a checkout of this repository:

```bash
python3 scripts/scan.py /path/to/your/project
```

For machine-readable output:

```bash
python3 scripts/scan.py /path/to/your/project --json
```

Useful offline and deterministic options:

```bash
python3 scripts/scan.py /path/to/your/project --no-network --no-audit
```

The scanner does not rewrite code. Review each finding, make the fix in the project, and run the same scan again before treating an issue as resolved.

## Free and Pro coverage

Without a license key, the scanner runs its Free tier: hardcoded-secret and insecure-configuration checks. A valid PsyLinks license key enables the Pro pattern set, dependency auditing, and package-registry verification:

```bash
python3 scripts/scan.py /path/to/your/project --license-key PSYL-xxxx
# or
PSYLINKS_LICENSE_KEY=PSYL-xxxx python3 scripts/scan.py /path/to/your/project
```

The scanner may contact the PsyLinks license endpoint when a key is supplied. If that service is unreachable, the script has an explicitly limited offline-grace behavior; this is not a technical access-control boundary. See [`SKILL.md`](./SKILL.md) and [`LICENSE.md`](./LICENSE.md) for the licensing model.

## Repository layout

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Main AI skill instructions and security-review workflow |
| `references/` | Focused security checklists and OWASP mapping |
| `scripts/scan.py` | Stdlib-only static and optional dependency scanner |
| `psylinks-360-security.skill` | Packaged skill artifact for clients that support `.skill` uploads |
| `SECURITY.md` | Private vulnerability-reporting policy |
| `LICENSE.md` | Usage and redistribution terms |

## Responsible use

Only scan code and systems that you own or are authorized to test. This tool catches known patterns and cannot establish that an application is secure. Before handling real user data, payments, or production traffic, obtain appropriate human review and, where needed, a professional application-security assessment, penetration test, infrastructure review, and compliance review.

## Contributing and reporting issues

Please read [`SECURITY.md`](./SECURITY.md) before reporting a security issue in this tool. Do not publish sensitive vulnerability details in a public issue.

## License

Copyright © PsyLinks Security Private Limited. All rights reserved. Use is governed by [`LICENSE.md`](./LICENSE.md). In particular, do not redistribute, resell, sublicense, or repackage this skill as your own product.

## Contact

- Website: [psylinksssecurity.com](https://psylinksssecurity.com)
- Security reports: [security@psylinksssecurity.com](mailto:security@psylinksssecurity.com)
