# PsyLinks 360° Security

[![Validate skill](https://github.com/PsylinksSecurityWeb/PsyLinks-360-Security/actions/workflows/validate.yml/badge.svg)](https://github.com/PsylinksSecurityWeb/PsyLinks-360-Security/actions/workflows/validate.yml) [![Latest release](https://img.shields.io/github/v/release/PsylinksSecurityWeb/PsyLinks-360-Security?display_name=tag)](https://github.com/PsylinksSecurityWeb/PsyLinks-360-Security/releases) [![License](https://img.shields.io/badge/license-proprietary-lightgrey)](./LICENSE.md)

**A security skill for Claude, Claude Code, and other AI-assisted development workflows, with a built-in static scanner for common application-security problems.**

Built by **PsyLinks Security Private Limited** — [psylinksssecurity.com](https://psylinksssecurity.com)

> **Fast path:** download [`psylinks-360-security.skill`](./psylinks-360-security.skill) for a supported Claude upload workflow, or clone this repository and install the canonical skill directory with the command below.

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

### Claude upload

1. Download [`psylinks-360-security.skill`](./psylinks-360-security.skill).
2. In Claude, open the skills management interface and choose **Add skill** or **Upload skill**.
3. Select the downloaded file and start a coding task that matches the skill description.

If your Claude client does not accept `.skill` uploads, use the source installation below.

### Claude Code: personal installation

Claude Code discovers skills from `~/.claude/skills/<skill-name>/SKILL.md`. The repository includes the canonical project layout at `.claude/skills/psylinks-360-security/`:

```bash
git clone https://github.com/PsylinksSecurityWeb/PsyLinks-360-Security.git
cd PsyLinks-360-Security
mkdir -p ~/.claude/skills/psylinks-360-security
cp -R .claude/skills/psylinks-360-security/. ~/.claude/skills/psylinks-360-security/
cp -R references scripts SKILL.md LICENSE.md SECURITY.md ~/.claude/skills/psylinks-360-security/
```

Start Claude Code in a project and test automatic invocation with a request such as: `Review this API for security issues.` You can also invoke the skill directly with `/psylinks-360-security` when your Claude Code version exposes it as a slash command.

### Claude Code: project installation

To share the skill with a team working in one repository, copy the canonical directory into that project's `.claude/skills/` folder and commit it:

```bash
mkdir -p .claude/skills
cp -R /path/to/PsyLinks-360-Security/.claude/skills/psylinks-360-security .claude/skills/
```

Keep the referenced `SKILL.md`, `references/`, and `scripts/` files beside the installed skill, or adapt the entry point to your team's layout. See the [Claude Code skills documentation](https://code.claude.com/docs/en/skills) for the supported scopes and invocation behavior.

### Other AI coding tools

For tools that support Agent Skills, use the repository root as the skill directory or follow that tool's documented skill path. For tools that use project instructions instead, include the contents of [`SKILL.md`](./SKILL.md) and preserve its linked resources. AI tools differ in discovery behavior; copying a file into an arbitrary folder does not automatically activate it.

### Scanner-only use

The scanner is stdlib-only and needs Python 3:

```bash
python3 scripts/scan.py /path/to/your/project
python3 scripts/scan.py /path/to/your/project --json
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
| `.claude/skills/psylinks-360-security/` | Canonical Claude Code project-skill entry point |
| `references/` | Focused security checklists and OWASP mapping |
| `scripts/scan.py` | Stdlib-only static and optional dependency scanner |
| `psylinks-360-security.skill` | Packaged skill artifact for clients that support `.skill` uploads |
| `.github/workflows/validate.yml` | Automated syntax, self-scan, and artifact validation |
| `CONTRIBUTING.md` | Contribution and testing guidance |
| `SECURITY.md` | Private vulnerability-reporting policy |
| `LICENSE.md` | Usage and redistribution terms |

## Responsible use

Only scan code and systems that you own or are authorized to test. This tool catches known patterns and cannot establish that an application is secure. Before handling real user data, payments, or production traffic, obtain appropriate human review and, where needed, a professional application-security assessment, penetration test, infrastructure review, and compliance review.

## Contributing and reporting issues

Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before opening a pull request. Use the issue templates for reproducible bugs and feature requests. Do not publish sensitive vulnerability details in a public issue; follow [`SECURITY.md`](./SECURITY.md) instead.

## Changelog and releases

See [`CHANGELOG.md`](./CHANGELOG.md) for user-visible changes and the [releases page](https://github.com/PsylinksSecurityWeb/PsyLinks-360-Security/releases) for versioned downloads.

## License

Copyright © PsyLinks Security Private Limited. All rights reserved. Use is governed by [`LICENSE.md`](./LICENSE.md). In particular, do not redistribute, resell, sublicense, or repackage this skill as your own product.

## Contact

- Website: [psylinksssecurity.com](https://psylinksssecurity.com)
- Security reports: [security@psylinksssecurity.com](mailto:security@psylinksssecurity.com)
