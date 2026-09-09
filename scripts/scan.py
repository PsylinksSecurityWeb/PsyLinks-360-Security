#!/usr/bin/env python3
"""
PsyLinks 360 Security Scanner
------------------------------
Copyright (c) PsyLinks Security Private Limited. See LICENSE.md. Free-tier
local checks are provided as-is. Pro-tier detection (expanded pattern set,
package/dependency checks, and live threat-intel updates) requires a
PsyLinks license key — see the licensing section below. This keeps
PsyLinks 360° Security's ongoing value (an updated rule set and threat
intelligence) server-side rather than shipped inside this file, since a
plain-text file readable by an AI assistant can always be read by a human
too — there is no way around that, and this script does not pretend
otherwise.

Static + dependency scan for the vulnerability classes covered by the
psylinks-360-security skill. Stdlib-only (no install required). Optionally
shells out to npm audit / pip-audit if present, and can verify package
names against public registries (pypi.org / registry.npmjs.org) to catch
hallucinated/typosquatted dependencies.

Usage:
    python3 scan.py [path] [--json] [--no-network] [--no-audit]
                     [--license-key KEY]

License key can also be supplied via the PSYLINKS_LICENSE_KEY env var.
Without a valid key, the scanner runs in Free tier: secrets + insecure
config checks only. A licensed key unlocks the full Pro-tier pattern set
(crypto, injection, cookies), dependency audit, and package-registry
verification.

Output: a severity-tagged findings report (human-readable by default,
--json for structured output the caller can parse and act on).

This script FLAGS issues. It intentionally does not auto-rewrite code —
fixes should be made contextually by the caller (Claude) and confirmed
by re-running this scan, since automated regex-based rewriting of
security-relevant code is itself risky.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error

LICENSE_VALIDATE_URL = "https://api.psylinksssecurity.com/v1/license/validate"  # point at your real endpoint once it's live

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".cache", "vendor", "target", ".mypy_cache", ".pytest_cache",
    "coverage", ".tox", "egg-info",
}

TEXT_EXT_ALLOW = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java",
    ".rs", ".c", ".cpp", ".h", ".hpp", ".cs", ".sh", ".yml", ".yaml",
    ".json", ".env", ".txt", ".toml", ".ini", ".cfg", ".conf", ".sql",
    ".html", ".htm", ".vue", ".svelte",
}

MAX_FILE_BYTES = 2_000_000  # skip huge/generated files

# ---------------------------------------------------------------------------
# Pattern definitions: (id, severity, category, regex, message)
# ---------------------------------------------------------------------------
PATTERNS = [
    # --- Secrets ---
    ("SEC-AWS-KEY", "CRITICAL", "secrets",
     r"AKIA[0-9A-Z]{16}",
     "Looks like an AWS Access Key ID."),
    ("SEC-PRIVATE-KEY", "CRITICAL", "secrets",
     r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
     "Private key material committed to a file."),
    ("SEC-STRIPE", "CRITICAL", "secrets",
     r"sk_live_[0-9a-zA-Z]{16,}",
     "Looks like a live Stripe secret key."),
    ("SEC-SLACK", "CRITICAL", "secrets",
     r"xox[baprs]-[0-9A-Za-z-]{10,}",
     "Looks like a Slack token."),
    ("SEC-GH-TOKEN", "CRITICAL", "secrets",
     r"gh[pousr]_[0-9A-Za-z]{20,}",
     "Looks like a GitHub personal access token."),
    ("SEC-GENERIC-ASSIGN", "HIGH", "secrets",
     r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|db[_-]?password|password)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
     "Hardcoded credential-looking assignment. Move to env var / secrets manager."),
    ("SEC-DOTENV-COMMITTED", "HIGH", "secrets",
     r"^",  # placeholder, handled specially by filename check below
     "A .env-style file appears to be present in the scanned tree."),

    # --- Weak crypto ---
    ("CRYPTO-MD5-PW", "HIGH", "crypto",
     r"(?i)(md5|sha1)\([^)]*(pass(word)?|pwd)",
     "MD5/SHA1 used near password handling — use bcrypt/scrypt/Argon2id instead."),
    ("CRYPTO-MD5-GENERIC", "MEDIUM", "crypto",
     r"(?i)\bhashlib\.md5\(|\bhashlib\.sha1\(",
     "MD5/SHA1 in use — fine for non-security checksums only; never for passwords/tokens."),

    # --- Injection ---
    ("SQLI-STRING-FORMAT", "HIGH", "injection",
     r"(?i)(execute|query|cursor\.execute)\s*\(\s*(f['\"]|['\"].*%s.*['\"]\s*%|['\"].*\+)",
     "Possible SQL built via string formatting/concatenation — use parameterized queries."),
    ("SQLI-STRING-BUILD", "HIGH", "injection",
     r"""(?i)(select\s+.*from|insert\s+into|update\s+\w+\s+set|delete\s+from)\s+[^;]*['"]\s*\+|f['"](select|insert|update|delete)\s""",
     "SQL string appears to be built via concatenation/f-string — use parameterized queries even if not passed to execute() on this line."),
    ("CMDI-OS-SYSTEM", "HIGH", "injection",
     r"(?i)\bos\.system\(|\bsubprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True",
     "Shell execution with shell=True or os.system — validate/avoid concatenating user input here."),
    ("CMDI-EVAL", "HIGH", "injection",
     r"(?i)\beval\(|\bexec\(|\bnew Function\(",
     "eval/exec/Function on dynamic input is a common injection vector."),
    ("XSS-DANGEROUS-HTML", "MEDIUM", "injection",
     r"dangerouslySetInnerHTML|\.innerHTML\s*=|v-html=",
     "Raw HTML injection point — ensure content is sanitized, not just user-controlled text."),

    # --- Insecure configuration ---
    ("CFG-DEBUG-TRUE", "HIGH", "config",
     r"(?i)\bDEBUG\s*=\s*True\b",
     "Debug mode enabled — must be off in anything reachable by real users."),
    ("CFG-ALLOWED-HOSTS-WILDCARD", "MEDIUM", "config",
     r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]",
     "Wildcard ALLOWED_HOSTS — restrict to known hostnames in production."),
    ("CFG-CORS-WILDCARD", "MEDIUM", "config",
     r"(?i)Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|cors\(\s*\{\s*origin\s*:\s*['\"]\*['\"]",
     "CORS allows any origin — restrict to known origins for anything non-public."),
    ("CFG-TLS-VERIFY-DISABLED", "HIGH", "config",
     r"(?i)verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
     "TLS certificate verification disabled — never do this outside a throwaway local test."),
    ("CFG-JWT-NONE-ALG", "CRITICAL", "config",
     r"(?i)alg(orithm)?['\"]?\s*[:=]\s*['\"]none['\"]",
     "JWT algorithm 'none' accepted — allows unsigned-token forgery."),

    # --- Cookies / sessions ---
    ("COOKIE-NO-HTTPONLY", "MEDIUM", "cookies",
     r"(?i)set-cookie|res\.cookie\(|response\.set_cookie\(",
     "Cookie is being set nearby — confirm HttpOnly, Secure, and SameSite are set explicitly."),
]

DOTENV_FILENAMES = {".env", ".env.local", ".env.production", ".env.development"}
KEY_FILE_EXT = {".pem", ".key", ".pfx", ".p12"}

# Free tier: the highest-signal, lowest-noise categories (secrets, obvious
# insecure config) are available with no license. Pro tier unlocks the
# rest, plus dependency audit and package-registry verification, plus
# (when the license server is live) continuously updated rules.
FREE_CATEGORIES = {"secrets", "config"}
PRO_CATEGORIES = {"crypto", "injection", "cookies"}


def validate_license(key):
    """Returns (is_valid, mode) where mode is 'online', 'offline-grace', or 'none'.

    Tries the real PsyLinks license API first. If that endpoint isn't
    reachable (e.g. this key/domain isn't on your egress allowlist, or you
    haven't stood up the license service yet), falls back to a basic local
    format check as an offline grace mode — this is a placeholder, not a
    real security boundary, and should be replaced with real server-side
    validation before relying on this for actual access control.
    """
    if not key:
        return False, "none"
    try:
        req = urllib.request.Request(
            LICENSE_VALIDATE_URL,
            data=json.dumps({"key": key}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "psylinks-scan"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            return bool(data.get("valid")), "online"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        # License server unreachable — offline grace mode. Any reasonably
        # formatted key is accepted locally so the tool stays usable
        # offline; this is intentionally weak and exists only so Pro
        # features aren't hard-blocked by a network hiccup. Real gating of
        # the truly valuable stuff (live rule updates, threat intel) still
        # requires reaching the server, so this grace mode doesn't leak
        # anything that isn't already in this file.
        if re.match(r"^PSYL-[A-Za-z0-9]{8,}$", key):
            return True, "offline-grace"
        return False, "none"


def watermark(key, mode):
    if mode == "none":
        return "Free tier (no license key)"
    digest = hashlib.sha256(key.encode()).hexdigest()[:10]
    return f"Licensed [{mode}] — key fingerprint {digest}"


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            yield full


def is_scannable(path):
    _, ext = os.path.splitext(path)
    base = os.path.basename(path)
    if base in DOTENV_FILENAMES:
        return True
    if ext in KEY_FILE_EXT:
        return True
    if ext in TEXT_EXT_ALLOW:
        return True
    return False


def scan_file(path, findings, allowed_categories):
    base = os.path.basename(path)
    _, ext = os.path.splitext(path)

    if "secrets" in allowed_categories:
        if base in DOTENV_FILENAMES:
            findings.append({
                "id": "SEC-DOTENV-COMMITTED", "severity": "HIGH", "category": "secrets",
                "file": path, "line": 0,
                "message": f"'{base}' present in scanned tree — confirm it's in .gitignore and never committed.",
            })
        if ext in KEY_FILE_EXT:
            findings.append({
                "id": "SEC-KEY-FILE", "severity": "CRITICAL", "category": "secrets",
                "file": path, "line": 0,
                "message": f"Private key/cert file '{base}' present in repo tree — should not be committed.",
            })

    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return
    except OSError:
        return

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return

    content_lines = lines
    for pat_id, sev, cat, pattern, msg in PATTERNS:
        if cat not in allowed_categories:
            continue
        if pat_id == "SEC-DOTENV-COMMITTED":
            continue  # handled above by filename
        try:
            rx = re.compile(pattern)
        except re.error:
            continue
        for i, line in enumerate(content_lines, start=1):
            if "psylinks-scan-ignore" in line:
                continue
            if rx.search(line):
                findings.append({
                    "id": pat_id, "severity": sev, "category": cat,
                    "file": path, "line": i, "message": msg,
                    "snippet": line.strip()[:160],
                })


def run_dependency_audit():
    results = []
    if os.path.exists("package-lock.json") or os.path.exists("package.json"):
        try:
            out = subprocess.run(["npm", "audit", "--json"], capture_output=True, text=True, timeout=120)
            if out.stdout:
                try:
                    data = json.loads(out.stdout)
                    meta = data.get("metadata", {}).get("vulnerabilities", {})
                    if meta:
                        results.append({"tool": "npm audit", "summary": meta})
                except json.JSONDecodeError:
                    results.append({"tool": "npm audit", "raw": out.stdout[:2000]})
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            results.append({"tool": "npm audit", "error": str(e)})

    if os.path.exists("requirements.txt") or os.path.exists("pyproject.toml"):
        try:
            out = subprocess.run(["pip-audit", "-r", "requirements.txt", "-f", "json"],
                                  capture_output=True, text=True, timeout=120)
            if out.stdout:
                try:
                    data = json.loads(out.stdout)
                    results.append({"tool": "pip-audit", "summary": data})
                except json.JSONDecodeError:
                    results.append({"tool": "pip-audit", "raw": out.stdout[:2000]})
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            results.append({"tool": "pip-audit", "error": str(e)})

    return results


def extract_package_names():
    names = []
    if os.path.exists("package.json"):
        try:
            with open("package.json") as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for name in data.get(section, {}) or {}:
                    names.append(("npm", name))
        except (OSError, json.JSONDecodeError):
            pass
    if os.path.exists("requirements.txt"):
        try:
            with open("requirements.txt") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg = re.split(r"[<>=!~\[; ]", line)[0].strip()
                    if pkg:
                        names.append(("pypi", pkg))
        except OSError:
            pass
    return names


def verify_packages_exist(names, timeout=5):
    """Check each package against its public registry. Flags names that
    don't resolve — a strong signal of a hallucinated or typosquatted
    dependency, per the ai-agent-and-vibe-coding-risks.md reference."""
    flagged = []
    for ecosystem, name in names:
        url = None
        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{name.replace('/', '%2F')}"
        elif ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{name}/json"
        if not url:
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "psylinks-scan"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status >= 400:
                    flagged.append((ecosystem, name, f"HTTP {resp.status}"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                flagged.append((ecosystem, name, "NOT FOUND on registry — verify this isn't hallucinated/typosquatted"))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            flagged.append((ecosystem, name, f"could not verify (network issue: {e})"))
    return flagged


def severity_rank(sev):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


def compute_grade(findings, unverified_packages):
    """A simple weighted score → letter grade, so the report gives an
    at-a-glance signal instead of just a raw list. Weights penalize
    Critical/High heavily since those map to the failure classes most
    associated with real breaches (secrets, injection, broken auth)."""
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
    penalty = sum(weights.get(f["severity"], 1) for f in findings)
    penalty += 15 * len(unverified_packages)  # unresolved package identity is treated as severe
    score = max(0, 100 - penalty)
    if score >= 95:
        grade = "A"
    elif score >= 85:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-network", action="store_true", help="skip package-registry verification")
    parser.add_argument("--no-audit", action="store_true", help="skip npm audit / pip-audit")
    parser.add_argument("--license-key", default=os.environ.get("PSYLINKS_LICENSE_KEY", ""),
                         help="PsyLinks Pro license key (or set PSYLINKS_LICENSE_KEY env var)")
    args = parser.parse_args()

    is_licensed, lic_mode = validate_license(args.license_key)
    allowed_categories = set(FREE_CATEGORIES) | (PRO_CATEGORIES if is_licensed else set())

    root = args.path
    findings = []
    for path in iter_files(root):
        if is_scannable(path):
            scan_file(path, findings, allowed_categories)

    findings.sort(key=lambda f: (severity_rank(f["severity"]), f["file"], f["line"]))

    dep_audit = []
    pkg_flags = []
    if is_licensed:
        dep_audit = [] if args.no_audit else run_dependency_audit()
        if not args.no_network:
            cwd = os.getcwd()
            try:
                os.chdir(root)
                names = extract_package_names()
                pkg_flags = verify_packages_exist(names)
            finally:
                os.chdir(cwd)

    score, grade = compute_grade(findings, pkg_flags)

    if args.json:
        print(json.dumps({
            "license": {"tier": "pro" if is_licensed else "free", "mode": lic_mode,
                        "watermark": watermark(args.license_key, lic_mode if is_licensed else "none")},
            "grade": {"score": score, "letter": grade},
            "findings": findings,
            "dependency_audit": dep_audit,
            "unverified_packages": [{"ecosystem": e, "name": n, "note": note} for e, n, note in pkg_flags],
        }, indent=2))
        return

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("PsyLinks 360 Security Scan")
    print("=" * 40)
    print(f"Scanned: {os.path.abspath(root)}")
    print(f"Tier: {'Pro' if is_licensed else 'Free'}  |  {watermark(args.license_key, lic_mode if is_licensed else 'none')}")
    print(f"Security grade: {grade}  (score {score}/100)")
    print(f"Findings: {len(findings)}  " + "  ".join(f"{k}:{v}" for k, v in counts.items()))
    if not is_licensed:
        print()
        print("Free tier: secrets + insecure-config checks only.")
        print("Pro (licensed) unlocks: injection, weak-crypto, cookie/session checks,")
        print("dependency audit (npm audit / pip-audit), and package-registry verification")
        print("(catches hallucinated/typosquatted dependencies). Get a key: [psylinksssecurity.com]")
    print()
    for f in findings:
        print(f"[{f['severity']:8}] {f['id']:24} {f['file']}:{f['line']}")
        print(f"           {f['message']}")
        if "snippet" in f:
            print(f"           > {f['snippet']}")
    if pkg_flags:
        print()
        print("Unverified / not-found packages (possible hallucinated or typosquatted deps):")
        for e, n, note in pkg_flags:
            print(f"  [{e}] {n} — {note}")
    if dep_audit:
        print()
        print("Dependency audit tool output:")
        for entry in dep_audit:
            print(f"  {entry}")
    if not findings and not pkg_flags and not dep_audit:
        print("No pattern-based findings. This is a static scan only — it does not replace")
        print("the Adversarial Self-Audit Gate or a professional review.")


if __name__ == "__main__":
    main()
