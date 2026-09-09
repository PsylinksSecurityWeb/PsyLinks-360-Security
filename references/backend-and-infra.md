# Backend & Infrastructure Security Checklist

## Secrets management
- Never commit secrets to source control, even temporarily "to test." Use environment variables, a secrets manager (Vault, AWS/GCP/Azure secret managers), or platform-provided config (e.g., `.env` loaded outside the repo, `.gitignore`d).
- Different secrets per environment (dev/staging/prod) — a leaked dev key should never unlock production.
- Rotate secrets on a schedule and immediately on suspected exposure.
- Scan repos for accidentally committed secrets before pushing (e.g., `git-secrets`, `trufflehog`, or the platform's built-in secret scanning).

## Database & data handling
- Use parameterized queries / an ORM's safe query builder — never string-concatenate user input into SQL.
- Principle of least privilege for DB credentials: the app's DB user should not have superuser/DDL rights it doesn't need.
- Encrypt sensitive data at rest (full-disk or column-level, depending on sensitivity) and always in transit (TLS to the database too, not just the client).
- Have a real backup strategy and test restores — this is a security property (availability/integrity), not just ops hygiene.

## Dependencies & supply chain (OWASP A03:2025)
- Pin dependency versions; use lockfiles.
- Run dependency vulnerability scanning (e.g., `npm audit`, `pip-audit`, Dependabot/Snyk) and don't ignore high-severity findings.
- Be wary of newly-published or low-maintainer-count packages for security-sensitive functionality.
- Verify build/CI pipeline integrity — don't let CI scripts pull and execute unpinned remote scripts.

## Configuration
- Disable debug mode, verbose logging of request bodies, and admin/debug endpoints in production.
- Set security headers: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, `X-Frame-Options` (or frame-ancestors via CSP).
- Keep runtime, framework, and OS packages patched; don't run outdated base images.

## Logging & alerting (OWASP A09:2025)
- Log security-relevant events: auth failures, permission denials, admin actions, unusual rate-limit triggers.
- Never log secrets, passwords, full payment card numbers, or raw tokens.
- Logging without alerting is close to useless for incident response — wire critical events to an actual alert (email, Slack, PagerDuty), not just a file no one reads.

## Error handling (OWASP A10:2025 — new category)
- Fail closed, not open: if an authorization check errors, deny access rather than defaulting to allow.
- Handle exceptional/edge conditions explicitly (empty inputs, timeouts, partial failures) rather than assuming the happy path.
- Return generic errors to clients; keep detailed diagnostics server-side only.

## Deployment
- Principle of least privilege for cloud IAM roles and service accounts.
- Separate environments (dev/staging/prod) with separate credentials and access controls.
- Automate security checks (dependency scan, secret scan, SAST) in CI so they run every time, not just when someone remembers.
