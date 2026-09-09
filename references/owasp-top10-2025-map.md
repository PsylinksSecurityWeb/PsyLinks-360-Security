# OWASP Top 10:2025 — Quick Reference

Use this as a cross-check for anything not already covered by the auth, API, or backend checklists. Source: owasp.org/Top10/2025.

| # | Category | What to check for |
|---|----------|--------------------|
| A01 | Broken Access Control | Every access to a resource checks *this user, this object* — includes SSRF (server-initiated requests must be validated/restricted). |
| A02 | Security Misconfiguration | Default credentials changed, debug mode off in prod, unnecessary features/ports disabled, security headers set. |
| A03 | Software Supply Chain Failures | Dependencies pinned and scanned; CI/build pipeline can't be hijacked; wary of unmaintained or newly-published packages. |
| A04 | Cryptographic Failures | Modern algorithms only, TLS everywhere, no hardcoded keys, sensitive data encrypted at rest. |
| A05 | Injection | Parameterized queries, output encoding, no string-built SQL/shell/HTML from user input. |
| A06 | Insecure Design | Threat-model the feature before building — what's the abuse case, not just the happy path? |
| A07 | Authentication Failures | See `auth-and-signup.md`. |
| A08 | Software or Data Integrity Failures | Verify integrity of code/data at the point of use (signed updates, checked deserialization, no blind trust of client-supplied data structures). |
| A09 | Security Logging & Alerting Failures | Security events logged *and* alerted on, not just written to a file nobody reads. |
| A10 | Mishandling of Exceptional Conditions | Fail closed on errors; handle edge cases explicitly rather than assuming success. |

This list changes over time — if it's been a while, a quick web search for "OWASP Top 10" will confirm you're still working from the current version.
