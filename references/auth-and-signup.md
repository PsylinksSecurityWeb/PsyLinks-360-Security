# Authentication & Signup Security Checklist

Based on OWASP ASVS and OWASP Top 10:2025 — A07:2025 Authentication Failures.

## Signup
- Enforce a minimum password length (12+ chars recommended) rather than arbitrary complexity rules (those push users toward predictable patterns).
- Check new passwords against a breached-password list (e.g., Have I Been Pwned range API) where feasible.
- Verify email/phone ownership before granting full account privileges.
- Don't reveal whether an email is already registered in ways that enable account enumeration (use consistent, generic responses/timing).
- Never accept and trust client-supplied fields like `role`, `isAdmin`, or `accountId` on signup — set these server-side.

## Login
- Hash passwords with bcrypt / scrypt / Argon2id, tuned cost factor, unique salt per user (handled automatically by these algorithms).
- Rate-limit and progressively delay repeated failed login attempts per account and per IP; lock or challenge (CAPTCHA/MFA step-up) after repeated failures.
- Use generic error messages ("invalid email or password") — never reveal which field was wrong.
- Offer and encourage multi-factor authentication (TOTP apps preferred over SMS where possible).
- Log authentication events (success/failure, IP, timestamp) for later alerting — but never log the password itself.

## Sessions & tokens
- Generate session identifiers with a cryptographically secure random generator, sufficient entropy (128+ bits).
- Set cookies `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`.
- Rotate session tokens on privilege change (e.g., after login, after password change).
- Expire sessions after a reasonable inactivity window; invalidate all sessions on password change.
- For JWTs: use short expiry, validate signature and algorithm server-side (never trust `alg: none`), avoid storing sensitive data in the payload (it's readable, not just signed), and have a real revocation strategy if you rely on long-lived tokens.

## Password reset
- Use single-use, time-limited, cryptographically random reset tokens sent to the verified email/phone — never reuse or predict them.
- Invalidate the reset token after use or expiry.
- Don't log the reset token or include it in analytics/error tracking.

## MFA
- If offering MFA, protect the enrollment and recovery-code flow as carefully as the primary login (these are common bypass targets).
- Store recovery codes hashed, not plaintext.

## Common pitfalls to explicitly avoid
- "Remember me" tokens that never expire.
- Password reset via security questions alone.
- Trusting client-side-only validation for account state or role.
- Storing session tokens in `localStorage` where they're exposed to XSS (prefer `HttpOnly` cookies).
