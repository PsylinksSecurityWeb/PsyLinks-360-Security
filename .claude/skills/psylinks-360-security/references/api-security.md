# API Security Checklist

Based on OWASP API Security Top 10:2023.

## Authorization (the biggest real-world category — 3 of the top 5 risks)
- **Object-level authorization (BOLA)**: every endpoint that takes an ID (`/orders/{id}`, `/users/{id}`) must verify the *requesting user* is allowed to access *that specific object* — never rely on the ID being "hard to guess."
- **Property-level authorization**: don't return or accept fields the caller shouldn't see/set (e.g., don't let a `PATCH /users/me` accept `role` or `balance` unless explicitly intended and separately authorized). Use explicit allow-lists for serialization and input binding, not blocklists.
- **Function-level authorization**: admin/privileged endpoints check role/permission server-side on every call, not just hide the button in the UI.

## Resource consumption
- Rate-limit per user/API key/IP on all endpoints, tuned tighter on expensive ones (search, export, bulk operations).
- Cap payload sizes, pagination limits, and query complexity (especially for GraphQL — limit depth/complexity to prevent expensive nested queries).
- Set timeouts on all outbound calls the API makes.

## Business logic abuse
- Think about what happens if a legitimate action is repeated abnormally fast or many times (e.g., applying a promo code thousands of times, requesting password resets in a loop) — add logic-level limits, not just technical rate limits.

## SSRF (server-side request forgery)
- If the API fetches a URL supplied by the user (webhooks, image-from-URL, link previews), validate and restrict destinations — block internal/private IP ranges (169.254.169.254, 10.0.0.0/8, 127.0.0.1, etc.), disallow redirects to internal addresses, and use an allow-list where feasible.

## Configuration & inventory
- Disable verbose framework error pages / stack traces in any environment reachable by real users.
- Version and document all endpoints; remove or properly secure old/deprecated versions instead of leaving them live and unmonitored.
- Restrict CORS to known origins — avoid `Access-Control-Allow-Origin: *` on anything that isn't a fully public, unauthenticated endpoint.
- Turn off unnecessary HTTP methods (TRACE, unused verbs) at the framework/gateway level.

## Consuming third-party APIs safely
- Validate and sanitize data received from third-party/upstream APIs before trusting or storing it — don't assume an external API's response is safe just because it's authenticated.
- Pin and review third-party SDKs/dependencies (this overlaps with Software Supply Chain Failures — see `owasp-top10-2025-map.md`).

## Quick self-check before shipping an endpoint
1. Who can call this, and did I check that server-side?
2. What's the worst that happens if this is called 10,000 times in a minute?
3. What does the error response leak if something goes wrong?
4. Does this return only the fields the caller should see?
