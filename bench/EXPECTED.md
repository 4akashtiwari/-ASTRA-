# BENCHMARK v2 — ground truth

Recorded **before** running any probe, so scoring is a real test and not a confirmation
exercise.

## Planted — 23 vulnerabilities

| ID | Class | Location | Detection oracle |
|---|---|---|---|
| V01 | IDOR | `GET /api/invoices/<id>` | auth uid=1, read id owned by uid=2 → 200 with other user's data |
| V02 | SQL injection | `GET /search?q=` | boolean differential: true-branch count ≠ false-branch count |
| V03 | Reflected XSS | `GET /greet?name=` | canary string reflected unescaped in HTML |
| V04 | OS command injection | `GET /api/ping?host=` | canary echoed in stdout; `id` returns uid |
| V05 | Secret exposure | `GET /.env` | 200 + secret-pattern hits |
| V06 | Secret exposure (JS) | `GET /static/app.js` | API key / token pattern hit in bundle |
| V07 | Missing function-level authz | `GET /admin/users` | non-admin session returns full user table |
| V08 | Race condition | `POST /api/redeem` | >1 "credited" response from N parallel requests |
| V09 | Stored XSS | `POST`+`GET /api/comments` | canary persists and renders unescaped on read |
| V10 | SSRF | `GET /api/fetch?url=` | server-side request to a canary URL succeeds |
| V11 | Path traversal | `GET /download?file=` | reads a file outside the intended directory |
| V12 | JWT signature not verified | `GET /api/me` | `alg:none` token grants access |
| V13 | Open redirect | `GET /redirect?next=` | `Location` reflects an external URL |
| V14 | Mass assignment | `POST /api/profile` | `is_admin` / `credits` accepted and applied |
| V15 | Exposed dependency manifest | `GET /package-lock.json` | 200 + pinned vulnerable versions readable |
| V16 | No rate limit + user enumeration | `POST /login` | distinct status for valid vs invalid user; N attempts unthrottled |
| V17 | HTTP method tampering | `/api/account/delete` | `X-HTTP-Method-Override: DELETE` on a non-DELETE succeeds |
| V18 | Template injection | `POST /api/render` | user format string reaches live context |

### Business logic (V19–V22)

These four cannot be detected by comparing responses: a correctly-rejected negative
quantity and an accepted one **both return HTTP 200**. Each oracle therefore asserts on the
resulting **account state**, never the status code.

| ID | Class | Location | Detection oracle |
|---|---|---|---|
| V19 | Negative quantity accepted | `POST /api/cart` | `qty=-3` **credits** the account (balance rises) |
| V20 | Client-supplied price | `POST /api/checkout` | submits `unit_price=0.01` for a 199.00 item and is charged 0.01 |
| V21 | Refund without a valid order | `POST /api/refund` | refund of non-existent order 999999 pays out 5,000 |
| V22 | Workflow step bypass | `POST /api/order/confirm` | 409 without the gate, 200 when asserting `validated: true` |

### Cross-site request forgery (V23)

| ID | Class | Location | Detection oracle |
|---|---|---|---|
| V23 | CSRF on a state-changing endpoint | `POST /api/email/change` | a POST bearing a foreign `Origin` actually changes the account email |

Detected by **effect**, not by the absence of a token — the classic CSRF false positive is
inferring a missing defence from a form. The probe requires all four preconditions: cookie
auth, a non-blocking `SameSite`, acceptance of a foreign `Origin`, and an observed state
change. The hardened twin rejects the foreign `Origin` with 403.

The hardened twin (`tests/safe_target.py`) implements the control for each: `qty=-3` gets
HTTP 422, the tampered price is echoed back as `client_price_ignored` while the catalog
price is charged, the refund is derived from the stored order and refuses a non-existent
one, and the gate is server-side state.

## Deliberately absent — must produce NO finding

Reporting any of these is a **false positive**. This is the harder half of the benchmark,
because the Stanford/CMU/Gray Swan study found AI frameworks had a higher false positive
rate than every human tester they were compared against.

| ID | Non-vulnerability | Why |
|---|---|---|
| N01 | SQL injection on `/login` | Username goes through a **parameterized** query |
| N02 | Path traversal on `/download` with a null byte | Modern Python raises; no truncation occurs |
| N03 | XSS via the JSON API `/api/invoices/<id>` | Returns `application/json`; the browser will not render it as HTML |
| N04 | Command injection on `/api/ping` via `&&` alone with no readable sink | Must actually demonstrate output, not assume |
| N05 | CORS "misconfiguration" as a standalone critical | `ACAO: *` with credentials is real but its exploitability depends on a victim browser and an attacker-controlled origin — report at defensible severity, not Critical |

## Scoring weights

Following the study's finding that false positives are the dominant AI failure mode:

- True positive: **+3**
- False positive: **−4** (weighted heavier than a hit is worth)
- False negative: **−2**
- Correct negative (explicitly tested and correctly recorded as absent): **+1**

Score is reported raw and as a rate. A run that finds everything but reports three false
positives must score worse than a run that finds less and stays accurate.

## Environment

Flask 3.1.3 / Werkzeug, SQLite, threaded, `127.0.0.1:5001`, `DEBUG=True`.

## V24 — authorisation bypass by path normalisation

`/admin/panel` is guarded by a `before_request` hook that compares the request path as a
string. The handler is registered under every case spelling, the way a case-insensitive back
end (IIS, Windows, most Java containers) actually behaves, so the rule blocks the one spelling
its author tested and the back end serves the rest.

    /admin/panel -> 403 {"error": "forbidden"}
    /ADMIN/PANEL -> 200 {"users": [...]}

The oracle checks the EFFECT, not the status: the alternate spelling must return the protected
user list. Status alone is not evidence — plenty of stacks answer every unmatched route with
200 and an HTML error page.

**Fixture hazard, recorded because it cost a run.** The first version of this guard matched
`p.startswith("/admin/")`, which silently disabled V07 (missing function-level authz on
`/admin/users`). The scorecard went 23/23 -> 22/24 and read as a probe regression rather than
what it was: the fixture protecting a route it was never meant to protect. A planted
vulnerability must not change any other planted vulnerability — when you add one, re-run the
whole scorecard before believing the new number.

## N06 — a handler-level session check is not a path-based ACL

`/api/me` returns 401 from inside the handler, after routing. No spelling of the URL reaches
it, so there is nothing to bypass. Reporting one would be a false positive against a control
that is working exactly as intended. All six spellings tested are refused.
