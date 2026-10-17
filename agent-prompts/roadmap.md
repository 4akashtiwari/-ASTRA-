# ROADMAP — A Powerful Web Application Penetration Test

Twelve phases. Each has an entry gate, an owner, exit criteria, and the artefact it must
produce. **You do not advance past a gate until the exit criteria are met** — that rule is
what separates a methodical engagement from a scattergun scan.

---

## The shape of it

```
  PHASE 0      AUTHORIZATION          ← nothing runs before this
     │
  PHASE 1      OSINT (passive)        ← zero packets to target
     │
  PHASE 2      ACTIVE RECON           ← first contact
     │
  PHASE 3      SURFACE MAPPING        ← the input inventory
     │
  PHASE 4      FINGERPRINT → CVE      ← version → known vuln → notify → teach
     │
  PHASE 5      VULN ASSESSMENT        ← breadth, parallelizable
     │
  PHASE 6      EXPLOITATION           ← depth, sequential, one thread
     │
  PHASE 7      BUSINESS LOGIC         ← the stuff scanners never find
     │
  PHASE 8      ESCALATION & LATERAL   ← Tier 3 gate
     │
  PHASE 9      REPORT
     │
  PHASE 10     REMEDIATION VERIFY     ← re-test every fix
     │
  PHASE 11     DEBRIEF                ← feed lessons back into the prompts
```

**The critical architectural insight:** phases 1–5 are *breadth* and parallelize well across
subdomains and vulnerability classes. Phase 6 is *depth* and must stay sequential in a single
reasoning thread. Splitting exploitation across parallel agents fragments the reasoning chain
and errors cascade instead of cancelling. See §Architecture note at the end.

---

## PHASE 0 — Authorization & Scoping

**Owner:** Sentinel (scope enforcement) · **Gate: HARD STOP**

| Do | Why |
|---|---|
| Record the authorization basis in writing | Own asset, contract, or bounty ID. No basis, no test |
| Define in-scope assets explicitly | Domains, subdomains, IPs, APIs. Wildcards only if stated |
| Define exclusions explicitly | CDN, SSO, payment processor, analytics — chains run through these |
| Set the rate ceiling | req/s, max threads, blackout windows |
| Set the testing window | When you're allowed, and who to call if something breaks |
| Confirm destructive testing | Default: not permitted |
| Confirm credential availability | Changes black/grey/white box entirely |
| Confirm reporting audience | Technical, executive, or both |
| Confirm emergency contact | If you destabilize something at 3am, who answers |

**Exit gate:** `engagement/scope.yaml` exists and is complete. Every later phase checks
against it programmatically. An out-of-scope request exits non-zero and gets logged.

**Artefact:** `scope.yaml`, `roe.md`

**Failure mode to avoid:** starting recon "just to have a look" before scope is written. That
is how engagements become incidents.

---

## PHASE 1 — OSINT (Passive Collection)

**Owner:** Scout (lead), Mole (secrets), Oracle (stack) · **Gate: no target contact**

Zero packets to the target. Highest signal-per-risk phase in the entire engagement.

**Work in this order:**

1. **Registration & DNS** — WHOIS (creation date: young domains are rushed builds; expiry:
   lapsed domains are takeover targets), full record set, SPF/DKIM/DMARC (a missing or
   permissive DMARC is a finding in itself, and `include:` chains enumerate every third-party
   mail sender), AXFR attempt, reverse DNS on every IP found.

2. **Subdomain enumeration** — crt.sh certificate transparency first (highest free yield),
   then passive DNS sources, then permutation guessing: if `staging.` exists try `stg`,
   `stage`, `qa`, `dev`, `uat`, `preprod`, `test`, `sandbox`, `beta`, `internal`.

3. **Historical web** — Wayback CDX API for the full URL history. The gold here is **old
   JavaScript bundles**: historic builds leak API keys and internal endpoints long after they
   were "removed" from production. Diff `robots.txt` and `sitemap.xml` across time.

4. **Code & secret exposure** — GitHub/GitLab/Gists/npm/PyPI searched for the domain, org
   name, product codenames, employee email domains. Sweep everything collected for AWS keys,
   GitHub PATs, Slack tokens, private keys, connection strings.

5. **Infrastructure** — ASN and netblocks, Shodan/Censys by cert CN and HTTP title, favicon
   hash (finds hosts with no DNS name at all), cloud bucket permutations.

6. **People & org** — LinkedIn, and **job postings are gold** (they name the exact stack,
   cloud provider, and internal tooling). Engineering blogs and conference talks. Derive the
   email address pattern from any two known addresses.

7. **Breach data** — HIBP for the domain. Record the count of leaked employee addresses;
   never store the passwords.

8. **Document metadata** — EXIF in public images, author names and internal paths in PDFs
   and office docs.

**Exit gate:** `osint/SUMMARY.md` ends with a **ranked attack-hypothesis list** — each
hypothesis states what the risk is, why OSINT suggests it, and which command tests it.
**If there are no hypotheses, this phase is not finished.** You collected trivia, not
intelligence.

**Artefacts:** `osint/*.txt`, `osint/SUMMARY.md`, asset inventory

**Time budget:** most people under-invest here by an order of magnitude. Invert the instinct
to rush to scanning.

---

## PHASE 2 — Active Recon

**Owner:** Cartographer · **Tier 0/1**

1. Port scan — top-1000 first, then full range on the apex host only. Save `-oX`, parse the
   XML. **Note: SYN scans need root**; if you're not root, use a connect scan and say so.
2. Service and version detection on open ports.
3. Live-host probing across the subdomain list — which ones actually answer on 80/443?
4. Virtual host discovery.
5. TLS review — certificate chain, expiry, weak ciphers, missing HSTS.
6. Header analysis — security header gaps, `Server` and `X-Powered-By` banners.

**Exit gate:** every in-scope host characterized — what it is, what version, what it exposes.

**Artefacts:** parsed port/service JSON, live host list, header gap analysis

---

## PHASE 3 — Surface Mapping

**Owner:** Cartographer → Weaver · **Tier 1**

The output of this phase drives everything after it. Build a complete input inventory.

1. Bounded crawl (scope-respecting, depth-limited).
2. **JS bundle harvesting** — download every bundle including source maps
   (`/app.js.map` leaks original source), extract endpoints, parameters, feature flags.
3. Content discovery — capped wordlist, capped threads. A 200k-wordlist run at 100 threads is
   a DoS, not thoroughness.
4. API discovery — `/api/`, `/graphql`, OpenAPI/Swagger docs, `/.well-known/`, versioned
   paths (`/v1/` vs `/v2/` often have inconsistent authorization).
5. Parameter mining from Wayback + JS.
6. Form, file upload, and header inventory.
7. Error behaviour cataloguing — what does a 500 look like? What leaks in it?
8. Auth and session mechanics — how are tokens issued, rotated, validated?

**Exit gate:** `surface/inventory.json` — every endpoint, method, parameter, header, and
upload point, with its source.

---

## PHASE 4 — Fingerprint → CVE Correlation

**Owner:** Oracle · **Tier 0** (passive) then **Tier 1** (verification)

See `version-cve-pipeline.md` for the full specification. Summary:

1. Fingerprint every detected component with a **confidence rating**.
2. Query **live** sources — OSV.dev, NVD, GitHub Advisory, ExploitDB. Never trust the
   model's memory for CVEs; its training data predates recent disclosures and it will
   hallucinate identifiers that look plausible.
3. **Verify reachability** before reporting. A CVE in a library you never call is not a
   finding.
4. Notify with the evidence chain.
5. **Teach the user** — every notification includes the mechanism, the affected code
   pattern, and how to spot it next time.

**Exit gate:** every fingerprinted component either matched to a verified CVE or explicitly
recorded as "checked, no applicable finding."

---

## PHASE 5 — Vulnerability Assessment

**Owner:** Breaker (lead), supported by Mole and Oracle · **Tier 1** · **PARALLELIZABLE**

This is the breadth phase. Vulnerability classes are independent, so run them concurrently.

Automate for leads. **Verify manually. Scanner output is a lead list, never a finding list.**

| Class | What actually matters |
|---|---|
| Broken access control | IDOR, forced browsing, missing function-level authz, tenant isolation. **Test every object ID you find** |
| Injection | SQLi, NoSQLi, command, LDAP, XPath, SSTI. Confirm by differential, not by 500 |
| XSS | Reflected, stored, DOM. Check sinks in bundled JS, not just responses |
| Auth failures | Weak policy, no rate limit, user enumeration, broken MFA, session fixation |
| Session mgmt | Predictable tokens, no rotation on privilege change, weak cookie flags |
| SSRF | Cloud metadata `169.254.169.254`, internal ranges, protocol smuggling, DNS rebinding |
| Misconfig | Default creds, exposed admin panels, debug modes, open buckets |
| Vulnerable components | From phase 4 |
| Data exposure | Secrets in JS and git history, verbose APIs, PII in responses, backups |
| Logging gaps | Would an attack even be detected? |

**The critical discipline:** a boolean differential needs **three distinguishable states** —
baseline, true branch, false branch. If true and false return the same result, your payload
is a syntax error, not proof of safety. Read the injection context first (inside `LIKE
'%...'`? a quoted string? numeric?) and account for what the app appends after your input.
This failure mode — declaring a false negative from a broken payload — is as damaging as
declaring a false positive from a 500.

**Exit gate:** every probe class either confirmed, disproven, or recorded as a coverage gap
with the reason.

---

## PHASE 6 — Exploitation & Chaining

**Owner:** Breaker, single-threaded · **Tier 2/3** · **SEQUENTIAL — DO NOT PARALLELIZE**

Prove impact, don't just prove presence. A stored XSS is a finding; using it to capture a
session and perform an admin action is impact. An IDOR is a finding; showing it spans
tenants and yields N records is impact.

**Chain deliberately.** Low + low often equals critical. Document the chain as one narrative
with each link evidenced.

**STOP AT PROOF.** The moment impact is demonstrated: capture evidence, redact PII, write
the finding, stop. Going deeper to be impressive is how engagements get out of hand.

**Exit gate:** every confirmed finding has command + request + response artefacts.

---

## PHASE 7 — Business Logic & Race Conditions

**Owner:** Fool (ideation) → Breaker (execution) · **Tier 1/2**

Scanners never find these. This phase needs a human-shaped imagination.

1. **Race conditions** — wherever state changes (money, quota, one-time tokens, redemptions,
   coupons), fire parallel requests and count successes. In dry-run validation this found a
   single-use code redeemed 10/10 times.
2. **Workflow skipping** — can you reach step 5 without steps 1–4? Navigate directly to the
   post-auth, post-payment, post-verification state.
3. **Negative and boundary values** — negative quantities, zero amounts, huge integers,
   type confusion (`"100"` vs `100` vs `[100]`).
4. **Coupon and price manipulation** — client-side totals, discount stacking, currency
   confusion, rounding.
5. **Multi-step abuse** — apply the same one-time benefit across accounts, replay
   confirmations, exploit the gap between check and commit.
6. **Trust boundary confusion** — does the app trust a client-supplied role, price, or
   user ID anywhere?

**Exit gate:** each critical business flow walked end-to-end with at least one abuse attempt
per step.

---

## PHASE 8 — Privilege Escalation & Lateral Movement

**Owner:** Breaker + Cartographer · **Tier 3 — HARD GATE**

Requires explicit written approval. Default behaviour is to stop and ask.

- Vertical escalation: user → admin, tenant → tenant
- Horizontal: user A → user B at the same level
- From RCE: what is the service account? What groups is it in? In dry-run validation the
  service account turned out to be in the `sudo` group — that is the difference between a
  finding and a full compromise.
- Cloud metadata credential retrieval if SSRF was found
- Pivoting to other in-scope hosts only

**Exit gate:** escalation path documented with each link evidenced, or explicitly recorded as
"attempted, not achievable."

---

## PHASE 9 — Reporting

**Owner:** Scribe, reviewed by Ledger and Reflector

1. **Executive summary** — one page, no jargon, business risk framed, top 3 issues. Written
   for someone who will not read the rest.
2. **Scope and methodology** — what was tested, when, how, what was excluded and why.
3. **Findings by severity** — with CVSS vector, impact statement, PoC, evidence refs,
   remediation.
4. **Attack narrative** — the chains that matter, told as a story. This is what lands with
   executives.
5. **Out-of-scope observations** — third-party risks noticed but not tested.
6. **What was NOT found** — explicitly. Calibrates the reader's confidence.
7. **Teaching notes** — for each significant finding, the mechanism and the pattern to
   recognize in future. This is what makes the client better rather than just informed.
8. **Appendices** — artefact index, tool versions, raw logs.

**Severity discipline:** inflation destroys credibility. A report padded with missing-header
findings gets skimmed and the real Critical gets missed.

---

## PHASE 10 — Remediation Verification

**Owner:** Ledger → Breaker

For each finding: state the specific fix, wait for it, re-test, record the result. Close the
loop. Findings that were "fixed" but still exploitable are the most valuable thing in the
second report.

---

## PHASE 11 — Debrief & Feedback

**Owner:** Reflector

What did the method get wrong? Which probes produced false negatives? Which phase was
under-budgeted? Feed the answers back into the agent prompts. This is the phase that makes
the *next* engagement better, and it's the one everyone skips.

---

## ARCHITECTURE NOTE — what to parallelize and what not to

This roadmap is shaped by what the research on multi-agent systems actually shows:

- **Parallelize the breadth phases (1, 2, 3, 5).** Subdomain enumeration, port scanning,
  content discovery, and independent vulnerability classes are genuinely decomposable.
  Coordination overhead is worth paying here.
- **Do NOT parallelize phase 6 (exploitation).** It's a sequential reasoning chain where
  step N depends on step N−1. Splitting it fragments the reasoning and errors cascade rather
  than cancelling. Research on sequential constraint-satisfaction tasks shows multi-agent
  coordination degrading performance by 39–70%.
- **Keep one agent on the sequential thread** and let it call specialists, rather than
  letting specialists coordinate with each other.

See `agents-roster.md` §Coordination model for how this maps onto the team.
