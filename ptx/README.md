# ptx — the CLI toolkit

The implementation of `pentest-agent-builder.md`. Small, dependency-free, and built to be
driven by an AI agent through a shell.

**Status: working.** Every command below was executed and verified. See "What was verified"
at the bottom for exactly what that covers — and what it doesn't.

---

## Design rules

These aren't preferences. An agent with a limited context window and per-turn latency is the
consumer, so:

- Every capability is a subcommand. No interactive prompts, no TUI, no REPL.
- `--json` on every command for machine-readable output.
- Raw output goes to files; stdout gets a summary and interpretation only.
- Meaningful exit codes: `0` ok · `2` no results · `3` **scope blocked** · `4` tool missing ·
  `5` source unreachable · `6` malformed invocation (distinct from a refusal to act).
- Every network call has a timeout.

**Exit 3 and exit 5 are the two that matter most.** 3 is the safety boundary. 5 is the
honesty boundary — the difference between "no results" and "the query failed."

---

## Installing and dependencies

```bash
ln -s <install>/bin/ptx ~/.local/bin/ptx      # or put bin/ on PATH
ptx --help                                     # works from any working directory
```

The launcher resolves its install directory from its own real path, so a symlink works. It
loads `ptx.py` by explicit file path because that file lives inside a directory also called
`ptx`, and a plain `import ptx` binds to the directory instead of the module.

**The CLI core and every module under `ptxlib/` are pure stdlib** — argparse, base64,
concurrent, hashlib, hmac, http, ipaddress, json, os, re, socket, ssl, subprocess, time,
urllib. Nothing needs installing to run an assessment. The one exception is `z3-solver`, an
*optional* enhancement used only by `probe_constraint_logic` (SMT-solving for a business-
logic invariant violation); its import is try/except-guarded, so without z3 that single probe
returns inconclusive and everything else is unaffected. `requirements-cli.txt` states this
explicitly, and a test walks the package with `ast` and fails if any third-party import
appears that is not both try/except-guarded and declared optional there.

`requirements.txt` pins what the *harness* needs (Flask 3.1.3 and its dependencies, plus
coverage and `z3-solver` for the constraint-logic benchmark targets). Those pins exist because the sandbox lost flask twice mid-session and the
benchmark stopped being runnable with no explanation. A test asserts every line is pinned.

---

## Commands

```bash
# scope — the hard safety boundary
ptx scope init <target> --in-scope <hosts...> --exclude <third-parties...> \
    --authorization "basis" --type blackbox --rate 5 [--destructive]
ptx scope check <hosts...>      # test against scope WITHOUT touching them
ptx scope show

ptx status                      # where the engagement is, and what to do next

# CVE — live lookup, never from memory
ptx cve lockfile <path>         # audit package-lock.json against OSV.dev
ptx cve query <pkg> <ver> --ecosystem npm

# OSINT — phase 1, passive only
ptx osint dns <domain>
ptx osint emailsec <domain>     # SPF/DMARC, include: chain enumeration
ptx osint subs <domain>         # crt.sh certificate transparency
ptx osint wayback <domain>      # CDX URL history, JS bundle + parameter mining

# Suspicion Ledger — findings stop being binary
ptx susp add <surface> <class> --why "..." --hypothesis "..." --falsification "..."
ptx susp list [--state suspected]
ptx susp set <SUSP-NNN> <suspected|probing|substantiated|confirmed|falsified> --note "..."

ptx probe <name> --base <url> [options]   # active tests, verdict + evidence
    # unauthenticated | exposure | headers | idor | sqli | xss | stored-xss | cmdi |
    # ssrf | traversal | jwt-none | redirect | method-tamper | ssti | race | privilege |
    # session-forge
    # `privilege` needs two stored sessions: --as <low> --as-high <high>
    # `session-forge` rewrites the session token and replays a privileged write; with no
    # --forge-body it discovers the gated field itself and builds the request from it
    # There is no "all": a probe run against the wrong endpoint produces a meaningless
    # result, not a thorough one. "unauthenticated" runs the two that need no parameters.
ptx session login <name> --base <url> --user U --password P [--role admin]
ptx session list | remove <name>
    # named identities, so a probe can act as a specific user. Cookies are stored 0600
    # inside the engagement and are never printed in full -- a log that echoes a live
    # session cookie turns a finding into an incident.

ptx discover --base <url> [--start /path ...] [--wordlist f] [--methods] [--limit N]
    # which endpoints exist, measured against a not-found baseline rather than assumed

ptx probe-mass-assignment --base <url> --path <p> --discover --body '{"author":"x"}'
    # discovers privileged field names from the server's own responses; without
    # --discover it needs --verify-path and --verify-match-value and only tests the
    # field names you supply

ptx logic --base <url> --endpoint <p> --param discount:0:200 \
          --invariant "price*qty*(100-discount) < 0" --verify "total < 0"
    # solves (z3) for an input that breaks a stated business-logic invariant, then confirms
    # it by effect on the response -- not the status code. Needs the optional z3-solver;
    # without it the probe reports inconclusive. --param is repeatable (NAME:LO:HI).

ptx probe-credential-leak --base <url> --endpoint <p>
    # finds a usable credential embedded in a response body (a GitHub temp_clone_token, OAuth
    # access token, or signed URL) handed to an unauthenticated caller. Detects by FIELD NAME as
    # well as value shape, because short-lived tokens match no known secret format; reports the
    # kind, never the value.

ptx double-spend --base <url> --state-endpoint <get> --action-path <post> --state-field <n>
    # STATEFUL sequence test: applies a one-time action (claim a credit, apply a coupon, redeem a
    # code) TWICE and measures the state delta each time. If the second identical call moves the
    # state again, the one-time effect is double-spendable / replayable. No single request reveals
    # this -- the bug lives in the gap between the two calls. Destructive: needs
    # `scope init --destructive`. Judges by the state delta, never the status code.

ptx race-consume --base <url> --state-endpoint <get> --action-path <post> --state-field <n> --unit <u>
    # CONCURRENT twin of double-spend: fires N identical requests at a single-use action IN
    # PARALLEL and measures the state delta. If the state moved by more than one unit, the
    # check-then-act was not atomic and the race was won (TOCTOU). Judged by the ledger, not by a
    # success marker in the response body -- a body can misreport success in either direction.
    # --unit is the state change ONE success produces; --requests sets the burst size (default 8).
    # Destructive: needs `scope init --destructive`.

ptx redact [file] [--subject "Acme Corp"] ...   # stdin if no file
    # LLM-BOUNDARY GUARD: replaces subject identifiers (host, URL authority, IP, email, token,
    # and any --subject name) with stable placeholders before text reaches a third-party model.
    # URL paths/query and version numbers are preserved, so the model still gets real context.
    # The reversible map is written to <engagement>/redaction-map.json -- LOCAL ONLY, never send it.
ptx unredact [file]                              # operator-side: restore real values from the map

ptx fingerprint --base <url> [--path <p>] [--cve]
    # Detect stack components + versions from headers, generator meta, and versioned JS libraries
    # (each with a confidence rating + evidence). With --cve, correlates every version that maps to
    # a package ecosystem against a LIVE OSV.dev lookup -- never from memory. Components with no
    # OSV ecosystem (nginx, PHP, WordPress) are surfaced as "check vendor advisories", not "clean".
    # A CVE is a LEAD; reachability is separate (`ptx cve reach`). Implements the ORACLE agent.

ptx variants --class <c> --base <url> [--seed-path <p> --seed-param <q>] [--target <path:param>]... [--discover]
ptx variants --from-finding PTX-003 --base <url> [--discover]
    # Variant analysis: from ONE confirmed fault, sweep the same probe class across sibling
    # endpoints. Vulnerabilities cluster -- a flaw copy-pasted across endpoints is several bugs,
    # not one. Give it the confirmed class (sqli/xss/cmdi/ssrf/traversal/redirect) and either list
    # siblings with --target PATH:PARAM or let --discover crawl for them. The seed (where it was
    # first confirmed) is re-confirmed and reported separately from NEW variants; every new variant
    # is recorded as its own finding. "Seed only, siblings clean" is a real result -- it bounds the
    # issue. Only injectable classes can be swept; business-logic classes have no sibling to sweep.
    # --from-finding starts from a recorded finding: it takes the class and the confirmed location
    # as the seed, so the sweep needs nothing retyped (findings now record where they were found).

ptx retest --base <url> [--finding PTX-003]
    # Phase 8: re-run each confirmed finding's OWN probe at its recorded location after a claimed
    # fix. Reports not-reproduced / STILL OPEN / inconclusive / manual (a class that cannot be
    # re-run from a stored location). 'Not-reproduced' is deliberately NOT 'fixed' -- a black-box
    # re-run cannot tell a real fix from a WAF rule or a rate limit, so the operator confirms the
    # root cause against the diff before closing it.

ptx finding list | validate | set <ID> --impact "..." --severity High --artifact <ref>
ptx report                      # BLOCKS if any finding is invalid

ptx selfcheck                   # pre-report gate; exits 1 if it fails
```

---

## The scope guard is code, not a prompt instruction

`ptxlib/scope.py` is the safety boundary. Every network-bound command resolves its target
against `scope.yaml` **before sending anything**. On violation it raises, logs the attempt
with a timestamp, and exits 3.

Exclusions win over inclusions, always. Wildcards (`*.acme.test`), subdomain matching, bare
IPs, and CIDR ranges are all handled.

Verified: `scope check api.acme.test cdn.cloudflare.net login.okta.com evil.example.com`
allowed the first, blocked the other three with distinct reasons, and wrote three
`SCOPE BLOCK` entries to the log. `osint dns` against an out-of-scope domain exits 3 without
sending a packet.

---

## Two honesty rules baked into the code

### 1. A missing tool produces a coverage gap, never a finding

During testing, `dig` was absent and the DNS module reported **"NO DMARC record — domain is
spoofable"** based on no data whatsoever. A false positive manufactured by the tooling.

Now: if TXT records couldn't be queried, the module emits
`COVERAGE GAP: SPF/DMARC NOT ASSESSED` and **no finding**. A/AAAA fall back to the resolver
library so you still learn the host exists; MX/NS/TXT gaps are reported, never guessed.

### 2. A failed query is not zero results

crt.sh returned 502 and Wayback timed out from this sandbox. The original output read
`subdomains for github.com — 0`, which an agent would reasonably parse as "this target has
no subdomains." That's a false negative produced by infrastructure.

Now: source failures print `SOURCE UNAVAILABLE, NOT ENUMERATED`, suppress the interpretive
hints, exit 5, and log `coverage gap, not a negative result`.

Both bugs are the same class as the inverted scorecard oracle and the malformed SQLi
payload: **the measurement instrument lying.** They're the most common failure mode in this
whole project and the reason the Falsifier exists.

---

## What was verified

Executed and observed:

| Command | Result |
|---|---|
| `scope init` / `show` | writes scope.yaml + state.json |
| `status` without scope | exits 3 with "nothing runs without scope" |
| `scope check` | allowed 2, blocked 3, logged all 3 blocks |
| `osint dns` against out-of-scope | exits 3, nothing sent |
| `osint dns example.com` (dig present) | 10 records across A/AAAA/MX/NS/SOA/TXT, no findings |
| `osint dns` (dig absent) | 4 records via fallback + 2 explicit coverage gaps, **no invented finding** |
| `osint emailsec` | SPF/DMARC status + include-chain enumeration |
| `cve lockfile` | **4/4 packages affected, live from OSV.dev**: lodash@4.17.4 → 10 advisories incl. CVE-2019-10744 (critical), minimist@0.2.1 → CVE-2021-44906, jsonwebtoken@8.5.0 → CVE-2022-23539/40/41, express@4.16.0 → CVE-2024-29041 |
| `cve lockfile` output discipline | prints "reachability UNASSESSED — verify before assigning severity" |
| `susp add/list/set` | full lifecycle, JSON parses, `confirmed` increments finding count |
| `selfcheck` | failed 5/6 with an unprobed suspicion, passed 6/6 after resolution — **the gate works** |
| `osint subs` / `wayback` | sources unreachable from this sandbox; correctly reported as gaps with exit 5 |

## Six honesty rules

### 3. A probe that cannot distinguish states reports inconclusive, never safe

`ptx probe sqli` was run against an injection point sitting inside `LIKE '%...%'` using the
wrong injection context. The true and false branches both returned 0. The probe output:

```
[inconclusive] SQL injection on /search?q
  INCONCLUSIVE — baseline=0 true=0 false=0. True and false branches are not
  distinguishable, so this is either not injectable or the payload does not parse
  in this context. Try a different injection context before concluding.
```

With the correct context it returned `VULNERABLE — baseline=5, true-branch=5,
false-branch=0`. **The probe refused to manufacture a negative from a broken payload** —
which is the exact error that produced a false negative during the dry run.

### 4. A probe verifies the effect, not the response

The mass-assignment probe sends privileged fields and then reads the record back. When the
session was invalid mid-run, it correctly reported `privileged fields ACTUALLY CHANGED:
False` instead of trusting the API's `{"ok": true}`. The evidence string now says so
explicitly: *"the response claiming success is not evidence — the effect is."*

### 5. Re-running a probe must not duplicate a finding

`from_probe` dedupes on class + title and updates in place. Without this, iterating on a
probe inflates the finding count — and a report listing the same issue twice loses the
reader's trust in every other number in it. Verified: re-running the IDOR probe left the
finding count at 13.

---

### 6. Scope gates every command that touches a target, and the rate ceiling binds

`ptx probe --base <url>` now resolves `<url>` against `scope.yaml` before sending anything,
and exits 3 on a violation. It did not used to — see the audit below. The rate ceiling comes
from `scope.yaml` and is a maximum: `--rate` can lower it, never raise it.

---

## CVE reachability — the step that kills scanner noise

`ptx cve reachability` assesses whether the vulnerable code is actually reachable, and
returns one of four verdicts with a confidence rating and an explicit statement of what
would confirm it:

| Verdict | Meaning |
|---|---|
| `EXPOSED` | the vulnerable component is the request-handling path itself, observed serving HTTP |
| `LIKELY` | server-side and loaded, but call-path use cannot be determined from outside |
| `UNDETERMINED` | no evidence either way; says exactly what would resolve it |
| `NOT_PRESENT` | browser-side only, **or a devDependency** — build-time/supply-chain risk, not runtime |

The devDependency distinction matters: a build tool never ships to production, so a CVE in
one is not reachable through the running application. The raw version match ignores this
entirely.

`EXPOSED` is assigned on **package identity** (the package *is* the HTTP layer) or on
**unambiguous advisory wording** about request handling. An earlier version also matched
"prototype pollution" and marked lodash and minimist `EXPOSED` — a vulnerability *class*
says nothing about whether the request path reaches it. Over-broad heuristics here
manufacture false positives, which is exactly what this module exists to prevent.

Verified against the benchmark lockfile: `express@4.16.0 → EXPOSED (high)`, the other three
`→ LIKELY (medium)`, each with `to_confirm` guidance. Output closes with:
*"Reachability drives severity. A version match is a lead; a reachable vulnerable call path
is a finding. Do not conflate them."*

**Black-box honesty:** without source access you cannot prove reachability, so this module
never claims certainty it doesn't have. That's a feature, not a limitation.

---

## The CLI audit — thirty-nine bugs, thirty-seven found by reading the code

After the test suite was green, I audited the CLI by hand and found thirty-five more bugs,
none of which any test covered. Three were found by generating a report and reading it; one by
running a new probe through the CLI and noticing it disagreed with itself as a library; one by
auditing the benchmark itself; and two by reading the *uncovered lines* of the report module
rather than guessing where to add tests.

**#37 was self-inflicted**, and is recorded for that reason. Fixing #32 (remediation always
blank) meant splitting a list literal inside `for r in recs:` — and four lines, including the
artefact block, were re-inserted one indent level too far out. An engagement with **no
findings** then died with `UnboundLocalError: cannot access local variable 'r'`. The suite was
green at the time because every existing test had at least one finding. A multi-line edit
inside a loop needs a test for the zero-iteration case. Two were found by running the whole workflow and reading what it
produced rather than by reading code — including the one that had made the Memory Loop
incapable of ever learning anything. Four of them are the *same* failure of the scope-exclusion guard
reached by four different routes, which is the reason the last one is fixed by validation
rather than by another parsing rule. Two were found by tools rather than by reading — a linter and a
coverage report — which is the point of the gates that now run in the suite. The first four are safety failures rather than correctness
failures, one is a *reporting* failure of the same family as the fabricated DMARC record,
and the last is the scope-exclusion bug's twin in another module.

| Bug | Severity | What happened |
|---|---|---|
| **Exclusions ignored CIDRs and wildcards — the guard failed OPEN** | **CRITICAL** | The exclusion list was matched with `h == ex or h.endswith("." + ex)` while the inclusion list understood wildcards, subdomains, CIDRs *and* bare IPs. So `exclusions: 10.0.0.0/8` matched nothing, and `exclusions: *.prod.acme.com` matched nothing — and both hosts were **allowed**, because an in-scope CIDR or wildcard covered them. A user excludes their production range and the tool attacks it, with no warning anywhere. The docstring even said "exclusions win over inclusions, always", which was true for two of four formats |
| **Report sections failed silently into HTML comments** | **HIGH** | Both failure handlers emitted `<!-- coverage section unavailable: ... -->`, which renders as **nothing**. Verified before fixing: `build()` returned a path, the word "Coverage" appeared nowhere in the output, and the only trace was a comment no reader sees. The second handler was worse — it covered attack chains, probe reliability **and the evidence-integrity check**, so a report could ship with no integrity verification and nothing to say so. Both now emit a visible `SECTION FAILED TO GENERATE` heading naming the exception and stating what was not measured |
| **A multi-line edit inside a loop broke the empty case** | **HIGH** | Self-inflicted, from fixing #32. Four lines including the artefact block were re-inserted one indent level out of `for r in recs:`, so an engagement with **no findings** raised `UnboundLocalError: cannot access local variable 'r'`. The suite passed because every existing test had at least one finding |
| **A falsification oracle that could not fail** | **CRITICAL** | `N05` — "CORS reported as standalone Critical" — computed the right answer from the response headers into a variable called `ok`, then passed the literal `False` to `record()` instead. It recorded `CORRECT_NEGATIVE` forever. One of the benchmark's **six** over-reporting checks was inert, and it was the one guarding the most common severity inflation in web reports. An AST pass over all 37 `record()` calls now asserts that no planted target assumes its own ground truth, and every target must populate a tool verdict. Verified: mutating the CORS probe to say `Critical` flips N05 to `FALSE_POSITIVE` and drops the score 81 → 76 |
| **A shared argument default made a new probe test nothing** | **HIGH** | `probe user-enum` was wired with `field=args.param`, and `--param` defaults to `q` — right for a search box, wrong for a login form. The endpoint never saw a username, both sides of the comparison came back identical, and the probe printed **`not vulnerable`** having sent four requests that measured nothing. The library call on the same target said `vulnerable: True`. Now `--user-field` (default `username`), plus a guard that reports `inconclusive` when both sides come back HTTP 400 — a malformed body is not a clean result |
| **The report contradicted itself about coverage** | **MEDIUM** | One section said *"No coverage gaps were logged. Treat that with suspicion"* and twenty lines later the Coverage section listed **nineteen** probe classes that had never run. The two sections meant different things by "gap" — one counted OSINT/recon gaps, the other untested probe classes — and a reader cannot tell. Now the first says explicitly what it counts and points at the section that does have something to report |
| **Every finding's remediation was blank** | **HIGH** | `from_probe` hardcoded `"remediation": ""`, while every probe writes its fix as the sixth positional argument to `_verdict`, which lands in `teaching`. So the report printed `#### Remediation / _not recorded_` on **every** finding, with the actual advice one heading lower under "Teaching note". A pentest report whose remediation column is always blank reads as though the tool had nothing to say. Now remediation is populated from the probe, and the teaching note prints only when it genuinely differs, so the advice appears once |
| **The report advised testing the bypass URL it had just used** | **MEDIUM** | The acl-bypass probe's evidence names the variant that worked — `/ADMIN/PANEL` for `/admin/panel` — and the endpoint scraper added it to the inventory, so the untested-pairs table listed `acl-bypass` × `/ADMIN/PANEL`. Endpoint comparison is now case-insensitive: HTTP paths are case-sensitive, but for a checklist of "which routes have you tried this class on" they are one route |
| **The takeover scan fired unthrottled at third parties** | **MEDIUM** | The confirmation requests go to GitHub, Heroku and Amazon — not to the target — and the scan had no rate limit at all. Across a domain with a few thousand subdomains that is a volume attack on someone else's infrastructure and a fast way to get the operator's egress IP blocked. Now a thread-safe `_Throttle` at the engagement's ceiling (`--rate`, default 5/s). **Thread-safe on purpose:** the unlocked version of this exact bug was already found in `probes.Http`, where ten threads read the same `_last`, computed the same wait and fired together — 48 req/s against a 5 req/s ceiling. Measured here: 40 requests across 10 threads at a 5 req/s ceiling → **5.1 req/s** |
| **The coverage report went silent on a brand-new engagement** | **HIGH** | `render()` returned early when `actions_recorded == 0`, so an engagement that had run nothing printed one sentence and **no gap list at all**. That is backwards: what has not been run is known exactly, and it is the part of the report the operator needs most before starting. The warning stays; the early return does not |
| **`assessment_type` was a control with no reader — the fourth** | **MEDIUM** | Written to `scope.yaml`, printed by `ptx status`, and read by nothing. It accepts `blackbox`/`greybox`/`whitebox`. It matters because a blackbox engagement has no credentials, so the eight classes that assume an authenticated identity *cannot* be run — and listing them under "never run at all" told the operator they had forgotten something that was never reachable. A gap list containing unreachable items gets skimmed, which hides the real ones. Now split into *"Not runnable without credentials (8)"* and *"Never run at all (12)"*, sourced from `chains.REQUIRES` so the two files cannot drift. **Wiring it exposed a fifth instance of the same shape:** the first attempt read the value inside `try: … except Exception: pass`, and `load_scope` takes an *engagement directory*, not a path to `scope.yaml` — so it raised `FileNotFoundError`, the bare except swallowed it, and the feature looked wired up while doing nothing |
| **Two probes crashed or lied when their argument was missing** | **HIGH** | The CLI leaves `--marker` and `--canary-url` at `None`. `probe_traversal` did `marker in r["body"]`, which raised `TypeError: 'in <string>' requires string as left operand, not NoneType` — a traceback on the probe's own default invocation. `probe_ssrf` was worse and quieter: it built the URL `None?name=<token>`, asked the target to fetch that, and reported **`not vulnerable`** when the token naturally did not come back. It tested nothing and recorded a clean result. Both now return `inconclusive` with the exact flag to supply, and coverage lists them under *attempted but never measured* |
| **A table row no code path could select** | **HIGH** | `chains.demonstrated` built its `ONE_HOP` key as `(cls, "secret")` or `(cls, "exec")` and nothing else, so an entry keyed on any other capability was unreachable — it could be added, reviewed, and tested for presence in the table, and still never fire. Found while adding the subdomain-takeover hop. The lookup is now capability-generic; the three affected classes were checked against the old logic and are unchanged |
| **The integrity check cried wolf on every completed finding** | **HIGH** | A finding is sealed at creation, when `impact` and `reproduction` are still empty — and the report **refuses to generate** until the operator fills them in. So the mandatory next step of every engagement produced `EVIDENCE DRIFT` on every finding, and the integrity section reported "0 of 2 findings intact" for a perfectly honest report. A control that always alarms is a control nobody reads. Now: only *populated* fields are sealed, `finding set` re-seals and appends the previous digest to the seal's history, and `verify` reports intact with the edit trail. **Hand-editing probe evidence is still caught** — that property is asserted separately, because it is the one that must not be traded away |
| **The Memory Loop could never observe a refutation** | **CRITICAL** | Two separate breaks, and together they meant the loop had never once seen a human reject a finding. **(a)** Nothing in the toolchain could set `status: "refuted"` — `finding set` had no `--status`, so the demotion path had a *reader and no writer*, and `ptx reliability` would show 0% false positives no matter how wrong the probes were. **(b)** The dedupe key was a bare boolean, so once a finding was counted as confirmed it could never be counted again — and a finding is **always** created confirmed and refuted later, the only sequence that ever happens in practice. Now: `finding set --status refuted --refute-reason ...` (a reason is mandatory, since it is the evidence that demotes a probe class), and the dedupe key stores the *outcome* so a transition moves the count instead of being skipped. Verified live: `confirmed=1 refuted=0` → refute → `confirmed=0 refuted=1`, idempotent across repeated syncs, legacy boolean markers migrated |
| **The report told the operator to test endpoints that do not exist** | **MEDIUM** | Coverage scrapes endpoints out of finding titles and evidence, which is prose. The regex was a bare `/anything`, so the banner `server=Werkzeug/3.1.8 Python/3.13.14` yielded `/3.1.8` and `/3.13.14`, and the report then listed both under *"probe `idor` against this endpoint"*. Noise in a coverage list is not harmless: the list is long, and a reader who finds nonsense in it stops reading the rest — which is how the one real gap in it gets missed. A route must now start with a letter, dot, underscore or parameter bracket (`/.env` and `/<id>` are real endpoints; `/3.1.8-beta` is not) |
| **The reliability ledger had the same race** | **HIGH** | Found by asking, after fixing the state.json race, *where else does this codebase rewrite a file wholesale without a lock?* `reliability.record()` was an unlocked read-modify-write with a non-atomic save. Measured: 20 concurrent calls lost 2 increments. Losing one there quietly biases the false-positive rate the demotion decision is made from. Now shares `state._locked` and writes atomically. **The lesson is the follow-up question, not the fix** — one instance of a race means the pattern is worth grepping for |
| **Concurrent invocations silently lost suspicions** | **HIGH** | `state.json` is rewritten whole on every mutation, and an agent orchestrating parallel probes — which is exactly the architecture this toolkit is built for — runs several `ptx` processes against one engagement at once. Two of them read the same state, each append their own entry, and the last write wins. Measured: **20 concurrent probe commands left 13 suspicions, with 7 silently gone**, and `action_count` disagreeing with the append-only log. Nothing crashes; the ledger just quietly understates what was examined, and both the reliability ledger and the report are derived from it. Now every read-modify-write holds an exclusive `flock`, and `_save` writes to a sibling and renames, so a kill mid-write cannot truncate the engagement's whole history. Verified: 20 concurrent probes → 20 suspicions, 20 unique ids, 0 lost |
| **A comment on an exclusion line silently disabled the exclusion** | **CRITICAL** | The hand-written YAML parser did not strip inline comments, so `exclusions:\n  - 10.9.0.0/16  # production DB` parsed as the literal pattern `10.9.0.0/16  # production DB`, which matches no host. The tool then **attacked the production range the operator had just excluded**, printing a confident "in scope: inside CIDR 10.0.0.0/8" while doing it. Writing a comment on the line where you exclude your production database is the most natural thing in the world to do. Flow lists (`exclusions: [10.9.0.0/16]`) failed the same way, stored verbatim as a string. Now: comments stripped with quote awareness, flow lists parsed, CRLF normalised — **and** `Scope` refuses to load any pattern that cannot match a host, because a pattern that matches nothing is an exclusion that does not exclude. Verified end to end: `SCOPE BLOCKED: 10.9.1.1 -> explicitly excluded: matches 10.9.0.0/16`, exit 3 |
| **The Memory Loop demoted probes for being right** | **CRITICAL** | Two senses of "refuted" were added into one counter. In the suspicion ledger, `falsified` means the probe ran and the *suspicion* was falsified — it correctly found nothing. In the reliability ledger, `refuted` means a human rejected the probe's finding. `sync_from_engagement` fed the first into the second, so a probe that correctly reported a clean result four times was demoted: *"4/4 verdicts refuted — output is a lead to verify, not a finding"*. **The better a probe was at reporting clean results, the faster it lost standing.** On a hardened target the Memory Loop demoted every class, telling the operator to distrust the tool precisely when it was working. Correct negatives are now their own counter, shown in the table but deliberately excluded from the FP rate; the real path — a human refuting findings — still demotes (verified 6 refuted / 2 confirmed → demoted, FP rate 0.75) |
| **An unreachable target produced a clean report** | **CRITICAL** | `Http.req` returns `code 0`, an empty body and no headers when the connection fails. `probe_headers` read that empty header set as "every security header is missing" and reported **vulnerable against a host that was not even listening** — the most-run probe in the tool, on every engagement, emitting the most expensive thing it can emit (FP is weighted −4). Every other probe failed the other way: a conclusive negative. Point the tool at the wrong port and it produced a full set of clean verdicts plus a coverage report reading "every class tested, all clean", for a target that was never reached. **A false negative across a whole engagement is worse than a crash, because it is silent.** Now `Http` counts transport failures, `probe_headers` refuses to judge a response that never arrived, and `mark_unmeasured()` — applied centrally in the CLI so future probes inherit it — downgrades any clean verdict whose requests did not complete. The CLI prints `UNMEASURED` and coverage lists the class under "Attempted but never measured" |
| **`ptx recon` crashed with a NameError on a live path** | **HIGH** | `sys.exit(EXIT_NO_RESULTS ...)` — the constant is `EXIT_NORESULT`. So `ptx recon http` against an unreachable host raised `NameError` and exited 1 with a traceback, instead of exiting 2. No test caught it because every recon test used a reachable target. `py_compile` catches syntax, not names; a one-word typo in an exit-code constant is invisible until the branch runs in the field. `TestStaticLintGate` now runs pyflakes over the package and fails on any undefined name or dropped value, and a second test asserts the end-to-end exit code |
| **Recon's coverage gaps never reached the report** | **HIGH** | `ptx recon` printed its gaps, wrote a *count* of them to the action log, and persisted nothing. `ptx report` builds its gap list from `log.md` and the saved JSON artefacts, so "scan intercepted — SCAN INVALID" and "could not reach host — fingerprint unassessed" were shown to the operator once and then absent from the report entirely. The report read as more complete than the engagement was. Recon now writes `engagement/recon/*.json` and `_coverage_gaps` scans it. Tested both directions, plus that one corrupt artefact does not suppress the readable ones |
| **Reachability fingerprinted packages by substring, so prose became evidence** | **HIGH** | `assess()` searched the served page for the package name with a bare `re.search(re.escape(package), served)`. The npm packages `is`, `ms` and `has` all matched ordinary English, so a CVE in **`is` returned `LIKELY` at medium confidence** because the page contained the word "is" — a false positive manufactured by the one module whose stated purpose is to prevent them, and worse than no fingerprint because the operator sees it listed as evidence. Short names (≤3 chars) now need a *structural* position (script src, path segment, JSON key, `name@version`) and longer ones a word boundary, so `express` no longer matches inside `expressly`. Both directions tested |
| **crt.sh results were filtered by substring, attributing attacker hosts to the target** | **HIGH** | `subdomains()` kept any certificate name where `domain in name`. So `notacme.test`, `evilacme.test.evil.com` and — the dangerous one — `acme.test.attacker.example` were all reported as subdomains of `acme.test`. That last is a host on infrastructure the target does not control, presented to the operator as part of the target's estate and then probed. Exactly the scope-exclusion bug again: a second, weaker implementation of "belongs to this domain" living in a different module from the one that does it properly. Now `_belongs()` requires the name to *be* the domain or end with `"." + domain`; `test_scope_and_osint_agree_on_what_belongs` asserts the two modules cannot drift apart |
| **"Could not read the response" was recorded as "tested and clean"** | **SEVERE** | Three probes (IDOR, price-tamper, negative-quantity) swallowed a JSON parse failure and returned `vulnerable=False` — indistinguishable downstream from a probe that ran and found the control working, and `ptx coverage` counted the class as exercised. A real IDOR on a target answering in HTML instead of JSON simply vanished from the report. `reliability.py` had an `inconclusive` outcome all along that nothing could produce. Probes now carry a real flag; `_log_probe` writes it to the structured `verdict` field (it previously inferred inconclusive by string-matching `"INCONCLUSIVE"` in the prose *and* wrote `"negative"` to the field everything reads); coverage lists such classes under **"Attempted but never measured — treat these as gaps, not as clean results."** Both directions tested: an unreadable body is inconclusive, a legible one is a real negative |
| **The rate ceiling did not hold under concurrency** | **SEVERE** | `Http._throttle` had no lock. Ten threads all read the same timestamp, computed the same wait, slept the same interval and fired together — measured against a 5 req/s ceiling, ten parallel requests went out in 203 ms, **48 req/s, about ten times the limit the operator had set**. A rate limit that only works single-threaded fails exactly when the tool is busiest. Fixed with a lock; `probe_race` opts out explicitly via `throttle=False`, because a race test is *defined* by concurrent requests and spacing them would close the window it is trying to hit. Now 5.5 req/s against a 5 ceiling, and the race probe still reports 10/10. Both directions are asserted — the ceiling holds, *and* the burst is preserved |
| **A blank `authorization` stopped nothing** | **SEVERE** | The field was written into scope.yaml, printed in the scope summary, and checked only by `selfcheck` — a report card an operator may never run. An engagement with `authorization:` empty still probed the target. Scope says *where*; authorization says *whether*, and every other gate is meaningless if that one is optional. Now enforced in `require_scope(..., authorized=True)`, which every network-bound command requests. Local-only commands (`report`, `finding list`, `selfcheck`) are deliberately exempt — blocking those would stop an operator inspecting the engagement to work out why they were blocked |
| **`destructive_permitted` gated nothing** | **SEVERE** | The flag was written into scope.yaml, printed in the scope summary, and read by no code at all. Say `false` and the tool still ran `method-tamper` (which invokes a DELETE path), `refund-abuse` (which issues a refund) and `race` (which consumes a single-use resource). A control that exists in the configuration and does nothing is worse than no control, because the operator has read the line that says it is off. There is now a `DESTRUCTIVE` table of eight state-changing classes and a gate that refuses them with exit 3 and logs the refusal |
| **`probe --base` was not scope-gated** | **SEVERE** | `require_scope()` only checked that a scope *file exists*. `ptx probe --base http://evil-not-in-scope.example` attacked it. The safety boundary was not applied to the commands that need it most |
| Rate ceiling was decorative | Medium | `rate_ceiling_rps` was written into scope.yaml and never read; `--rate` defaulted to 0 = unlimited |
| `probe all` ran 2 of 15 probes | Medium | It read as comprehensive while silently skipping 13. Renamed to `unauthenticated` and `all` removed |
| `next_id` collided after deletion | Low | Used `len()+1`; with PTX-001 deleted and PTX-002 present it returned PTX-002 and overwrote the survivor |
| **Coverage omitted the business-logic classes entirely** | **Medium** | The never-run list is built from a hardcoded `TARGETED` set. The four new probes were added to `probes.py` and to the CLI but not there, so an engagement that skipped them printed "never run at all (13)" and named none of the four. A coverage report that omits a whole category reads as complete |
| **`probe-mass-assignment` recorded no action** | **Medium** | The logging call lived inline inside `cmd_probe`'s `run()` closure. This probe has its own subparser and handler, so it produced a verdict, printed it, and logged nothing — coverage then reported mass-assignment as never run *after it had been run* |
| **Reachability suppressed a real vulnerability** | **High** | A lockfile can list the same package twice — hoisted at the root and again nested under another dependency — and the copies can differ in kind. `_dependency_kind` scanned in dict order and returned whichever matched first, so a top-level **production** `lodash` was classified `dev` when a nested devDependency copy came earlier. `assess()` then returned `NOT_PRESENT` and printed *"Do not report as a runtime vulnerability"* about a vulnerability that was reachable. The root install now decides |
| **Business logic absent from the chain model** | **Medium** | Missing from both `GRANTS` and `REQUIRES`, so a confirmed refund-abuse finding could neither anchor a chain nor be de-escalated. `REQUIRES` was the real loss: all four probes return 401 without a session, so their severity is a claim about what an *authenticated* attacker can do — and if that identity was never demonstrated, the number in the report overstates the proven risk |

The exclusion bug had the same shape as the three below it: **two implementations of the
same rule, with different capabilities.** Inclusions and exclusions now go through one
`_matches()` helper, so they cannot drift apart again — and a test asserts `is_in_scope`
calls it exactly twice, once per list. A randomised invariant test then checks 400 generated
combinations of in-scope patterns, exclusions and hosts for the one property that must
never break: *a host matching any exclusion is never allowed*. Reverting the fix fails six
tests.

Three of the others are the same underlying fault: **adding a probe is a four-file change,
and a four-file change will eventually be a three-file change.** So the class list now has a single
source of truth (`coverage.known_classes()`) and the suite cross-checks it against the CLI's
registered choices in both directions, against `chains.GRANTS`, asserts every `cmd_*` that
runs a probe reaches `_log_probe`, and asserts the skipped classes actually appear in the
never-run list. Reverting any of the three fixes fails the suite.

All thirty-seven are now regression-tested. The first is the important one: **a guard that isn't
wired to the dangerous commands isn't a guard.** The scope module was correct; the calls
into it were missing.

### The one the code review missed

**38. `probe-mass-assignment` could only find the two field names it hardcoded.**
`fields={"is_admin": 1, "credits": 99999}` — and the same two names were welded into the
`verify` function that checked whether anything changed. So the probe wasn't testing for mass
assignment, it was testing for mass assignment *of `is_admin` or `credits`*.

This is the only bug on the list found by running the tool against a live target rather than
by reading the code. On 2026-09-11 an operator supplied a guestbook whose privileged field
was called `approved`; the developer had guarded it, and the guard correctly rejected
`approved: true` — but `1`, `"true"` and `"yes"` all stored as approved and published
straight to the public page. The tool reported nothing. I found it by hand, and the tool
would not have.

Two separate faults, both fixed:

- **The field name was guessed instead of read.** The server returns the privileged field in
  its own create response, every time. `discover_gated_fields()` now creates one baseline
  record, reads back the keys the server added itself, and targets the ones it set to a
  restrictive default (`false`, `0`, `"pending"`, `"draft"`). Those are exactly the gates.
  On the live target it derives `approved` with no wordlist and no hint.
- **The guard was tested in one spelling.** A guard written as `if body.get("approved") is True`
  only blocks that one value, so the probe now submits every representation that means true.

Both halves are load-bearing and both are mutation-verified: pin `_TRUTH_VARIANTS` to
`(True,)` and V26 becomes a false negative; replace discovery with the old hardcoded names
and V26 becomes a false negative. N07 is the falsification twin — same endpoint shape, same
echoed boolean, correct allowlist — and a probe that flags it is detecting "a create
endpoint that echoes a record", not mass assignment.

The general lesson is the same one as #27 and #29: **a probe that embeds the answer can only
ever find that answer.** It looks like coverage because it runs, sends requests, and reports
a clean result.

**39. `probe_idor` had the same fault, and the obvious fix made it worse.**
The verdict was `ok and owner is not None`, where `owner` came from one hardcoded field
name. An object carrying `author_id`, `owner` or `created_by` was reported clean — a real
cross-user read, invisible because of a guess.

The obvious fix is to widen the guess: match any field ending in `_id`. That is exactly
wrong, and it took a falsification target to show it. A public, ID-scoped object whose
`category_id` differs between two records satisfies any `*_id` heuristic, so the widened
probe flagged it as an IDOR. Trading a false negative for a false positive is not a fix —
on the scorecard it cost more, since a false positive is weighted −4 against a true
positive's +3.

The resolution is that the two signals are not equally trustworthy. **A field name is a
guess about the data model. Whether an unauthenticated caller can read the object is not a
guess at all.** So the probe now sends a third request — the same object with no cookie —
and that control decides:

| anonymous read | verdict |
|---|---|
| refused, and a differing ownership marker exists | **vulnerable** — another principal's private object |
| refused, no ownership marker found | **inconclusive** — unmeasured, never "clean" |
| allowed, body byte-identical | **not vulnerable** — public object, no boundary crossed |
| allowed, body differs | **vulnerable** — authentication exposes more than the public view |

The marker is still discovered by diffing our object against theirs rather than assumed,
but it corroborates the control instead of replacing it.

Both halves are mutation-verified and each isolates one piece: restore the single hardcoded
field and V27 becomes a false negative; disable the anonymous control and N08 becomes a
false positive.

The lesson generalises: **when a probe needs to distinguish two situations, prefer the
oracle that observes behaviour over the one that inspects names.** Names are the
application's vocabulary and we are guessing at it. Behaviour is the thing we can actually
measure.

---

## Coverage — what was not tested

A report that lists findings is half a report. The other half is the statement of what
was never examined, because a reader cannot distinguish an absence of findings from an
absence of testing.

`ptx coverage` derives this from the structured action log rather than from anyone's
memory. It reports probe classes never invoked, endpoints never probed, and specific
(probe, endpoint) combinations not exercised:

```
- probe classes exercised: exposure, headers, idor, jwt-none, sqli
### Never run at all (10)
`cmdi`, `mass-assignment`, `method-tamper`, `race`, `redirect`, `ssrf`, `ssti`, ...
**Unambiguous gaps:** `headers` need no parameters and should always run.
```

The third category is the one that catches a quietly aborted engagement. Every probe
reports a result, so a run that stopped after two probes still looks like a completed
run unless something counts what is missing.

Two requirements this exposed:

**The log had to become machine-readable.** `log_action` wrote prose to `log.md` and a
single integer to `state.json`, so no tool could answer "which probes ran against which
endpoints". A log a program cannot read supports claims, not checks.

**It had to stay cheap.** The first structured version embedded the history inside
`state.json` and rewrote the whole file on every action — measured 0.97 ms/action at 200
entries rising to 7.89 ms at 2000, so the one operation that runs most often got steadily
slower. It is now an append-only JSONL file at a flat 0.08 ms/action.

Noise control matters as much as completeness. Suggesting `sqli` against `/.env` is not
coverage, and a list a reader must filter mentally gets skimmed and then ignored — so
static files are excluded and `/api/invoices/<id>` is normalised to the `/api/invoices`
that was actually tested.

## Reconnaissance

Four subcommands, all scope-gated: a host that is not in `scope.yaml` is refused with
exit 3 before anything is sent.

**Ports.** A TCP connect scan using no raw sockets, so no root. Three states are kept
distinct — `open`, `refused`, `filtered` — because a refused connection means a host
answered and said no, while a timeout means something dropped the packet. That
distinction is the evidence that a firewall exists, and collapsing it throws the
information away.

**The scan validates itself.** A successful `connect()` does not mean the target is
listening. Every scan includes control ports that cannot legitimately be open; if one
reports open, the whole scan is declared `SCAN INVALID` and no open port is reported.

This was not a theoretical concern. This sandbox has a transparent egress proxy that
accepts every outbound connection, and the first version of the scan reported
`192.0.2.1:80` open — an RFC 5737 TEST-NET address that is guaranteed unroutable. It also
"opened" `198.51.100.7:9999` and `203.0.113.1:22`. Corporate egress proxies, NAT gateways
and captive portals do exactly this, so a connect scan that cannot detect interception
reports 100% of ports open and is worse than no scan at all.

**TLS.** Certificate subject, issuer, SAN coverage, expiry in days, negotiated protocol
and cipher. A failed handshake is reported as a coverage gap — "certificate quality
unassessed" — never as a clean result.

This module was broken and looked fine. With `verify_mode = CERT_NONE`, Python's
`getpeercert()` returns an **empty dict** — the certificate is only parsed once
verification succeeds. The first version read it directly, so every certificate check
(self-signed, expiry, SAN coverage) evaluated against nothing and reported zero findings
for every certificate ever presented. Protocol and cipher still worked because they come
from the socket, which made the module look alive while its main job did nothing.

The fix decodes the DER, which is available regardless of verification. Verified against
four generated certificates — valid, expired (−950 days, High), expiring in 9 days
(Medium), and issued for a different hostname (Medium) — plus a good certificate that
must raise no finding, and a non-TLS port that must raise a coverage gap rather than a
clean result. The regression test was confirmed to fail when the bug is reintroduced.

**HTTP.** Server identity, cookie flags (a session cookie without `HttpOnly` is a real
finding, not a nitpick), advertised methods, missing security headers, and identity hints
from the body with a confidence rating, because a generator meta tag and a Python
traceback are not equally strong evidence of what is running.

## Attack-surface discovery — the baseline is the feature

`ptx discover` answers "which endpoints exist". The interesting part is not the crawling,
it is how "exists" is decided.

A scanner that treats HTTP 200 as "found" reports its entire wordlist against any
application that answers unmatched routes with a 200 error page. That result is not noisy,
it is worthless — and it reads as thoroughness, which is worse than being obviously wrong.

So `discover` measures the not-found signature first, by requesting paths that cannot
exist, and a candidate counts only when it differs observably: a different status, a
materially different length, or a redirect.

The mutation test makes the size of this concrete. Replace the baseline with "200 means
found" and the soft-404 fixture produces **60 discoveries from a 60-path wordlist** —
perfect recall, zero information. With the baseline it finds the two real pages and
nothing else.

Candidate sources, best first:

1. **Paths the application references** — `href`/`src`/`action` attributes and the string
   literals in its JavaScript. Not guessing; the app is telling us.
2. **Paths derived from what was found** — `/api/notes` implies `/api/notes/1`.
3. **A small built-in list.** Deliberately ~50 entries. A large wordlist is only worth
   anything once the baseline is trustworthy, and against a soft-404 target it mostly
   measures how many ways an application can say no.

Two safety properties, both mutation-verified:

- **Off-host links are dropped, not followed.** A scanner that wanders onto a third party
  gets someone's engagement cancelled. Removing the filter makes the test suite fire.
- **An unreachable target reports `UNMEASURED`, never an empty attack surface.** Exit 5.

`--methods` additionally asks `OPTIONS`/`POST`/`PUT`/`DELETE`/`PATCH` on each discovered
path, which is how an `Allow` header the application never meant to publish gets found.

---



`ptx chain` classifies each confirmed finding by the *capability* it grants and reports
which further findings that capability unlocks. A leaked `.env` and a broken IDOR reported
separately are Medium and High; together the `.env` is Critical, because it hands over the
identity the IDOR assumes.

```
### PTX-001 — Sensitive file exposure
- High -> **Critical** — escalates because it unlocks 1 further finding(s)
- demonstrated: `identity, read, secret`
- terminus: a usable identity, including administrative; harvested credentials or signing keys
  - unlocks **PTX-002** (IDOR) — grants `identity`: reads another user's object
```

Two hard rules, both from producing the wrong answer first:

**No transitive capability algebra.** The first version propagated capabilities forward
(`secret → identity → read → secret`), which cycled and granted every capability to every
finding — escalating 7 of 13 findings to Critical, including a reflected XSS. A link here
exists only when one finding's demonstrated output satisfies another finding's stated
assumption, at most one hop.

**Secrets are never inferred from narrative prose.** The second version keyword-matched
the finding's own text, so an impact statement saying "may contain secrets" was read as
secrets having been leaked, and traversing a file named `secret.txt` was credited with
credential disclosure. Only the probe that retrieved the body declares what it held, and
only on a concrete assignment or a recognised token shape.

The command also runs the direction no scanner performs — **de-escalation**. A finding
whose severity assumes a capability that nothing in the engagement demonstrated is
reported as overstated. A Medium that cannot be reached overstates risk exactly as much
as a false positive does.

### Walking a chain instead of inferring one

`ptx chain --walk --base <url>` stops inferring and starts demonstrating. For each
exposure finding it re-fetches the leaked file, extracts the signing key, **mints a
validly-signed HS256 token carrying `role: admin`**, presents it, and checks whether the
endpoint actually granted the claims:

```
### PTX-001 leaked signing key -> forged identity — DEMONSTRATED
- re-fetch the leaked file /.env [HTTP 200] — 262 bytes
- extract candidate signing keys — ['APP_SECRET', 'AWS_SECRET_ACCESS_KEY']
- present a token signed with APP_SECRET [HTTP 200]
- verify the endpoint granted the forged identity — granted=True

**The signing key `APP_SECRET` was read from the exposed file and used to mint a
validly-signed HS256 token carrying role=admin. The endpoint accepted it. The exposure
is not information disclosure — it is identity forgery.**
```

A third walk covers the case the chain table could only infer. `chains.GRANTS` says
jwt-none grants `identity`, and `chains.REQUIRES` says idor, race and the four
business-logic classes all *assume* an authenticated identity — so their severity is
downgraded when that identity was never demonstrated. Table lookup is not evidence, so
`ptx chain --walk --walk-admin-endpoint <path>` forges an unsigned `alg: none` token
claiming `role: admin` and presents it:

```
### PTX-001 unsigned alg:none token -> admin identity accepted — DEMONSTRATED
- call /api/me with no credentials (baseline) [HTTP 401] — must be refused, or the forged token proves nothing
- forge an alg:none token claiming role=admin — claims={'uid': 999, 'role': 'admin'}
- call /api/me with the forged token [HTTP 200] — {"claims":{"role":"admin",...},"granted":true}
```

**The baseline step is the whole argument.** An endpoint that accepts anonymous requests
will also accept the forged token, and reporting that as a demonstrated privilege
escalation would be precisely the manufactured chain this module exists to avoid. So the
walk refuses to call anything demonstrated unless the endpoint first said no:
`NOT_DEMONSTRATED — the endpoint is simply unauthenticated`.

Three outcomes, and only the first earns the escalated severity:

| verdict | meaning | effect on severity |
|---|---|---|
| `DEMONSTRATED` | every step executed, final effect observed | escalation **earned** |
| `NOT_DEMONSTRATED` | steps executed, chain broke | escalation **WITHDRAWN** |
| `CANNOT_ATTEMPT` | precondition missing | escalation stays labelled *inferred* |

The middle row is why the module exists. An inferred escalation that fails when attempted
is a false positive wearing a Critical label and a plausible narrative — worse than an
ordinary false positive, because it is the one a reader is most likely to act on.

A subtlety worth keeping: the grant check compares against a space-stripped haystack, so
the needle must be stripped too. The first version searched for `"granted": true` inside
a string whose spaces had already been removed. The primary signal never fired; a
secondary role-match fallback kept the live run passing and hid it.

The leaked secret value is never reproduced in the report.

## Secret detection

`probe exposure` and `probe traversal` now state what a retrieved file actually contained,
not merely that it was reachable:

```
/.env (262b, sensitive file with credential material)
```

Detection combines name-based matching (`*_SECRET`, `*_KEY`, `*_TOKEN`, `*_PASS`,
`*_CREDENTIAL`) with value-shape matching (`AKIA…`, `sk_live_…`, `ghp_…`, `xox?…`, `AIza…`,
PEM blocks, JWTs, connection strings with embedded credentials). Placeholder values
(`changeme`, `example`, `your_token_here`, `xxxxxxxx`) are rejected — reporting a
placeholder as a leaked credential sends a team hunting for a key that does not exist.

The first version of this found 2 of the 6 credentials in the benchmark's `.env`.

## Probe reliability — the Memory Loop

`ptx reliability` tracks, per probe class, how often its VULNERABLE verdict survived
contact with a human or with the finding validator. One refutation in three demotes a
probe from *evidence* to *lead generation*: it still runs and still reports, but its
output requires independent confirmation before it may be written up.

The threshold is deliberately strict, because this project weights a false positive
heavier than a true positive. Below three decided outcomes the probe stays trusted and
the table says the sample is too small — a rate computed from noise is worse than no rate.

## Evidence integrity

Every finding is sealed at the moment of confirmation: a SHA-256 over its evidence,
impact, reproduction, summary, title, severity and artifact list, plus a per-file digest
for each artifact. `ptx verify` re-checks all of them; `selfcheck` fails on any drift.

This is the direct countermeasure to the observed failure mode where an automated agent
reported success its own recorded output did not support. Self-report is not evidence, and
an unsealed finding is self-report.

Three distinctions the design keeps separate:

| Situation | Verdict |
|---|---|
| Evidence, impact or artifact list edited after sealing | **EVIDENCE DRIFT** — hard failure |
| Artifact present at sealing, now gone or rewritten | **DRIFT** — hard failure |
| Artifact never existed on disk at sealing | **note** — a finding-quality problem, not tampering |
| Finding recorded before sealing existed | **NOT SEALED** — run `ptx seal <id>` |

Editing evidence is not forbidden — it sometimes legitimately needs correcting. The
requirement is that the edit is visible.

---

## Severity ladder

Chain escalation moves a finding up a severity ladder. Two bugs lived in one line here,
and both were silent:

1. The ladder said `Informational` while `findings.SEVERITIES` says `Info`. `_bump("Info")`
   hit a `ValueError` branch and returned `Info` unchanged, so an Info finding that
   unlocked three others never escalated — with no error anywhere.
2. The obvious fix — import `findings.SEVERITIES` — **inverted the ladder**, because that
   tuple is ordered for display, Critical first. `_bump("High")` then returned `Medium`,
   so every chain escalation in the tool was quietly a de-escalation.

The ladder is now explicit and ascending, asserts it matches `findings.SEVERITIES` at
import time, and is pinned by a test that walks it in both directions.

## Randomised differential testing — breaking the benchmark's circularity

The benchmark has a structural weakness that no amount of internal testing can fix: the
vulnerable target and the oracles that grade against it were both written here. A score of
59/59 could mean the probes generalise, or merely that they fit those specific endpoints.
Nothing inside that loop can tell the difference.

`tests/property_targets.py` breaks the loop. A seeded generator builds applications whose
every endpoint is randomly either vulnerable or correctly implemented, and **ground truth
comes from the generator's own decisions**, not from a curated oracle list. The probes are
then run against applications they have never seen.

```
decisions        : 480 across 40 generated applications   (12 classes)
FALSE POSITIVES  : 0
false negatives  : 0
false-pos rate   : 0.000   (the metric that matters most)
```

Twelve classes are generated: sqli, xss, cmdi, traversal, redirect, ssti, headers, the four
business-logic ones, and csrf. The business-logic generators share mutable account state, so
a probe cannot pass by reading a response — it has to observe the balance move.

CSRF is generated with **two independent defences** randomised separately — whether the
endpoint checks `Origin`, and the session cookie's `SameSite` value. Ground truth is the
combination, so the endpoint is exploitable only when it fails the Origin check *and* the
cookie is not Strict or Lax. Varying one at a time would let a probe that only looked at one
of them score perfectly. Across 50 seeds all eight combinations appear, and the probe is
handed the login response headers rather than the `SameSite` value, so its own derivation
path is exercised too.

It found three defects the benchmark never surfaced:

| Defect | Where | Why the benchmark missed it |
|---|---|---|
| Reflected-XSS **false positive** on a JSON response | probe | The benchmark's JSON "trap" never actually reflected the payload, so the case was never exercised. Reflecting into `application/json` is not XSS — the browser parses it as data |
| SQL-injection **false negative** when the baseline matches nothing | probe | The rule required the true-branch to equal the baseline. With baseline=0, true-branch=5 (the entire table), false-branch=0, a textbook injection was reported as not vulnerable |
| SQL emulator too naive to evaluate `'1'='1'` | harness | The disagreement looked like a probe failure. It was the test's own SQL model; fixing the probe for it would have been exactly wrong |

The third is the reason the harness matters more than its pass rate. Two of the three
disagreements were real probe defects and one was the harness being wrong, and the only
way to tell them apart was to look at the actual traffic. A harness that can be wrong is
still worth building, because it produces disagreements to investigate — a curated
benchmark produces none.

A fourth bug appeared while fixing the third: stripping whitespace before matching glued
the `AND` keyword onto its operand, so `AND'1'='1` parsed as `AND1 = 1` and every
comparison looked false.

### A fifth: the generator's own ground truth was skewed

Extending the generator to business logic meant auditing the per-class balance, and
`headers` had produced **60 vulnerable endpoints and zero safe ones** across 60 seeds while
still reporting 0 FP and 0 FN. Its truth was derived from five independent coin flips —
"vulnerable if any header is missing" — so a safe variant needed all five heads, 1 in 32.
A probe that answered *vulnerable* unconditionally would have scored perfectly against it.

**Skewed ground truth is vacuous ground truth**, and an aggregate count of "some vulnerable,
some safe" hides it completely. The generator now decides the verdict first and derives the
headers from it, and the suite asserts *per class* that both variants appear — reverting
that generator fails the test with `{'headers': {'vuln': 25, 'safe': 0}}`.

The suite also asserts the generator produced **both** vulnerable and safe endpoints,
because a generator that only produced one kind would make the two headline tests pass
vacuously.

## Business logic — four classes a scanner cannot see

Technical probes compare two responses. Business-logic flaws cannot be found that way: a
correctly-rejected negative quantity and an accepted one **both return HTTP 200**. So each
of these probes is handed a way to observe the resulting state and asserts on the *effect*.

| Class | Probe | What it proves |
|---|---|---|
| Negative quantity | `probe negative-qty` | `qty=-3` **credits** the account: balance 100 → 247 |
| Client-supplied price | `probe price-tamper` | catalog 199.00, charged 0.01 — 0.01% of list |
| Refund without an order | `probe refund-abuse` | non-existent order 999999 pays out 5,000 |
| Workflow bypass | `probe workflow-bypass` | 409 without the gate, 200 asserting `validated: true` |
| Cross-site request forgery | `probe csrf` | POST with a foreign `Origin` changes the account email |

```bash
ptx probe negative-qty  --base URL --path /api/cart     --sku WIDGET \
                        --balance-path /api/credits --cookie "sid=..."
ptx probe price-tamper  --base URL --path /api/checkout --sku GADGET
ptx probe refund-abuse  --base URL --path /api/refund   --balance-path /api/credits
ptx probe workflow-bypass --base URL --path /api/order/confirm
```

The hardened twin implements the control each probe looks for, and all four correctly report
*not vulnerable* against it — `qty=-3` gets HTTP 422, the tampered price is echoed back as
`client_price_ignored` while the catalog price is charged. That matters more here than
anywhere else: a tester who chases invented logic flaws stops believing the real ones.

These were the classes the 2025 Stanford/CMU/Gray Swan study found AI frameworks weakest
at, alongside GUI interaction.

CSRF is deliberately not in that table: it is a technical class, but it needed the same
effect-based design. "No token in the form" is the single most common CSRF false positive,
because the defence may live in a cookie attribute or an `Origin` check the probe never
provoked. `probe_csrf` therefore requires **all four** preconditions before it says
anything: cookie-based auth, a non-blocking `SameSite`, acceptance of a foreign `Origin`,
and an observed state change. With `--samesite Lax` it reports *not vulnerable* even against
an endpoint that accepts the request and mutates state — because a browser will not deliver
that cookie cross-site, so there is no attack to report.

## Why the benchmark lied twice — instrumentation bugs

Both times the scorecard produced a wrong number, the target was fine and the
**instrument** was broken. Neither failure looked like an error; both looked like missed
vulnerabilities.

**1. The target restarted itself when I edited a different file.** It ran with debug mode
on, whose reloader watches every `.py` in the directory. Editing `scorecard.py` restarted
the target and wiped its in-memory session store, so every later authenticated oracle got
401 and was recorded as a false negative. Score fell 71/71 → 46/71 with **zero transport
errors anywhere** — a wrong measurement caused by a text editor. Fixed by forcing
`debug=False, use_reloader=False`. A measurement instrument must not restart itself because
a neighbouring file changed.

**2. Four oracles matched Flask's *pretty-printed* JSON.** They substring-matched
`'"deleted": true'` — with a space after the colon. Flask only pretty-prints in debug mode,
so those checks were silently coupled to the debug setting. Turning the reloader off made
`jsonify` emit compact `{"deleted":true}`, and V10, V12 and V17 flipped to false negatives
while their own evidence strings still showed the vulnerability present. They now parse the
JSON. Matching rendered output is not the same as checking a value.

The scorecard now refuses to present a score as clean when either condition recurs — it
counts transport failures and flags any oracle that saw `auth required`, and prints an
**INSTRUMENTATION WARNING** instead of a detection result. It also aborts outright if it
cannot obtain a session, because then every authenticated check would silently become a
false negative.

After the fixes: **71/71 across six consecutive runs, editing a file before each.**

## Test suite

```bash
python3 tests/test_ptx.py          # 493 tests (incl. randomised differential testing)

python3 tests/property_targets.py 40    # 280 decisions against generated applications
PTX_PROP_SEEDS=100 python3 tests/test_ptx.py   # more seeds
```

The suite runs every probe against **two targets** — the deliberately vulnerable benchmark
app and a hardened twin (`tests/safe_target.py`) that implements the same routes correctly.
A probe suite that only tests against a vulnerable target can never detect a probe that
reports everything as vulnerable, and false positives are the documented failure mode.

What it caught on first run:

| Real bug in ptx | How it showed up |
|---|---|
| `probe_headers` false positive | Fired on Werkzeug's *own default* `Server` header, which a hardened target cannot remove via `after_request`. Banner disclosure now means application-set disclosure |
| `probe_ssti` false positive | Matched the literal word "class", so a target that echoes the payload back was reported vulnerable. Now requires a resolved object repr and rejects verbatim echo |
| `probe_sqli` false negative on safe code | Against a parameterized query both branches matched nothing, so it shrugged `INCONCLUSIVE`. Added error-based discrimination so it reaches a **conclusive negative** |
| `probe_sqli` under-detection | With the wrong injection context it reported inconclusive on a genuinely injectable endpoint. Error-based detection now catches it regardless of context |

Plus five of my own test bugs, including a hardcoded "clean" lodash version that OSV
returned three advisories for — the assumption was stale, which is the entire argument for
live lookup.

---

## Measuring the test suite itself

The suite had never been measured, so "157 tests" said nothing about what they reached.
Running it under branch coverage:

```
ptxlib/chains.py          95%      ptxlib/reachability.py   84%
ptxlib/chainwalk.py       87%      ptxlib/recon.py          83%
ptxlib/cve.py             95%      ptxlib/reliability.py    85%
ptxlib/coverage.py        82%      ptxlib/report.py         79%
ptxlib/findings.py        88%      ptxlib/scope.py          88%
ptxlib/integrity.py       94%      ptxlib/state.py          86%
ptxlib/probes.py          94%      ptxlib/osint.py          68%
TOTAL                     86%
```

The remaining gaps are concentrated in the two modules that talk to the outside world.
`osint.py` at 68% is the crt.sh and Wayback success paths, which have never completed from
this sandbox (crt.sh returns 502, the CDX endpoint times out); the *parsing* of those
responses is tested against a local fake, but the real HTTP round trip is not. `recon.py`
rose from 72% to 83% when `render()`'s TLS and HTTP branches were fed real producer output
rather than a hand-written dict — the same discipline that exposed four earlier renderer
"bugs" as four wrong fixtures.

```bash
python3 -m coverage run --source=ptx/ptxlib,ptx/ptx.py --branch tests/test_ptx.py
python3 -m coverage report -m
```

The number is not the point; what it pointed at is. The five `render()` functions — the last
code to touch a result before a human reads it, running exactly once per engagement — were
among the least-exercised in the package. They are now tested by feeding each one the real
output of the function that produces its input, rather than a hand-written approximation:
an approximation encodes the author's guess about the contract, which is the same
circularity the property tests exist to break.

Worth recording what that did *not* find. Four renderers raised exceptions against
hand-built input, and every one was the hand-built input being wrong — `chains.render` wants
`entry`/`entry_title`, ports carry a `state`, `record()` takes
`confirmed|refuted|inconclusive`. No bug. The honest version of this exercise is checking
the producer's real output before believing the disagreement.

### Making the untestable testable

`osint.py` was the worst at 40%, and the reason was structural: the crt.sh and Wayback CDX
URLs were hardcoded inside the functions, and neither service has ever completed a request
in this sandbox. So the parsing code — where the fabricated-DMARC bug lived — could not be
executed by anything.

Both endpoints are now module-level constants (`CRTSH_URL`, `WAYBACK_URL`), which is useful
in its own right for mirrors and corporate proxies, and lets a local server stand in. Seven
tests now drive the real functions against canned responses.

The cases that matter are not the happy paths. They are the ones where a source fails, and
each is paired with its converse:

| Response | Must be reported as |
|---|---|
| HTTP 502 from crt.sh | `source_error` — a **coverage gap** |
| Malformed HTML instead of JSON | `source_error` — a coverage gap |
| `[]` from crt.sh | zero results, **no error** — a real answer |
| HTTP 504 from Wayback | `error` — a coverage gap |
| Empty CDX body | zero URLs, **no error** — a real answer |

Mutating `subdomains` to swallow the exception fails exactly the two tests that guard the
distinction. **A failed query reported as zero results reads as "clean" when it is
"unmeasured"**, and that is the single most dangerous output a recon tool can produce.

The same treatment lifted `recon.py` from 54% to 72%: `http()` and `run()` were only ever
exercised against a live host, and both take a URL, so a local server can stand in. Those
tests pin the confidence levels on identity hints — a `generator` meta tag is MEDIUM
evidence, a database driver in a stack trace is HIGH — because a check that flattens them
produces findings nobody trusts.

`cve.py` reached 95% the same way — `OSV_URL` was already a constant, so a local server could
serve canned advisories and drive the real query and audit code. The case that matters is a
503 from the advisory API: the package must land in `errors` as **unaudited**, never in the
`clean` list, where it reads as verified safe.

What remains uncovered is honest: live TLS handshakes against a real remote host.

## What was NOT verified

- **`crt.sh` and Wayback never returned data here.** Both modules are written and fail
  honestly, but neither has produced a real subdomain list or URL history in this
  environment. They need a network that can reach them.
- **Reachability is heuristic, not proven.** `LIKELY` means "server-side and loaded", not
  "the vulnerable function is called with user input". Closing that properly needs source
  access or grey-box testing.
- **Rate limiting is per-probe only** (`--rate`), not enforced globally from scope.yaml.
- **Live OSINT sources are unproven here** — crt.sh and Wayback were unreachable from this
  sandbox; both fail honestly with exit 5.
- **Report has no attack-narrative section.** Findings are listed individually; the chains
  that connect them are not assembled. That's the part that lands with executives.

---

## Layout

```
ptx/
  ptx.py              CLI entry point, argument parsing, exit codes
  ptxlib/
    scope.py          the safety boundary
    cve.py            live OSV.dev lookup — never from memory
    osint.py          passive collection with honest failure modes
    state.py          engagement state, action log, Suspicion Ledger
```

No required third-party dependencies — Python 3 stdlib only, plus `dig` for full DNS
coverage (degrades to a reported gap without it). One optional extra: `z3-solver`, used
only by `probe_constraint_logic`; without it that probe reports inconclusive and the rest
is unaffected.
