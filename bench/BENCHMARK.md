# BENCHMARK — how the methodology is measured

A benchmark harness that scores detection against known ground truth, with **false positives
weighted more heavily than true positives**.

## Why the weighting is asymmetric

The December 2025 Stanford / Carnegie Mellon / Gray Swan study put 10 OSCP-certified humans
against 7 AI agent frameworks on a live 8,000-host network. The best AI framework placed
second overall, ahead of 9 of the 10 humans — **and still carried a higher false positive
rate than every single human tested.** It also specifically struggled with business logic and
GUI interaction.

So the thing to measure isn't whether the tool finds bugs. It's whether it stays accurate
while finding them. Hence:

| Outcome | Weight | Rationale |
|---|---|---|
| True positive | **+3** | A real find |
| False positive | **−4** | Weighted heavier than a hit is worth. This is the documented AI failure mode |
| False negative | **−2** | Invisible damage — never appears in the report |
| Correct negative | **+1** | Explicitly tested and correctly recorded as absent |

A run that finds everything but reports three false positives must score worse than a run
that finds less and stays accurate. That's the point.

---

## Running it

```bash
cd /home/user/bench
pip3 install flask requests          # sandbox resets wipe packages
python3 target_v2.py &               # vulnerable target on 127.0.0.1:5001
python3 scorecard.py                 # runs every oracle, prints the scorecard
```

Output goes to `engagement/artifacts/scorecard.json`.

## Ground truth

**28 planted vulnerabilities and 9 deliberately-absent conditions** (the counts below are historical; the suite has grown). Both are listed in
`EXPECTED.md`, recorded **before** any probe ran, so the scoring is a test and not a
confirmation exercise.

**Planted (18):** IDOR, SQL injection, reflected XSS, command injection, secret exposure
(`.env`), secrets in JS bundle, missing function-level authz, race condition, stored XSS,
SSRF, path traversal, JWT `alg=none`, open redirect, mass assignment, exposed dependency
manifest, no rate limit + user enumeration, HTTP method tampering, template injection.

**Deliberately absent (5) — reporting any of these is a false positive:**

| ID | Non-vulnerability | Why it's a trap |
|---|---|---|
| N01 | SQLi on `/login` | Username goes through a **parameterized** query |
| N02 | Null-byte path truncation | Modern Python rejects; no truncation occurs |
| N03 | XSS via the JSON API | `application/json` isn't rendered as HTML by browsers |
| N04 | Command injection via `&&` | `ping` fails without raw sockets, so the chained command never fires — **a metacharacter is not a vulnerability** |
| N05 | CORS as a standalone Critical | Real misconfiguration, but needs a victim browser; Medium at most |

N04 is the most instructive trap. `;` works on that endpoint and `&&` doesn't, for a reason
that has nothing to do with injection filtering. An agent that reports "command injection"
because it saw a shell metacharacter accepted will fail this test.

---

## Results

### First run — 39/59

```
planted found      : 15/18   detection rate 0.833
absent correctly   : 4/5     false-positive rate 0.2
precision          : 0.938
weighted score     : 39 / 59  (0.661)
MISSED  : V11, V15, V17
FALSELY REPORTED: N04
```

### After diagnosing every failure — 59/59

```
planted found      : 18/18   detection rate 1.0
absent correctly   : 5/5     false-positive rate 0.0
precision          : 1.0
weighted score     : 59 / 59  (1.0)
```

### The four failures, diagnosed

| Failure | Actual root cause | Whose bug |
|---|---|---|
| V11 path traversal missed | Target hardcoded `/home/user/dryrun/files/`, a directory deleted when the earlier project was scrapped | target |
| V15 lockfile missed | Oracle regex `": \{"` couldn't span the pretty-printed newline | oracle |
| V17 method tampering missed | Flask rejects POST at the **routing** layer before the override handler ever runs | target design |
| N04 false positive | **Oracle inverted** — `found = not ok` scored a correct negative as a false positive | oracle logic |

### The fifth failure — found later, and the most instructive

After fixing those four and recording a clean 59/59, I re-ran the benchmark to confirm
reproducibility. It scored **54/59, missing V08**.

The race-condition test is **not idempotent**. The first run consumed the `WELCOME50` code,
so on the second run the code was already redeemed, every parallel request correctly got
"already redeemed", and the oracle correctly reported no race. A **false negative produced
by stale state, not by a detection failure.**

Fixed by adding `POST /benchmark/reset` to the target and calling it at the top of every
scorecard run. Three consecutive runs now all score 59/59.

The lesson generalizes well past this harness: **a stateful benchmark that doesn't reset is
measuring its own previous run.** Any test suite with ordering dependencies between cases
will eventually report a failure that isn't a failure — and worse, will eventually *hide* one
that is. This is the same class of error as the inverted oracle: the measurement instrument
was wrong, not the subject.

---

## The honest reading

**The perfect score is not the finding.** A harness that scores 100% on its first run proves
nothing — it might not discriminate at all.

The finding is that the harness **caught four real bugs**, including one where the scoring
logic itself was inverted and would have reported a false positive that did not exist. That's
what makes it a harness rather than a demonstration.

Note what all four bugs have in common: **every one was in my own code, not the target's.**
The Sophos investigation into an AI-built malware lab found the same pattern in the wild —
the attacker's agents self-reported near-universal evasion success that their own documented
test output did not support. Self-report is not evidence, and a harness that grades itself is
not a harness.

That's the concrete argument for the **Falsifier** (`frontier-systems.md` §1): the N04 bug
was a false claim about safety that survived until I happened to go looking for it.
Self-review found it. Independent falsification would have found it automatically.

---

## What this benchmark cannot tell you

- **It tests my oracles against a target I built.** That's inherently circular — I know where
  the bodies are buried. The 18/18 measures whether the *detection techniques* work, not
  whether an agent would *think* to run them.
- **It has no OSINT surface.** `127.0.0.1` has no WHOIS, no crt.sh, no Wayback, no GitHub.
  The highest-signal phase in the whole methodology remains unvalidated.
- **No real dependency surface.** The lockfile is planted, so the version→CVE pipeline's live
  lookup stage was never exercised against OSV.dev or NVD.
- **No AI components.** Echo's entire test matrix is unexercised.
- **Business logic is thin.** One race condition. That's the category the Stanford/CMU study
  found AI specifically bad at, and it's under-represented here.

To close these you need a real domain and a real target with known-vulnerable dependencies.

---

## Extending it

Add a vulnerability to `target_v2.py`, add its ID and oracle to `EXPECTED.md`, add the
`record(...)` call to `scorecard.py`. Two rules:

1. **Write the ground truth before writing the oracle.** Otherwise you're encoding your
   assumption into both and the test can't fail.
2. **Add a trap for every vulnerability you add.** The false-positive half of the benchmark
   is the half that matters, and it's the half that's easy to neglect.

Regression discipline: if a change to the prompts or probes moves the score, find out which
line moved and why before accepting it. A score that improves for the wrong reason is worse
than one that doesn't improve.

## Extending to business logic — 22 planted, score 71/71

The original 18 were all *technical* classes: compare two responses, look for a difference.
Four business-logic classes were added (V19–V22: negative quantity, client-supplied price,
refund without a valid order, workflow-step bypass) because these are precisely where the
2025 Stanford/CMU/Gray Swan study found AI frameworks weakest.

They forced a different probe design. **A correctly-rejected negative quantity and an
accepted one both return HTTP 200**, so no response comparison can distinguish them. Each
probe is instead handed a way to observe account state and asserts on the effect:

| | Vulnerable target | Hardened twin |
|---|---|---|
| `qty=-3` | balance 100 → **247** (credited) | HTTP 422, balance unchanged |
| `unit_price=0.01` on a 199.00 item | charged **0.01** | charged **199.00**, `client_price_ignored: 0.01` |
| refund of order 999999 | pays out **5,000** | HTTP 404, balance unchanged |
| `validated: true` | HTTP **200**, order confirmed | HTTP **409** on both paths |

All four fire on the vulnerable target and stay silent on the hardened one. Nine tests cover
them in both directions, including one asserting the hardened twin really *charges the
catalog price* — otherwise the four "not reported" tests would also pass against an endpoint
that simply did not exist.

## The benchmark lied twice more — and both times it was the instrument

Neither failure looked like an error. Both looked like missed vulnerabilities, which is the
worst possible presentation for a wrong measurement.

**The target restarted itself when I edited a different file.** It ran with debug mode on,
whose reloader watches every `.py` in the directory. Editing `scorecard.py` restarted the
target and wiped its in-memory session store, so every later authenticated oracle got 401
and was recorded as a false negative. The score fell from 71/71 to 46/71 with **zero
transport errors anywhere** — a wrong measurement caused by a text editor. Fixed by forcing
`debug=False, use_reloader=False`. A measurement instrument must not restart itself because
a neighbouring file changed.

**Four oracles matched Flask's *pretty-printed* JSON.** They substring-matched
`'"deleted": true'` — with a space after the colon. Flask only pretty-prints in debug mode,
so those checks were silently coupled to the debug setting. Turning the reloader off made
`jsonify` emit compact `{"deleted":true}`, and V10, V12 and V17 flipped to false negatives
*while their own recorded evidence still showed the vulnerability present*. Matching
rendered output is not the same as checking a value; they now parse the JSON.

The scorecard now refuses to present a score as clean when either condition recurs. It
counts transport failures, flags any oracle that saw `auth required`, prints an
**INSTRUMENTATION WARNING** instead of a detection result, and aborts outright if it cannot
obtain a session — because then every authenticated check would silently become a false
negative.

**71/71 across six consecutive runs, editing a file before each.**

---

## The benchmark was measuring the target, not the tool — 25 of 28 times

Two audit rounds, both prompted by the same question: *is the code under test actually on
the path from input to verdict?*

**Round one, the absent side.** Auditing all nine falsification traps showed N01–N04 and N06
computed their verdict from raw HTTP requests and never called a probe. They recorded
`CORRECT_NEGATIVE` unconditionally. Proved empirically: hardcoding `probe_sqli` to always
report injection left N01 passing. All five were rewritten to call their probe.

**Round two, the planted side — the same defect in reverse, and much larger.** `record()`
took a single boolean. For 25 of 28 planted targets that boolean came from a raw request
against the target, so `TRUE_POSITIVE` meant *"the bug is in the target"*, not *"the tool
found the bug"*. **The advertised 28/28 detection rate was 3 tool detections and 25
assertions about the target.**

The fix separates the two things that had been conflated:

- `record(vid, name, kind, truth, ...)` — `truth` is ground truth, computed from the target.
- The **verdict** is read from a `TOOL` dict that only `ptxlib.probes` calls can populate.
  A target with no tool verdict aborts the run rather than scoring.
- `TARGET_BROKEN` (weight −6) covers the case where the bug isn't in the target at all, so an
  instrumentation failure can never masquerade as a detection result in either direction.

Two scripts now prove the coupling by breaking the tool on purpose:

| Script | Mutation | Required result | Status |
|---|---|---|---|
| `bench/audit_detection.py` | disable each probe | target → `FALSE_NEGATIVE` | **28/28 flip** |
| `bench/audit_falsification.py` | force each probe to over-report | target → `FALSE_POSITIVE` | **9/9 flip** |

### What coupling the detection side immediately revealed

Four genuine misses, all previously invisible behind a perfect score:

| Target | Cause | Resolution |
|---|---|---|
| V19, V20 | my error — `item_field` passed as `"qty"`/`"unit_price"` instead of `"sku"` | parameter fix |
| V08 | the oracle consumed the single-use `WELCOME50` before the tool could race it | added `/benchmark/reset-redemption` |
| V07 | **real capability gap** — see below | `expect_role_gated` |

V07 is the interesting one. `/admin/users` returns 401 anonymous and 200 for a non-admin.
`probe_privilege` refused to call that a finding, because behaviour alone cannot distinguish
"a route meant for every authenticated user" from "a missing role check" — and inferring
intent from the URL path would mean reporting every `/admin/...` as vulnerable.

That reasoning is correct, so the oracle was not weakened. Instead the probe now accepts
`expect_role_gated`: the caller asserts the intent, exactly as `scope.yaml` asserts what is
in scope. Intent is a fact about the system under test that behaviour cannot reveal.

### The generalisable lesson

A benchmark's headline number is only as real as the path from the code under test to the
verdict. **Test both directions.** An absent-case oracle that never calls the tool passes
forever; a planted-case oracle that never calls the tool also passes forever. Neither failure
is visible in the score, and both are invisible in a perfect one.

The Sophos finding — *agents self-reported evasion success their own test output did not
support* — applies to benchmarks built by the same agent that built the tool. I had been
reporting 28/28 as evidence of capability. It was 25 nines of theatre about the target and 3
about the tool.
