# FRONTIER SYSTEMS — four additions that change what this tool can find

Each of these came from something real: a research result, a documented failure mode, or a
gap the benchmark exposed. None are decoration.

---

## 1. THE FALSIFIER

### The problem it solves

Every methodology in this pack is built to *find* vulnerabilities. Almost nothing is built to
challenge the claim that something is **safe**. And that's where the damage lives — a false
negative is invisible. It never appears in the report, the client never knows, and the bug
ships.

My own dry run proved this: I declared a SQLi test "inconclusive" on a genuinely injectable
endpoint because my payload was malformed. The toolchain reported a negative. The negative
was wrong. Nothing caught it except me happening to notice.

### The paradigm

Adapted from **Code-Augur**, which does something genuinely clever: when an agent decides a
component is secure, it commits the invariants behind that judgment as in-source assertions,
then a guided fuzzer tries to falsify them. An assertion that breaks reveals either a real
vulnerability or a flawed assumption — and both are useful.

The web equivalent:

> **Every "not vulnerable" must be accompanied by the assumption it rests on, and that
> assumption must be attacked.**

Not "I tested for SQLi and found nothing." Instead:

```
CLAIM:    /login is not SQL-injectable
ASSUMES:  the username reaches the query through a parameterized statement
FALSIFY:  1. auth-bypass payloads return 200?         -> no
          2. boolean differential observable?          -> no
          3. time-based delay observable?              -> no
          4. error-based leak in response?             -> no
VERDICT:  assumption holds under 4 attacks. Recorded as tested-negative, not as safe.
```

The distinction between **tested-negative** and **safe** is the whole point. "Safe" is a
claim about the world. "Tested-negative" is a claim about what you did. Only the second one
is yours to make.

### The falsification ladder

For each negative, attack the assumption in escalating order of creativity:

1. **Direct** — the obvious payload for the class
2. **Contextual** — the payload adapted to the actual injection context (this is where my
   dry run failed: the payload ignored that the string sat inside `LIKE '%...%'`)
3. **Encoded** — the same payload through the encoders the app accepts (URL, double-URL,
   unicode, HTML entity, JSON escape)
4. **Semantic** — a different route to the same sink (different parameter, different
   endpoint, different HTTP method, a header instead of a body field)
5. **Compounded** — the vulnerability only appears in combination (auth + parameter,
   tenant + object ID, feature flag + endpoint)

A negative survives only if all five rungs fail. Most "we tested it" claims fail at rung 2.

### Rules

- A negative without a recorded assumption is not a result. It's an omission. Log it as a
  coverage gap.
- The Falsifier never accepts a negative from the agent that produced it. Independence is
  the entire mechanism.
- Falsification attempts are logged whether they succeed or fail. A survived attack is
  evidence; an unattempted attack is nothing.
- When a falsification succeeds, the finding's severity is recalculated and the original
  negative is recorded in the report as a methodology failure. That record is more valuable
  than the finding.
- Falsify the CONTROL, not just the target. A verdict read off a caching or forwarding
  intermediary is a claim about the intermediary's freshness, not the target. Before trusting
  either direction, bust the cache and confirm the instrument answers correctly for an object
  that cannot exist. A stale cache yields a false "live breach"; a mangled control yields a
  false "deleted." Both happened, in sequence, on the same engagement — the oracle was only
  as good as its control.

### Why this is the highest-leverage addition

The Stanford/CMU/Gray Swan study found AI frameworks beat 9 of 10 OSCP-certified humans —
and still had a higher false positive rate than every one of them. Everyone optimizes for
false positives because they're visible. **False negatives are the unmeasured failure**, and
the Falsifier is the only mechanism in this pack that attacks them directly.

---

## 2. THE SUSPICION LEDGER

### The problem it solves

Findings are binary: confirmed or nothing. But most of an engagement lives in between —
things that look wrong, might be wrong, need one more test. Those live in the operator's head
and get lost.

### The abstraction

Adapted from **FuzzingBrain V2**'s "Suspicious Point" — a granularity between line-level and
function-level that captures a vulnerability-relevant region with enough context to be
verified independently and in parallel.

The web equivalent is a **Suspicion**: a structured record of something that might be
vulnerable, with enough context that another agent can verify it without re-deriving the
reasoning.

```json
{
  "id": "SUSP-014",
  "surface": "POST /api/profile",
  "class": "mass-assignment",
  "why_suspicious": "endpoint accepts a JSON body and the response echoes every key supplied;
                     no allowlist is visible in behaviour",
  "context": {"auth_required": true, "role": "user", "content_type": "application/json"},
  "hypothesis": "privileged fields (is_admin, role, credits) may be bound from the body",
  "falsification": "send is_admin=1 as a non-admin, then read the user record back",
  "state": "suspected",
  "score": 0.7,
  "created_by": "BREAKER", "created_at": "2026-09-08T11:02:00Z",
  "artifacts": ["018-profile-request.txt"]
}
```

### Lifecycle

```
suspected ──► probing ──► substantiated ──► confirmed ──► finding PTX-NNN
                  │              │
                  └──► falsified ◄┘        (recorded, with the attack that killed it)
```

**State rules:**
- Only `confirmed` becomes a finding. Everything else stays in the ledger.
- `falsified` is a terminal state and is *kept*, with the attack that killed it. A killed
  suspicion is evidence of coverage.
- `suspected` items that were never probed become the coverage-gap list in the report.

### Why it matters

1. **Parallelizable.** Suspicions are independent, so verification can be distributed —
   which is exactly the shape of work that the multi-agent research says parallelizes well.
2. **Nothing gets lost.** The ledger is the memory of what looked interesting.
3. **Honest reporting.** "41 suspicions raised, 12 confirmed, 19 falsified, 10 unprobed" is a
   far more informative sentence than "12 findings."
4. **It stops premature closure.** An agent can't declare a phase complete while suspicions
   sit in `suspected` state.

---

## 3. THE MEMORY LOOP

### The problem it solves

Every engagement starts from zero. The tool doesn't remember that its SSRF probe produced a
false positive on GraphQL endpoints last time, or that this client's stack always leaks
secrets in the same place. There's no compounding.

### The design

After every engagement, Reflector runs an extraction pass and writes to a persistent store:

```
memory/
  techniques.jsonl     # technique -> {targets tried, confirmed, falsified, last used}
  stack-profiles/      # per-technology patterns observed across engagements
  anti-patterns.jsonl  # our own failures, with the fix
  probe-reliability.jsonl  # per-probe false positive rate, measured
```

**`techniques.jsonl`** — the record that makes the next engagement faster:
```json
{"technique":"jwt-alg-none","stack":"express+jsonwebtoken@8.5.0","tried":7,"confirmed":2,
 "falsified":5,"note":"only confirms when the library is <9.0.0; newer rejects alg:none",
 "last_used":"2026-09-08"}
```
Next time Oracle fingerprints `jsonwebtoken@8.x`, this record says the technique is worth
trying. At `9.x` it says don't bother. That's learned prioritization, not a static checklist.

**`probe-reliability.jsonl`** — measured, not assumed:
```json
{"probe":"cors-wildcard","false_positive_rate":0.62,
 "note":"flags configs that are not exploitable without a victim browser; cap at Medium"}
```
A probe with a 62% false positive rate gets demoted to lead-generation and never writes a
finding directly. **This is the mechanism that actually reduces false positives over time** —
which is the failure mode the research identifies as AI's weakness.

**`anti-patterns.jsonl`** — our own failures, which are the most valuable entries:
```json
{"date":"2026-09-08","failure":"declared SQLi negative from a malformed payload",
 "root_cause":"payload did not account for the trailing quote in LIKE '%...%'",
 "fix":"boolean differential requires three distinguishable states; comment out the suffix",
 "generalised":"a negative from an unverified payload is not a result"}
```
Every entry in this file came from a real mistake. Both of the ones recorded so far came from
the dry run — and both are now anti-patterns in the operator prompts.

### The compounding loop

```
engagement ──► Reflector extracts ──► memory store ──► next engagement loads it
     ▲                                                        │
     └────────── priorities, probe weights, anti-patterns ────┘
```

**Guardrails:**
- Memory is *advisory*, never authoritative. A remembered technique still has to be verified
  on the current target. Stale memory is worse than no memory.
- Every memory entry carries a date and a target count. Low-count entries are weak evidence
  and get labelled as such.
- Client-specific memory never crosses to another client. That's a confidentiality boundary,
  not a preference.

---

## 4. ECHO — the fourteenth agent

### Why a new agent

Applications are increasingly embedding LLM agents, and an LLM agent is an attack surface
that nothing else in this roster knows how to test. This is not hypothetical: **AgentFuzz**
found 34 zero-day taint-style vulnerabilities across 20 popular open-source agent
applications (23 assigned CVEs), and **AgentDoS** found 36 zero-day resource-exhaustion
vulnerabilities across 20 agents, 15 with CVEs.

### ECHO

**Role:** AI-component security testing
**Activation:** whenever the target embeds an LLM, RAG pipeline, or agentic workflow

> *"I test the parts of the application that think. Everything else on this team treats user
> input as data — I'm here because somewhere in this app, user input becomes instructions,
> and nobody wrote a parameterized query for that. I look for the place where a document
> that the model reads can tell the model what to do."*

**Tests ECHO runs:**

| Class | What it looks for |
|---|---|
| Direct prompt injection | Instructions in user input that override system behaviour |
| **Indirect prompt injection** | Instructions hidden in data the model retrieves — web pages, PDFs, emails, database rows, tool outputs. The highest-impact class, because the payload never comes from the user |
| Tool/function abuse | Making the agent call tools it shouldn't, with arguments it shouldn't use |
| Data exfiltration via output | Coaxing the model to leak system prompt, other users' context, retrieved documents |
| Context/tenant bleed | One user's conversation reaching another's |
| Retrieval poisoning | Planting content that RAG later retrieves and acts on |
| Guardrail bypass | Encoding, roleplay, translation, and multi-turn escalation |
| Resource exhaustion | The AgentDoS class: prompts that trigger enormous retrieval, downloads, or recursion |
| Model/endpoint disclosure | Leaked model names, API endpoints, keys in error paths |

**Knowledge contract:** this field moves faster than any other in the pack. Every technique
must be treated as provisional and re-verified. Nothing here is stable enough to memorize.

**System prompt seed:**
```
You are ECHO. You test AI components embedded in the target application.
Your premise: somewhere in this system, untrusted data becomes instructions.
Find that boundary.
Prioritize indirect prompt injection — payloads in retrieved data rather than user
input — because they are the highest-impact and least-tested class.
Test tool invocation boundaries: which tools can be triggered, with what arguments,
by whom, and can the agent be made to call one it shouldn't.
Test tenant and context isolation between users.
Test for system prompt and retrieved-document exfiltration through output.
Test resource exhaustion: prompts inducing large retrieval, downloads, or recursion.
Every technique here is provisional. This field moves faster than your training data.
Verify, never assume, and record what you tried even when it fails.
```

**Never does:** assume a guardrail works because it's documented · treat a single failed
bypass as proof of safety · test AI components without the same scope discipline as
everything else

---

## WHAT THE BENCHMARK ACTUALLY PROVED

I built the harness, ran it, and it scored **39/59** the first time. Then I diagnosed all
four failures:

| Failure | What it really was |
|---|---|
| V11 path traversal missed | My target hardcoded a directory that no longer existed |
| V15 lockfile missed | My oracle's regex couldn't span pretty-printed JSON |
| V17 method tampering missed | Flask rejected POST at the routing layer before my handler ran |
| N04 false positive | **I inverted the oracle** — scored a correct negative as a false positive |

Three oracle bugs, one target bug. After fixing them: **18/18 detection, 5/5 correct
negatives, 59/59 weighted.**

The honest reading: **the perfect score is not the finding.** A harness that scores 100% on
its first run proves nothing — it might not discriminate at all. The finding is that the
harness *caught four real bugs*, including one where I'd inverted my own scoring logic and
would have reported a false positive that didn't exist.

That's also the argument for the Falsifier, made concrete: the N04 bug was a false claim
about safety that nothing would have caught if I hadn't gone looking. **Self-review found it.
Independent falsification would have found it automatically.**

And note what the four bugs have in common — every one was mine, not the target's. The
Sophos investigation found exactly this pattern in the wild: attacker agents self-reported
near-universal success that their own documented test output did not support. Self-report is
not evidence, and a harness that grades itself is not a harness.

*(The harness has since grown — 30 planted vulnerabilities and 12 falsification targets, every
one scored from the tool's own verdict and mutation-audited in both directions, disabling a
probe to confirm its target flips to a miss and forcing a probe to confirm its clean target
flips to a false positive. The lesson is unchanged: the value was never the perfect score, it
was the bugs the harness caught on the way there.)*
