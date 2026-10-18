# PENTEST-AGENT — Prompt Pack

Prompts, specifications, and a working benchmark for an AI agent system that accelerates web
application penetration testing. OSINT-first, CLI-native, evidence-driven, team-shaped.

## The pack

| File | What it is |
|---|---|
| **`roadmap.md`** | The 12-phase methodology. Entry gates, owners, exit criteria, artefacts per phase. **Start here.** |
| **`agents-roster.md`** | The 14-role team — introductions, system prompt seeds, knowledge contracts, Reflector's concrete drift signals, coordination topology. |
| **`frontier-systems.md`** | Four systems that change what this can find: the **Falsifier**, the **Suspicion Ledger**, the **Memory Loop**, and agent 14 (**Echo**). |
| `version-cve-pipeline.md` | Detect dependency → fingerprint version → match CVE → verify reachability → notify → teach. |
| `pentest-agent-master.md` | The operator prompt (1014 lines). Drop-in system prompt for a single agent. |
| `pentest-agent-compact.md` | Same behaviour, ~1/8 the tokens. |
| `pentest-agent-builder.md` | Meta-prompt: instructions for a *coding* agent to build this as a real CLI (`ptx`). |
| **`../bench/BENCHMARK.md`** | The working benchmark harness — what was measured, what it scored, what it can't tell you. |
| **`../ptx/README.md`** | The working CLI — scope guard, live CVE lookup, OSINT, probes, findings, report generator, Suspicion Ledger, selfcheck gate. |
| **`../tests/test_ptx.py`** | 506 tests. Runs probes against a vulnerable target *and* a hardened twin, so regressions and false positives in the fixtures are detectable. |

Each prompt is self-contained between its `START` / `END` markers — copy only that region.

---

## How the pieces fit

```
roadmap.md                  the METHOD — what happens, in what order, with what gates
   │
   ├── agents-roster.md     WHO does each phase, and how they coordinate
   │      │
   │      ├── frontier-systems.md    the Falsifier, Suspicion Ledger, Memory Loop, Echo
   │      └── version-cve-pipeline.md    Oracle's specialty, specified in full
   │
   ├── pentest-agent-master.md    the single-agent version, if you don't want a team
   │
   └── ../bench/            the BENCHMARK — measures whether any of it works
```

---

## What the benchmark proved

The harness plants **33 vulnerabilities** and **15 deliberately-absent conditions**
(falsification traps) and scores the tool, not the target. Current: **33/33 detected, 15/15
correctly not reported, 114/114 weighted.**

Those numbers were fiction until they were audited. Two separate rounds found oracles that
could not fail:

1. **Five of the nine falsification traps never called a probe.** They computed their verdict
   from raw HTTP requests, so they recorded `CORRECT_NEGATIVE` whatever the tool did.
   Proof: hardcoding `probe_sqli` to always report injection left N01 passing.
2. **Twenty-five of the twenty-eight planted targets had the same defect in reverse.**
   `record()` took one boolean, computed from a raw request against the target, and mapped it
   straight to `TRUE_POSITIVE` — the tool was never consulted. "28/28 detection rate" was
   really **3 tool detections and 25 assertions about the target**.

`record()` now takes ground truth *and* reads the verdict from a `TOOL` dict that only calls
into `ptxlib.probes` can populate. A target with no tool verdict aborts the run instead of
scoring. Two scripts prove the coupling by breaking the tool on purpose:

| Script | Mutation | Required result |
|---|---|---|
| `bench/audit_detection.py` | disable each probe | its target becomes `FALSE_NEGATIVE` — **28/28 flip** |
| `bench/audit_falsification.py` | force each probe to over-report | its target becomes `FALSE_POSITIVE` — **9/9 flip** |

Coupling the detection side surfaced **four genuine misses** the old scorecard had been
hiding (V07, V08, V19, V20). Two were my parameter errors; V08 was the oracle consuming a
single-use resource before the tool could race it; and V07 exposed a real capability gap —
`probe_privilege` correctly refused to guess whether an endpoint is *meant* to be
role-restricted, so it now accepts a caller-declared `expect_role_gated`.

**The lesson generalises: a benchmark's headline number is only as real as the path from the
code under test to the verdict.** Both directions have to be mutation-tested, or a perfect
score is indistinguishable from a benchmark that measures nothing.

The scoring weights **false positives at −4 against true positives at +3**, because the
Stanford/CMU/Gray Swan study found AI frameworks beat 9 of 10 OSCP-certified humans and
*still* had a higher false positive rate than every one of them.

---

## The four frontier systems

**1. The Falsifier.** Every "not vulnerable" must carry the assumption it rests on, and that
assumption gets attacked on a five-rung ladder (direct → contextual → encoded → semantic →
compounded). Adapted from Code-Augur. The distinction it enforces: **"tested-negative" is a
claim about what you did; "safe" is a claim about the world. Only the first one is yours to
make.** This is the only mechanism here that attacks false negatives — the invisible failure.

**2. The Suspicion Ledger.** Findings stop being binary. Everything that might be vulnerable
becomes a structured record with a lifecycle (`suspected → probing → substantiated →
confirmed`, or `falsified`), independently verifiable and parallelizable. "41 suspicions,
12 confirmed, 19 falsified, 10 unprobed" is a far more honest sentence than "12 findings."

**3. The Memory Loop.** Cross-engagement learning. Measured per-probe false positive rates
demote unreliable probes to lead-generation. Recorded techniques get prioritized by stack.
Our own failures become anti-patterns. **This is the mechanism that reduces false positives
over time** — the documented AI weakness.

**4. Echo.** Agent 14. Tests AI components embedded in the target — prompt injection,
indirect injection via retrieved data, tool abuse, tenant bleed, resource exhaustion.
AgentFuzz found 34 zero-days across 20 agent apps; AgentDoS found 36 more. This surface is
real and nothing else in the roster knows how to test it.

---

## On your generalists-vs-specialists test

The research is counterintuitive. Across 260 controlled configurations, single-agent baseline
performance was the strongest predictor of whether coordination helped at all, and where
single-agent accuracy already exceeded ~45%, adding agents gave *negative* returns.
Multi-agent degraded sequential tasks by 39–70% while helping parallelizable ones. Overhead
runs ~58% extra tokens for peers, ~285% for a supervisor. Teams starting at 3–5 agents beat
teams launching 10+.

**Neither room wins by default. The deciding variable is task decomposability, not the
room's composition.** Generalists fail on depth; specialists fail on coordination. What works
is a few specialists with non-overlapping boundaries, one sequential thread, and an
adversarial observer.

The sharpest version of your test isn't the two rooms you have:

> generalists vs specialists vs **one strong generalist given the specialists' tools**

That third condition wins more often than people expect, and it's the one most demos skip.

For a pentest specifically: specialists should win on breadth (phases 1–5) and lose on depth
(phase 6). If your results show specialists winning across the board, the task probably
wasn't sequential enough to be representative.

---

## On knowledge cutoffs

You asked for each agent's cutoff date. I didn't give dates, because these are behavioural
roles — system prompts, not trained models. They inherit whatever cutoff the hosting model
has, which I can't inspect. Inventing dates would have been fabrication.

Each agent has a **Knowledge Contract** instead: what staleness means in its domain, what
it's forbidden to answer from memory, what it must look up live. For security work that's
more useful, because a CVE published last week is invisible to *any* cutoff — and the real
failure mode isn't stale data, it's confidently describing a CVE that doesn't exist.

**Hard rule across the roster:** no agent states a CVE ID or version-vulnerability mapping
from memory. Live lookup, or it's labelled unverified.

---

## The five design decisions

**1. OSINT is phase 1, always.** Zero noise, no rate limits, no detection — and it finds what
active testing won't. The phase ends with a ranked attack-hypothesis list, or it isn't done.

**2. CLI-first.** Batch commands, raw output to files, print only the summary and
interpretation, background anything over 30 seconds.

**3. Evidence or it didn't happen.** Command + request + response, or it's a hypothesis.

**4. A team of five, not fourteen.** Specialists are invoked on trigger and released. That's
what the multi-agent research supports.

**5. Measure, don't assert.** The benchmark exists because agent self-report is not evidence
— Sophos documented attacker agents claiming success their own test data didn't support.

---

## Deploying

**Claude Code / Codex CLI / Cursor:** drop the master prompt into `CLAUDE.md`, `AGENTS.md`,
or `.cursorrules`.
**ChatGPT / Claude / Gemini web:** paste as the first message, then send the engagement brief.
**API:** use as the `system` message.
**n8n / LangChain / CrewAI:** system message on the agent node — and give it shell, file, and
HTTP tools.

### Engagement brief

```
TARGET: app.example.com
ALSO IN SCOPE: api.example.com, *.staging.example.com
OUT OF SCOPE: billing.example.com, our Okta tenant, the Cloudflare edge
AUTHORIZATION: my own company, I'm the security lead, written RoE on file
TYPE: black box
CREDS: none yet
RATE CEILING: 5 req/s, avoid 02:00–06:00 IST (backups run)
DESTRUCTIVE: not permitted
REPORT: technical + one exec page
```

---

## What is still unproven

Being explicit, because the useful part of this pack is knowing its own edges:

| Gap | Why it matters |
|---|---|
| **Full passive OSINT against a public domain** | DNS/email-auth collection has worked against a real domain, but crt.sh and Wayback have not returned usable data from this sandbox; this leaves subdomain and historical-URL coverage unvalidated |
| **Live CVE lookup assurance** | OSV.dev lookup has been exercised against real CVE identifiers, but that does not establish coverage or precision for arbitrary lockfiles, nor prove an agent will obey the no-memory rule |
| **Business logic generalization** | The harness now covers pricing, refunds, workflow gates, double-spend and races, but only in one self-authored application; real-world business invariants remain underrepresented |
| **Echo's whole test matrix** | No AI components in the target |
| **The benchmark's circularity** | I built both the target and the oracles. It tests whether techniques work, not whether an agent would think to run them |
| **No end-to-end agent runtime** | The CLI implements `recon`, `discover`, `probe`, `finding`, and `report`; the prompt pack itself has no model client or orchestration loop, and it has not been evaluated end-to-end with an actual agent/model |
| **CVE reachability assurance** | PTX now offers EXPOSED/LIKELY/UNDETERMINED/NOT_PRESENT assessments, but they are black-box heuristics; there is no source-level call/data-flow proof or independent real-app validation |
| **crt.sh and Wayback** | Unreachable from this sandbox. Both modules fail honestly with exit 5, but neither has returned real data here |
| **Network/tooling dependence** | Benchmark dependencies are pinned in `requirements.txt`, but the OSINT sources and optional system tools still depend on network/runtime availability; source failures must remain coverage gaps, not clean results |

**Since that list was written**, three gaps closed: `ptx` exists and runs, the live
CVE-lookup stage is verified against OSV.dev with real CVE identifiers, and the DNS/email-auth
OSINT path works against a real domain.

The highest-value remaining work is validating the existing heuristic reachability ratings
against independent applications and source-level ground truth, then evaluating the prompt
pack end-to-end with a real model. A version match or visible component fingerprint is not
proof that vulnerable code is reached with attacker-controlled input.
