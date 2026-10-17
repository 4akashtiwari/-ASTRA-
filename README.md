# ASTRA — an AI-agent web-pentesting assistant

> Write access confirmed. ASTRA is under active construction here; the CLI is `ptx`.

PTX turns a general-purpose AI agent into a disciplined web-application penetration tester.
It is two halves that reinforce each other:

- **`agent-prompts/`** — a "super prompt" system: a compact operating prompt, a specialist
  roster, and a frontier-methods document that encode *how* to test (verify, don't guess;
  judge by effect on state, never by status code; falsify the control; protect the subject at
  the LLM boundary).
- **`ptx/`** — the CLI the agent drives: ~30 probe classes, OSINT, a CVE pipeline, scope and
  destructive-action gating, coverage accounting, attack-chain reasoning, and reporting. Every
  probe is benchmarked against a target with planted flaws and mutation-audited so a broken
  probe is caught as a detection failure, not silently trusted.

## Safety model (non-negotiable, enforced in code)

- **Scope-gated.** Nothing touches the network without a recorded `scope.yaml` and an
  authorization basis. Third parties are noted, never tested.
- **Destructive-gated.** State-changing probes refuse to run unless the engagement explicitly
  permits them.
- **LLM-boundary redaction.** `ptx redact` replaces subject identifiers (host, URL authority,
  IP, email, token, client/org names) with stable placeholders *before* text reaches a
  third-party model provider; the reversible map never leaves the operator's machine. The model
  reasons over `PTX_HOST_1` and still gets the structure it needs (paths, params, response
  shape). See `ptx/ptxlib/redact.py`.
- **No secret reproduction.** Leaked credentials are reported by *kind*, never by value.

## Layout

```
agent-prompts/   the prompt system (compact prompt, roster, frontier methods)
ptx/             the CLI + ptxlib/ (probes, coverage, chains, cve, osint, redact, ...)
tests/           the test suite (unit + differential + live-target)
bench/           the benchmark target, scorecard, and detection/falsification audits
bin/ptx          entry point
```

## Quick start

```bash
pip install -r requirements.txt          # z3 is optional (powers `ptx logic`)
python3 -m unittest tests.test_ptx       # the suite
python3 bench/target_v2.py &             # the benchmark target
python3 bench/scorecard.py               # planted/absent scoring
python3 bench/audit_detection.py         # disable each probe -> its target must go FN
python3 bench/audit_falsification.py     # force each probe -> its control must go FP
```

CLI reference: [`ptx/README.md`](ptx/README.md).

## Status

Benchmark: 33 planted / 15 absent, all scored from a call into the probes; both mutation audits
flip every target; suite green. This is defensive security tooling for **authorized** testing
only — every engagement starts from a recorded scope and an authorization basis.
