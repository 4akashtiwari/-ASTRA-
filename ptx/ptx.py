#!/usr/bin/env python3
"""
ptx — CLI-native penetration testing toolkit.

Built to be driven by an AI agent through a shell. Design rules (non-negotiable):
  * every capability is a subcommand — no interactive prompts, no TUI
  * every command accepts --json for machine-readable output
  * raw output goes to files; stdout gets a summary only
  * meaningful exit codes: 0 ok, 2 no results, 3 SCOPE BLOCKED, 4 tool missing, 5 unreachable
  * every network call has a timeout

Exit code 3 is the important one. The scope guard is code, not a prompt instruction.
"""
import argparse, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ptxlib.scope import ScopeViolation, load_scope
from ptxlib import (cve, osint, state as statemod, probes, findings as fnd,
                    report as rpt, reachability, chains, reliability, integrity,
                    recon, chainwalk, coverage, takeover, discover, identities, redact,
                    fingerprint, variants)

EXIT_OK, EXIT_NORESULT, EXIT_SCOPE, EXIT_NOTOOL, EXIT_UNREACHABLE = 0, 2, 3, 4, 5
# A malformed invocation is not a scope violation and not a missing tool. It gets
# its own code so a script can tell "you typed it wrong" from "refused to act".
EXIT_USAGE = 6


def emit(args, summary_lines, payload):
    """Print summary by default, JSON with --json. Raw output already went to files."""
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
    else:
        for line in summary_lines:
            print(line)


_NO_AUTH = ("", "none", "unspecified", "n/a", "na", "todo", "tbd", "-")


def require_scope(args, authorized=False):
    """Load the scope; with authorized=True, also require a recorded authorization basis.

    The authorization line was written into scope.yaml, printed in the scope summary, and
    checked only by `selfcheck` — a report card an operator may never run. So an engagement
    with `authorization:` blank still probed the target. Every other gate in this tool is
    meaningless if that one is optional: scope says where, authorization says whether.

    Enforced here rather than in each command because this is the single function every
    network-bound command already calls. A check added per-command is a check that will be
    missing from the next command someone writes.
    """
    try:
        sc = load_scope(args.engagement)
    except FileNotFoundError:
        print("ERROR: no scope.yaml — run `ptx scope init` first. Nothing runs without scope.",
              file=sys.stderr)
        sys.exit(EXIT_SCOPE)

    # Only commands that put packets on the wire need this. `ptx report`, `finding list`
    # and `selfcheck` read the engagement directory and send nothing; blocking those would
    # stop an operator from inspecting the engagement to work out WHY they were blocked.
    if not authorized:
        return sc

    auth = str(sc.data.get("authorization") or "").strip()
    if auth.lower() in _NO_AUTH or "UNSPECIFIED" in auth.upper():
        print("REFUSED: no authorization basis recorded in scope.yaml. Nothing was sent.",
              file=sys.stderr)
        print("  Every command in this tool assumes the target is authorized. That is a",
              file=sys.stderr)
        print("  fact about the world, not a default, so it has to be written down:",
              file=sys.stderr)
        print(f"    ptx --engagement {args.engagement} scope init <target> \\",
              file=sys.stderr)
        print('        --in-scope <host> --authorization "own asset | contract ref | '
              'bounty ID" --force', file=sys.stderr)
        print("  `--force` overwrites scope.yaml and preserves existing state.",
              file=sys.stderr)
        sc.log_scope_checks([], [{"host": getattr(args, "base", "?") or "?",
                                  "reason": "refused: no authorization basis recorded"}])
        sys.exit(EXIT_SCOPE)
    return sc


# --- scope -------------------------------------------------------------------
def cmd_scope_init(args):
    d = os.path.join(args.engagement)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "scope.yaml")
    if os.path.exists(p) and not args.force:
        print("scope.yaml already exists (use --force to overwrite, state preserved)")
        return EXIT_OK
    tmpl = f"""# engagement scope — the scope guard enforces this on every network action
target: {args.target}
in_scope:
{chr(10).join('  - ' + t for t in (args.in_scope or [args.target]))}
exclusions:
{chr(10).join('  - ' + e for e in (args.exclude or []))}
authorization: {args.authorization or 'UNSPECIFIED — fill this in'}
assessment_type: {args.type}
destructive_permitted: {'true' if args.destructive else 'false'}
rate_ceiling_rps: {args.rate}
created: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
"""
    with open(p, "w") as f:
        f.write(tmpl)
    statemod.init(args.engagement)
    print(f"scope written -> {p}")
    print(f"state initialised -> {os.path.join(d, 'state.json')}")
    if not args.authorization:
        print("WARNING: authorization is UNSPECIFIED. Record the basis before testing.")
    return EXIT_OK


def cmd_scope_check(args):
    sc = require_scope(args)
    allowed, blocked = [], []
    for host in args.hosts:
        try:
            sc.assert_in_scope(host)
            allowed.append(host)
        except ScopeViolation as e:
            blocked.append({"host": host, "reason": str(e)})
    sc.log_scope_checks(allowed, blocked)
    emit(args,
         [f"in scope : {', '.join(allowed) or 'none'}",
          f"BLOCKED  : {', '.join(b['host'] for b in blocked) or 'none'}"] +
         [f"           {b['host']} -> {b['reason']}" for b in blocked],
         {"allowed": allowed, "blocked": blocked})
    return EXIT_SCOPE if blocked and not allowed else EXIT_OK


def cmd_scope_show(args):
    sc = require_scope(args)
    emit(args, sc.summary_lines(), sc.as_dict())
    return EXIT_OK


# --- status ------------------------------------------------------------------
def cmd_status(args):
    sc = require_scope(args)
    st = statemod.load(args.engagement)
    susp = statemod.suspicions(args.engagement)
    counts = {}
    for s in susp:
        counts[s["state"]] = counts.get(s["state"], 0) + 1
    lines = [
        f"engagement : {args.engagement}",
        f"target     : {sc.data.get('target')}",
        f"phase      : {st.get('phase', 'not started')}",
        f"actions    : {st.get('action_count', 0)} logged",
        f"scope blocks: {st.get('scope_blocks', 0)}",
        f"suspicions : {counts or 'none'}",
        f"findings   : {st.get('finding_count', 0)}",
    ]
    unprobed = [s["id"] for s in susp if s["state"] == "suspected"]
    if unprobed:
        lines.append(f"NEXT: {len(unprobed)} suspicions unprobed -> {', '.join(unprobed[:8])}")
    else:
        lines.append("NEXT: no unprobed suspicions; advance the phase or run ptx probe")
    emit(args, lines, {"scope": sc.as_dict(), "state": st, "suspicion_counts": counts,
                       "unprobed": unprobed})
    return EXIT_OK


# --- CVE ---------------------------------------------------------------------
def cmd_cve_lockfile(args):
    # loaded for the authorization gate, which is its side effect
    require_scope(args, authorized=True)
    try:
        result = cve.audit_lockfile(args.path, timeout=args.timeout)
    except cve.CVEError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return EXIT_UNREACHABLE
    emit(args, result["summary_lines"], result)
    statemod.log_action(args.engagement, "cve", "audit_lockfile", args.path,
                        f"{result['counts']['affected']} affected packages")
    return EXIT_OK if result["counts"]["affected"] else EXIT_NORESULT


def cmd_cve_query(args):
    require_scope(args, authorized=True)
    try:
        result = cve.query(args.package, args.ecosystem, args.version, timeout=args.timeout)
    except cve.CVEError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return EXIT_UNREACHABLE
    emit(args, result["summary_lines"], result)
    return EXIT_OK if result["vulns"] else EXIT_NORESULT


# --- OSINT -------------------------------------------------------------------
def cmd_osint_dns(args):
    sc = require_scope(args, authorized=True)
    try:
        sc.assert_in_scope(args.domain)
    except ScopeViolation as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        sc.log_scope_checks([], [{"host": args.domain, "reason": str(e)}])
        return EXIT_SCOPE
    r = osint.dns(args.domain, timeout=args.timeout)
    osint.save(args.engagement, "dns", r)
    emit(args, r["summary_lines"], r)
    statemod.log_action(args.engagement, "osint", "dns", args.domain,
                        f"{r['counts']['records']} records")
    return EXIT_OK


def cmd_osint_subs(args):
    sc = require_scope(args, authorized=True)
    try:
        sc.assert_in_scope(args.domain)
    except ScopeViolation as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        sc.log_scope_checks([], [{"host": args.domain, "reason": str(e)}])
        return EXIT_SCOPE
    r = osint.subdomains(args.domain, timeout=args.timeout)
    osint.save(args.engagement, "subs", r)
    emit(args, r["summary_lines"], r)
    if not r.get("enumerated"):
        statemod.log_action(args.engagement, "osint", "subs", args.domain,
                            "SOURCE UNAVAILABLE — coverage gap, not a negative result")
        return EXIT_UNREACHABLE
    statemod.log_action(args.engagement, "osint", "subs", args.domain,
                        f"{r['counts']['total']} subdomains")
    return EXIT_OK if r["counts"]["total"] else EXIT_NORESULT


def cmd_osint_takeover(args):
    """Assess enumerated subdomains for dangling delegations to claimable services.

    DETECTION ONLY. This reads a CNAME chain from public DNS and, where the chain
    delegates to a third party, fetches that host once to see whether the service reports
    the resource as unclaimed. It never registers or claims anything — claiming would be
    an attack on a third party that is not the target and not covered by this
    authorization, even though the dangling record makes it possible.
    """
    sc = require_scope(args, authorized=True)
    try:
        sc.assert_in_scope(args.domain)
    except ScopeViolation as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        sc.log_scope_checks([], [{"host": args.domain, "reason": str(e)}])
        return EXIT_SCOPE

    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        source = f"{len(hosts)} host(s) supplied with --hosts"
    else:
        subs = osint.subdomains(args.domain, timeout=args.timeout)
        osint.save(args.engagement, "subs", subs)
        hosts = subs["subdomains"]
        source = f"enumerated from {args.domain}"

    if not hosts:
        lines = ["subdomain takeover — NO HOSTS TO ASSESS"]
        lines.append(f"  subdomain enumeration returned nothing ({source}). The DNS or")
        lines.append("  certificate-transparency sources may be unreachable — this is a")
        lines.append("  COVERAGE GAP, not evidence that no takeover exists.")
        statemod.log_action(args.engagement, "osint", "takeover", args.domain,
                            "NO HOSTS TO ASSESS — coverage gap, not a negative result")
        emit(args, lines, {"results": [], "hosts_checked": 0})
        return EXIT_UNREACHABLE

    # Throttle to the engagement's ceiling. These requests go to third parties, so the
    # ceiling is a courtesy and an operational safeguard, not a scope rule. This comment
    # always claimed the clamp; the code passed args.rate straight through and never read
    # rate_ceiling_rps, so a lower configured ceiling was silently exceeded.
    rps = args.rate or 5
    try:
        raw = sc.data.get("rate_ceiling_rps")
        ceiling = float(raw) if raw else None
    except (TypeError, ValueError):
        ceiling = None
    if ceiling:
        rps = min(ceiling, rps)
    res = takeover.scan(hosts, timeout=args.timeout, rps=rps)
    osint.save(args.engagement, "takeover", res)
    emit(args, res["summary_lines"], res)

    likely = [r for r in res["results"] if r["verdict"] == "TAKEOVER_LIKELY"]
    cand = [r for r in res["results"] if r["verdict"] == "CANDIDATE"]
    statemod.log_action(args.engagement, "osint", "takeover", args.domain,
                        f"{len(hosts)} hosts: {len(likely)} claimable, {len(cand)} "
                        f"candidate(s), {len(res['unmeasured'])} unmeasured")
    if likely:
        for r in likely:
            statemod.add_suspicion(
                args.engagement, r["host"], "subdomain takeover",
                r["reason"],
                hypothesis=f"{r['host']} can be claimed by registering on {r['service']}",
                falsification="re-resolve the CNAME and confirm the service still reports "
                              "the resource as unclaimed")
        # `from_probe` takes a PROBE RESULT, not a finding: it keys the class off `id`,
        # the title off `name`, the summary off `mechanism`, and returns None unless
        # `vulnerable` is set. An earlier version of this call passed finding-shaped keys
        # and no `vulnerable`, so it returned None and created nothing at all — silently.
        # A takeover that produces no finding produces no report entry.
        evidence = "\n".join(
            f"{r['host']} -> {r['cname'][-1]} ({r['service']}): {r['reason']}"
            for r in likely)
        rec, created = fnd.from_probe(args.engagement, {
            "id": "subdomain takeover",
            "name": f"Subdomain takeover — {len(likely)} dangling delegation(s)",
            "vulnerable": True,
            "severity": "High",
            "mechanism": "Subdomains of the target delegate to third-party services where "
                         "the resource does not exist, so anyone can register it and serve "
                         "content from inside the target's own namespace.",
            "evidence": evidence,
            "teaching": "A CNAME is a promise that somebody else keeps. When that party "
                        "deprovisions the resource the promise still resolves, and whoever "
                        "claims it next inherits your namespace — including any cookie "
                        "scoped to a parent domain. Remove the record, or point it at a "
                        "host you control.",
        })
        if rec is None:
            print("INTERNAL: a takeover was detected but no finding was created",
                  file=sys.stderr)
        return EXIT_OK
    if res["unmeasured"] and not cand:
        return EXIT_UNREACHABLE
    return EXIT_NORESULT


def cmd_osint_wayback(args):
    sc = require_scope(args, authorized=True)
    try:
        sc.assert_in_scope(args.domain)
    except ScopeViolation as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        return EXIT_SCOPE
    r = osint.wayback(args.domain, timeout=args.timeout, limit=args.limit)
    osint.save(args.engagement, "wayback", r)
    emit(args, r["summary_lines"], r)
    if not r.get("enumerated"):
        statemod.log_action(args.engagement, "osint", "wayback", args.domain,
                            "SOURCE UNAVAILABLE — coverage gap, not a negative result")
        return EXIT_UNREACHABLE
    statemod.log_action(args.engagement, "osint", "wayback", args.domain,
                        f"{r['counts']['urls']} urls")
    return EXIT_OK if r["counts"]["urls"] else EXIT_NORESULT


def cmd_osint_emailsec(args):
    sc = require_scope(args, authorized=True)
    try:
        sc.assert_in_scope(args.domain)
    except ScopeViolation as e:
        print(f"SCOPE BLOCKED: {e}", file=sys.stderr)
        return EXIT_SCOPE
    r = osint.email_security(args.domain, timeout=args.timeout)
    osint.save(args.engagement, "emailsec", r)
    emit(args, r["summary_lines"], r)
    return EXIT_OK


# --- suspicions --------------------------------------------------------------
def cmd_susp_add(args):
    require_scope(args)
    s = statemod.add_suspicion(args.engagement, args.surface, args.vclass,
                               args.why, args.hypothesis, args.falsification)
    print(f"{s['id']}  {s['surface']}  [{s['class']}]  state={s['state']}")
    return EXIT_OK


def cmd_susp_list(args):
    require_scope(args)
    susp = statemod.suspicions(args.engagement)
    if args.state:
        susp = [s for s in susp if s["state"] == args.state]
    emit(args, [f"{s['id']:10s} {s['state']:14s} {s['surface']}  [{s['class']}]" for s in susp]
               or ["no suspicions"], susp)
    return EXIT_OK if susp else EXIT_NORESULT


def cmd_susp_set(args):
    require_scope(args)
    s = statemod.set_suspicion_state(args.engagement, args.id, args.state, args.note)
    if not s:
        print(f"no such suspicion: {args.id}", file=sys.stderr)
        return EXIT_NORESULT
    print(f"{s['id']} -> {s['state']}" + (f"  ({args.note})" if args.note else ""))
    return EXIT_OK


# --- selfcheck ---------------------------------------------------------------
def cmd_selfcheck(args):
    sc = require_scope(args)
    st = statemod.load(args.engagement)
    susp = statemod.suspicions(args.engagement)
    recs = fnd.all_findings(args.engagement)
    bad = [v for v in fnd.validate_all(args.engagement) if not v["valid"]]
    iver = integrity.verify_all(args.engagement, recs)
    drifted = [v for v in iver if v.get("sealed") and not v["ok"]]
    unsealed = [v for v in iver if not v.get("sealed")]
    checks = [
        ("scope.yaml exists and names a target", bool(sc.data.get("target"))),
        (f"all {len(recs)} findings valid (evidence, impact, reproduction)"
         if recs else "no findings recorded yet", not bad),
        (f"evidence intact ({len(recs)} sealed)" if recs else "no findings to seal",
         not drifted),
        ("authorization basis recorded",
         bool(sc.data.get("authorization")) and "UNSPECIFIED" not in str(sc.data.get("authorization"))),
        ("exclusions list is explicit", isinstance(sc.data.get("exclusions"), list)),
        ("at least one action logged", st.get("action_count", 0) > 0),
        ("no suspicions left in 'suspected' state",
         not any(s["state"] == "suspected" for s in susp)),
        ("every confirmed suspicion has a note",
         all(s.get("note") for s in susp if s["state"] == "confirmed")),
    ]
    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {n}")
    for b in bad:
        print(f"         {b['id']}: " + "; ".join(b["problems"][:2]))
    for v in drifted:
        print(f"         {v['id']}: " + "; ".join(v["problems"][:2]))
    if unsealed:
        print(f"         note: {len(unsealed)} finding(s) recorded before sealing existed "
              f"— run `ptx seal <id>` to pin them")
    emit(args, [f"selfcheck: {len(checks) - len(failed)}/{len(checks)} passed"],
         {"checks": [{"name": n, "passed": ok} for n, ok in checks], "failed": failed})
    return EXIT_OK if not failed else 1



# --- probe -------------------------------------------------------------------
def _require_in_scope(args):
    """Enforce the scope boundary for any command that touches a network target.

    require_scope() only checks that a scope FILE exists. That is not enough: without
    this, `ptx probe --base http://anything` happily attacks a host that was never
    authorized. Verified bug — the scope guard was not guarding the probe commands.
    """
    sc = require_scope(args, authorized=True)
    # Commands name their target differently: probes use --base, recon uses a positional.
    # A guard that only understands one of them is a guard with a hole in it.
    host = getattr(args, "base", None) or getattr(args, "target", None)
    if not host:
        print("internal error: no target on this command to scope-check", file=sys.stderr)
        sys.exit(EXIT_SCOPE)
    host = host.split("://")[-1].split("/")[0].split(":")[0] or host
    try:
        reason = sc.assert_in_scope(host)
    except ScopeViolation as e:
        print(f"SCOPE BLOCKED: {host} -> {e}", file=sys.stderr)
        sc.log_scope_checks([], [{"host": host, "reason": str(e)}])
        sys.exit(EXIT_SCOPE)
    return sc, reason


# Probe classes that change server state rather than only reading it. Running one against
# a target the user did not authorize for mutation is not a false positive — it is an
# unrequested change to a system, and on a production host it can spend money, delete a
# record, or consume a single-use resource.
DESTRUCTIVE = {
    "race":            "fires parallel requests at a single-use operation and consumes it",
    "method-tamper":   "invokes a DELETE path on the target",
    # Failed authentications are not a read. Most production login endpoints count them,
    # and the count ends in a locked account or a throttled source IP — an operational
    # change to a system the operator authorized for testing, not for disruption.
    "user-enum":       "sends failed login attempts, which can trip account lockout",
    "mass-assignment": "writes privileged fields onto a record",
    "csrf":            "performs the state change it is testing for",
    "negative-qty":    "adds a line to a cart and moves the account balance",
    "price-tamper":    "creates an order",
    "refund-abuse":    "issues a refund",
    "workflow-bypass": "advances an order through a state transition",
    "stored-xss":      "writes a payload into the target's data that renders in every "
                       "viewer's browser until someone deletes it",
    "double-spend":    "applies a one-time action twice, consuming it and moving account state",
    "race-consume":    "fires concurrent state-changing requests at a single-use operation",
    # Replays the privileged WRITE requests the caller named, using a forged session
    # cookie. Those are POSTs that change state, so this belongs behind the same gate as
    # every other mutating probe. It was missing, so `--destructive-ok` was never required
    # and the forged-session writes fired without explicit permission.
    "session-forge":   "replays privileged write requests with a forged session cookie",
}


def _truthy(v):
    return str(v).strip().lower() in ("true", "yes", "1", "on")


def _require_destructive_ok(args, sc, probe_class):
    """Refuse a state-changing probe unless the engagement explicitly allows it.

    `destructive_permitted` was written into scope.yaml and printed in the scope summary,
    and nothing ever read it — a control that existed in the config and did nothing, the
    same fault as the rate ceiling before it. Say the flag is false and the tool still
    deletes an account.
    """
    if probe_class not in DESTRUCTIVE:
        return
    if _truthy(sc.data.get("destructive_permitted")):
        return
    print(f"REFUSED: `{probe_class}` changes server state — {DESTRUCTIVE[probe_class]}.",
          file=sys.stderr)
    print("  This engagement has destructive_permitted: false. Nothing was sent.",
          file=sys.stderr)
    print("  Re-run `ptx scope init ... --destructive` only if the client has authorized",
          file=sys.stderr)
    print("  state-changing tests against this target.", file=sys.stderr)
    sc.log_scope_checks([], [{"host": getattr(args, "base", "?"),
                              "reason": f"destructive probe `{probe_class}` refused: "
                                        f"destructive_permitted is false"}])
    sys.exit(EXIT_SCOPE)


def _client(args, sc=None):
    """Build an HTTP client with the rate ceiling enforced.

    The ceiling comes from scope.yaml and is a MAXIMUM: --rate can lower it but never
    raise it. Previously --rate defaulted to 0, meaning unlimited, and the scope ceiling
    was written into the file and then never read.
    """
    ceiling = None
    if sc is None:
        sc = require_scope(args)
    raw = sc.data.get("rate_ceiling_rps")
    try:
        ceiling = float(raw) if raw else None
    except (TypeError, ValueError):
        ceiling = None
    requested = getattr(args, "rate", 0) or None
    if ceiling and requested:
        rps = min(ceiling, requested)
    else:
        rps = ceiling or requested or 5      # default ceiling if nothing is configured
    return probes.Http(args.base, rps=rps, timeout=args.timeout), rps

def _record(args, verdict):
    """Probe result -> suspicion ledger entry. Confirmed verdicts also become findings."""
    require_scope(args)
    st = "confirmed" if verdict["vulnerable"] else "falsified"
    note = verdict["evidence"][:200]
    s = statemod.add_suspicion(args.engagement, verdict["name"], verdict["id"],
                               why="probe executed", hypothesis=verdict["name"],
                               falsification=verdict["mechanism"][:160])
    statemod.set_suspicion_state(args.engagement, s["id"], st, note)
    rec = None
    if verdict["vulnerable"]:
        rec, _created = fnd.from_probe(args.engagement, verdict)
    return s, rec

def cmd_probe(args):
    sc, reason = _require_in_scope(args)
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    which = args.probe
    out = []

    # Requests that had already failed before the current probe ran. run() is called
    # immediately after each probe completes, so this snapshot is the count as it stood
    # when that probe started — which is what decides whether the probe measured anything.
    _failed_before = [h.transport_failures]

    def run(v):
        before, _failed_before[0] = _failed_before[0], h.transport_failures
        probes.mark_unmeasured(v, h, before)
        # Location-awareness: stamp WHERE this verdict was produced so a later variant
        # sweep (`--from-finding`) or retest can find it. Probes take their target from
        # the command args; setdefault so a probe that already named its own location wins.
        v.setdefault("endpoint", getattr(args, "path", None))
        v.setdefault("param", getattr(args, "param", None))
        s, rec = _record(args, v)
        out.append({"verdict": v, "suspicion": s["id"],
                    "finding": rec["id"] if rec else None})
        # Structured coverage record: which probe class was applied to which endpoint,
        # and what it concluded. Without this, "what was NOT tested" can only be asserted.
        _log_probe(args, v)
        mark = ("VULNERABLE" if v["vulnerable"]
                else "UNMEASURED" if v.get("inconclusive") else "not vulnerable")
        print(f"  [{mark:15s}] {v['name']}")
        print(f"                   {v['evidence'][:110]}")

    _require_destructive_ok(args, sc, which)
    if which in ("exposure", "unauthenticated"):
        run(probes.probe_exposure(h))
    if which in ("headers", "unauthenticated"):
        run(probes.probe_headers(h))
    if which == "idor":
        run(probes.probe_idor(h, args.path, args.own_id, args.other_id,
                              cookie=args.cookie, owner_field=args.owner_field))
    if which == "session-forge":
        priv = []
        if args.forge_body:
            try:
                priv = [{"path": args.forge_path or args.path,
                         "body": json.loads(args.forge_body)}]
            except Exception as e:
                print(f"  --forge-body is not valid JSON: {e}")
                return EXIT_USAGE
        elif args.path:
            # No body supplied: discover the gated field and build the request from it.
            # Composing the two probes is what makes this one work -- a role check
            # usually bites on a write, and replaying only reads proves nothing.
            gated, _b, note = probes.discover_gated_fields(
                h, args.path, args.path, args.cookie, {"author": "ptx", "message": "x"},
                marker_field=args.marker_field)
            if gated:
                body = {"author": "ptx", "message": "x", gated[0][0]: True}
                priv = [{"path": args.path, "body": body}]
                print(f"  discovered gated field {gated[0][0]!r}; "
                      f"replaying a write that sets it")
            else:
                print(f"  no gated field discovered ({note or 'none'}); "
                      f"replaying reads only, which rarely proves a role bypass")
        run(probes.probe_session_forge(
            h, [args.path] if args.path else [], seed_path=args.seed_path or args.path or "/",
            method=args.seed_method,
            post_body=json.loads(args.seed_body) if args.seed_body else None,
            privileged_requests=priv))
    if which == "privilege":
        low, err = identities.resolve(args, args.engagement)
        if err:
            print(f"  {err}")
            return EXIT_USAGE
        high = identities.get(args.engagement, args.as_high or "")
        if not high:
            print("  --as-high <name> must name a stored identity "
                  f"(stored: {', '.join(identities.all_names(args.engagement)) or 'none'})")
            return EXIT_USAGE
        run(probes.probe_privilege(h, args.path, low, high))
    if which == "sqli":
        run(probes.probe_sqli(h, args.path, args.param, ctx=args.context))
    if which == "xss":
        run(probes.probe_xss(h, args.path, args.param))
    if which == "stored-xss":
        run(probes.probe_stored_xss(h, args.path, args.get_path, args.param, cookie=args.cookie))
    if which == "cmdi":
        run(probes.probe_cmdi(h, args.path, args.param))
    if which == "ssrf":
        run(probes.probe_ssrf(h, args.path, args.param, args.canary_url))
    if which == "traversal":
        run(probes.probe_traversal(h, args.path, args.param, args.payload, args.marker))
    if which == "jwt-none":
        run(probes.probe_jwt_none(h, args.path))
    if which == "redirect":
        run(probes.probe_redirect(h, args.path, args.param))
    if which == "method-tamper":
        run(probes.probe_method_tamper(h, args.path, args.cookie))
    if which == "acl-bypass":
        run(probes.probe_acl_bypass(h, args.path, args.cookie))
    if which == "cors":
        run(probes.probe_cors(h, args.path, args.cookie))
    if which == "user-enum":
        # `--param` defaults to "q", which is right for a search box and wrong for a login
        # form. Passing it through here meant the endpoint never saw a username at all, both
        # sides of the comparison came back identical, and the probe reported "not
        # vulnerable" having tested nothing.
        run(probes.probe_user_enum(h, args.path, args.user, field=args.user_field,
                                   samples=max(1, args.n // 5)))
    if which == "ssti":
        run(probes.probe_ssti(h, args.path, args.cookie))
    if which == "race":
        run(probes.probe_race(h, args.path, json.loads(args.data), args.cookie, n=args.n))
    if which == "confused-deputy":
        run(probes.probe_confused_deputy(
            h, args.path, param=args.param, upstream=args.upstream,
            auth_path=args.auth_path, private_path=args.private_path))
    if which == "git-history-leak":
        if not args.repo:
            print("  git-history-leak needs --repo <url-or-path>")
            return EXIT_USAGE
        run(probes.probe_git_history_leak(args.repo))
    # --- business logic: each needs a way to observe the resulting state ---
    def _balance(hh, hdr):
        if not args.balance_path:
            return None
        try:
            return json.loads(hh.req(args.balance_path, headers=hdr)["body"]).get(
                args.balance_field)
        except Exception:
            return None

    if which == "negative-qty":
        run(probes.probe_negative_quantity(h, args.path, args.item_field, args.sku,
                                           qty_field=args.qty_field, qty=args.qty,
                                           balance_fn=_balance, cookie=args.cookie))
    if which == "price-tamper":
        run(probes.probe_price_tamper(h, args.path, args.item_field, args.sku,
                                      price_field=args.price_field,
                                      tampered=args.tampered_price, cookie=args.cookie))
    if which == "refund-abuse":
        run(probes.probe_refund_abuse(h, args.path, amount=args.refund_amount,
                                      order_id=args.refund_order,
                                      balance_fn=_balance, cookie=args.cookie))
    if which == "csrf":
        def _verify_changed(hh, hdr):
            if not args.verify_path:
                return False
            try:
                cur = json.loads(hh.req(args.verify_path, headers=hdr)["body"]).get(
                    args.verify_key, "")
                return args.verify_value in str(cur)
            except Exception:
                return False
        run(probes.probe_csrf(h, args.path, json.loads(args.data) if args.data else {},
                              args.cookie, _verify_changed, samesite=args.samesite))
    if which == "workflow-bypass":
        run(probes.probe_workflow_bypass(h, args.path, gate_field=args.gate_field,
                                         extra=json.loads(args.data) if args.data else None,
                                         cookie=args.cookie))
    statemod.log_action(args.engagement, "5-assessment", f"probe {which}", args.base,
                        f"{sum(1 for o in out if o['verdict']['vulnerable'])} vulnerable / {len(out)} tested, {h.request_count} requests")
    emit(args, [f"probe {which}: {sum(1 for o in out if o['verdict']['vulnerable'])} vulnerable of {len(out)} tested ({h.request_count} requests)"],
         {"requests": h.request_count, "results": out})
    return EXIT_OK if out else EXIT_NORESULT


def _log_probe(args, v):
    """Record a probe verdict in the structured action log.

    Shared by every probe entry point. This used to live inline in cmd_probe's run(),
    so cmd_probe_mass_assignment — which has its own subparser and its own handler —
    never called it. Running `ptx probe-mass-assignment` therefore left no trace in
    actions.jsonl, and `ptx coverage` reported mass-assignment as never run even after
    it had been run and had produced a verdict. Coverage that silently omits a class it
    does know about is the same failure as not knowing the class at all.
    """
    ep = getattr(args, "path", None) or getattr(args, "base", "") or ""
    if getattr(args, "param", None):
        ep = f"{ep}?{args.param}"
    # Probes now carry a real `inconclusive` flag. The previous version inferred it by
    # looking for the word "INCONCLUSIVE" inside the prose evidence string, and then set
    # the structured `verdict` field to "negative" anyway — so a probe that never observed
    # its effect was recorded, in the field everything downstream reads, as a clean result.
    # Two fields about the same run disagreed, and the one that was consulted was wrong.
    if v["vulnerable"]:
        outcome, verdict = "vulnerable", "vulnerable"
    elif v.get("inconclusive"):
        outcome, verdict = "inconclusive", "inconclusive"
    else:
        outcome, verdict = "negative", "negative"
    statemod.log_action(args.engagement, "5-assessment", f"probe {v['id']}", ep, outcome,
                        probe=v["id"], endpoint=ep or "/", verdict=verdict,
                        inconclusive_reason=v.get("inconclusive_reason"))


def cmd_probe_mass_assignment(args):
    sc, reason = _require_in_scope(args)
    _require_destructive_ok(args, sc, "mass-assignment")
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    if args.discover:
        try:
            body = json.loads(args.body)
        except Exception as e:
            print(f"  --body is not valid JSON: {e}")
            return EXIT_USAGE
        if args.marker_field not in body:
            body[args.marker_field] = ""
        v = probes.probe_mass_assignment_fields(
            h, args.path, args.get_path or args.path, args.cookie, body,
            marker_field=args.marker_field)
        _record(args, v); _log_probe(args, v)
        print(f"  [{'VULNERABLE' if v['vulnerable'] else 'not vulnerable'}] {v['name']}")
        for f in v.get("gated_fields") or []:
            print(f"    server-assigned field discovered: {f}")
        for hit in v.get("hits") or []:
            print(f"    bound: {hit['field']}={hit['sent']!r} -> stored "
                  f"{hit['stored']!r} (server default {hit['server_default']!r})")
        print(f"    {v['evidence']}")
        return EXIT_OK
    if not args.verify_path or not args.verify_match_value:
        print("  without --discover, --verify-path and --verify-match-value are required")
        return EXIT_USAGE
    def verify(hh, hdr):
        r = hh.req(args.verify_path, headers=hdr)
        try:
            for u in json.loads(r["body"]).get(args.verify_key, []):
                if u.get(args.verify_match_key) == args.verify_match_value:
                    return u.get("is_admin") == 1 or u.get("credits") == 99999
        except Exception:
            pass
        return False
    v = probes.probe_mass_assignment(h, args.path, args.cookie, verify,
                                     fields=json.loads(args.fields))
    _record(args, v)
    _log_probe(args, v)
    print(f"  [{'VULNERABLE' if v['vulnerable'] else 'not vulnerable'}] {v['name']}")
    print(f"    {v['evidence']}")
    return EXIT_OK


def cmd_logic(args):
    sc, reason = _require_in_scope(args)
    _require_destructive_ok(args, sc, "constraint-logic")
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    params = {}
    for spec in args.param or []:
        parts = spec.split(":")
        if len(parts) != 3:
            print(f"  --param must be NAME:LO:HI, got {spec!r}")
            return EXIT_USAGE
        name, lo, hi = parts
        try:
            params[name] = (int(lo), int(hi))
        except ValueError:
            print(f"  --param bounds must be integers, got {spec!r}")
            return EXIT_USAGE
    if not params:
        print("  at least one --param NAME:LO:HI is required")
        return EXIT_USAGE
    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(args.baseline)
        except Exception as e:
            print(f"  --baseline is not valid JSON: {e}")
            return EXIT_USAGE

    # The invariant and the verification predicate are operator-supplied expressions,
    # evaluated with no builtins: `impossible` over the solver's symbols, `verify` over the
    # parsed response fields. The operator already controls this CLI and the target, so this
    # is no different from writing the predicate in Python; it is never fed untrusted input.
    def impossible(sym):
        return eval(args.invariant, {"__builtins__": {}}, dict(sym))

    def verify(chosen, r):
        try:
            fields = json.loads(r["body"])
        except Exception:
            return False
        if not isinstance(fields, dict):
            return False
        try:
            return bool(eval(args.verify, {"__builtins__": {}}, dict(fields)))
        except Exception:
            return False

    v = probes.probe_constraint_logic(
        h, args.endpoint, params, impossible, verify,
        method=args.method, baseline=baseline)
    _record(args, v)
    _log_probe(args, v)
    print(f"  [{'VULNERABLE' if v['vulnerable'] else 'not vulnerable'}] {v['name']}")
    print(f"    {v['evidence']}")
    if v.get("chosen"):
        print(f"    solved input: {v['chosen']}")
    return EXIT_OK


# --- findings ----------------------------------------------------------------
def cmd_race_consume(args):
    sc, reason = _require_in_scope(args)
    _require_destructive_ok(args, sc, "race-consume")
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    body = None
    if args.body:
        try:
            body = json.loads(args.body)
        except Exception as e:
            print(f"  --body is not valid JSON: {e}")
            return EXIT_USAGE
    try:
        unit = float(args.unit)
    except (TypeError, ValueError):
        print("  --unit must be a number (the state change one success produces)")
        return EXIT_USAGE
    v = probes.probe_race_consume(h, args.state_endpoint, args.action_path,
                                  args.state_field, unit, body,
                                  method=args.method, n=args.requests)
    _record(args, v)
    _log_probe(args, v)
    print(f"  [{'VULNERABLE' if v['vulnerable'] else 'not vulnerable'}] {v['name']}")
    print(f"    {v['evidence']}")
    return EXIT_OK


def cmd_double_spend(args):
    sc, reason = _require_in_scope(args)
    _require_destructive_ok(args, sc, "double-spend")
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    body = None
    if args.body:
        try:
            body = json.loads(args.body)
        except Exception as e:
            print(f"  --body is not valid JSON: {e}")
            return EXIT_USAGE
    v = probes.probe_double_spend(h, args.state_endpoint, args.action_path,
                                  args.state_field, body, method=args.method)
    _record(args, v)
    _log_probe(args, v)
    print(f"  [{'VULNERABLE' if v['vulnerable'] else 'not vulnerable'}] {v['name']}")
    print(f"    {v['evidence']}")
    return EXIT_OK


def cmd_probe_credential_leak(args):
    sc, reason = _require_in_scope(args)
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    v = probes.probe_response_credential_leak(h, args.endpoint, method=args.method)
    _record(args, v)
    _log_probe(args, v)
    print(f"  [{'VULNERABLE' if v['vulnerable'] else 'not vulnerable'}] {v['name']}")
    print(f"    {v['evidence']}")
    for k in v.get("credential_kinds") or []:
        print(f"    credential kind: {k}")
    return EXIT_OK


def cmd_session(args):
    """Named identities. Cookies are credentials: stored 0600, never printed in full."""
    require_scope(args)
    if args.sub == "login":
        sc, _ = _require_in_scope(args)
        h, rps = _client(args, sc)
        body = {args.user_field: args.user, args.pass_field: args.password}
        r = h.req(args.path, "POST", body)
        cookie_hdr = (r.get("headers") or {}).get("Set-Cookie")
        if not cookie_hdr:
            print(f"  no Set-Cookie in the response to {args.path} "
                  f"(HTTP {r['code']}) — nothing to store")
            return EXIT_NORESULT
        cookie = "; ".join(c.split(";")[0].strip()
                           for c in cookie_hdr.split(",") if "=" in c)
        rec = identities.store(args.engagement, args.name, cookie,
                               role=args.role, note=args.note or "")
        statemod.log_action(args.engagement, "2-scoping", f"session login {args.name}",
                            args.base, "stored", extra={"role": rec["role"],
                                                        "cookie": identities.mask(cookie)})
        print(f"  stored {args.name} as {rec['role'] or 'unspecified role'}: "
              f"{identities.mask(cookie)}")
        return EXIT_OK
    if args.sub == "list":
        names = identities.all_names(args.engagement)
        lines = [f"  {n:14s} {(identities.describe(args.engagement, n) or {}).get('role','')}"
                 f"  {(identities.describe(args.engagement, n) or {}).get('cookie','')}"
                 for n in names] or ["  no identities stored"]
        emit(args, lines, [identities.describe(args.engagement, n) for n in names])
        return EXIT_OK if names else EXIT_NORESULT
    if args.sub == "remove":
        removed = identities.remove(args.engagement, args.name)
        print(f"  {'removed' if removed else 'no such identity'}: {args.name}")
        return EXIT_OK if removed else EXIT_NORESULT
    print("  session: login | list | remove")
    return EXIT_USAGE


def cmd_discover(args):
    """Attack-surface discovery. Scope-gated, rate-limited, baselined against not-found."""
    sc, reason = _require_in_scope(args)
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s", file=sys.stderr)
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, encoding="utf-8", errors="replace") as fh:
                wordlist = [ln.strip() for ln in fh
                            if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print(f"  cannot read --wordlist {args.wordlist}: {e}")
            return EXIT_USAGE
    statemod.log_action(args.engagement, "recon", "discover endpoints", args.base,
                        "started")
    res = discover.scan(h, start=tuple(args.start), wordlist=wordlist,
                        limit=args.limit, depth=args.depth, methods=args.methods)
    outcome = "inconclusive" if res.get("unmeasured") else (
        "positive" if res["results"] else "negative")
    statemod.log_action(args.engagement, "recon", "discover endpoints", args.base,
                        outcome, inconclusive_reason=res.get("note") or None,
                        extra={"discovered": len(res["results"]),
                               "checked": len(res["checked"]),
                               "soft_404": res["baseline"].get("soft_404")})
    if args.json:
        emit(args, discover.summarise(res), res)
    else:
        for line in discover.summarise(res):
            print(line)
    if res.get("unmeasured"):
        return EXIT_UNREACHABLE
    return EXIT_OK if res["results"] else EXIT_NORESULT


def cmd_finding_list(args):
    require_scope(args)
    recs = fnd.all_findings(args.engagement)
    emit(args, [f"{r['id']}  [{r['severity']:8s}] {r['title']}" for r in recs] or ["no findings"],
         recs)
    return EXIT_OK if recs else EXIT_NORESULT

def cmd_finding_validate(args):
    require_scope(args)
    res = fnd.validate_all(args.engagement)
    bad = [r for r in res if not r["valid"]]
    for r in res:
        print(f"  [{'PASS' if r['valid'] else 'FAIL'}] {r['id']}  {r['title']}")
        for p in r["problems"]:
            print(f"           - {p}")
    emit(args, [f"{len(res) - len(bad)}/{len(res)} findings valid"], res)
    return EXIT_OK if not bad else 1

def cmd_finding_set(args):
    require_scope(args)
    d = os.path.join(args.engagement, "findings")
    p = os.path.join(d, f"{args.id}.json")
    if not os.path.exists(p):
        print(f"no such finding: {args.id}", file=sys.stderr); return EXIT_NORESULT
    with open(p) as f:
        rec = json.load(f)
    for k, v in (("impact", args.impact), ("remediation", args.remediation),
                 ("severity", args.severity), ("reproduction", args.reproduction)):
        if v:
            rec[k] = v
    if args.artifact:
        rec.setdefault("artifacts", []).extend(args.artifact)
    if args.status:
        # This is the Memory Loop's only real input. sync_from_engagement demotes a probe
        # class on findings whose status is "refuted" — but until now nothing in the
        # toolchain could ever set that value, so the demotion path had a reader and no
        # writer. The loop could not learn anything, and `ptx reliability` would only ever
        # show 0% false positives no matter how wrong the probes were.
        if args.status == "refuted" and not args.refute_reason:
            print("REFUSED: --status refuted requires --refute-reason. A refutation "
                  "without a reason is not auditable, and it is the evidence the Memory "
                  "Loop uses to demote a probe class.", file=sys.stderr)
            return EXIT_NORESULT
        rec["status"] = args.status
        rec["status_changed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if args.refute_reason:
            rec["refute_reason"] = args.refute_reason
    # Re-seal after the edit and carry the previous digest into the seal's history. The
    # requirement is that an edit is VISIBLE, not that editing is forbidden — and before
    # this, completing a finding (adding the impact statement the report demands) always
    # produced "EVIDENCE DRIFT", so the integrity section cried wolf on the normal
    # workflow. A control that always alarms is a control nobody reads.
    rec["seal"] = integrity.seal(args.engagement, rec)
    with open(p, "w") as f:
        json.dump(rec, f, indent=2)
    ok, problems = fnd.validate(rec)
    print(f"{args.id} updated — {'VALID' if ok else 'STILL INVALID'}")
    if rec["seal"].get("history"):
        print(f"    re-sealed; {len(rec['seal']['history'])} recorded edit(s) in the "
              f"seal history")
    for pr in problems:
        print(f"    - {pr}")
    return EXIT_OK


# --- report ------------------------------------------------------------------
def cmd_coverage(args):
    # load_scope takes the ENGAGEMENT DIRECTORY and appends scope.yaml itself. Passing a
    # path to the file produced "engagement/scope.yaml/scope.yaml", which raised
    # FileNotFoundError — and the bare `except Exception: pass` that was here swallowed it,
    # so assessment_type silently read as None and the feature looked wired up while doing
    # nothing. Do not catch broadly around a single lookup: it converts a typo into a
    # silent no-op, which is the failure this codebase has now found four times.
    at = load_scope(args.engagement).data.get("assessment_type")
    cov = coverage.summarise(args.engagement, fnd.all_findings(args.engagement),
                             assessment_type=at)
    emit(args, coverage.render(cov).split("\n"), cov)


def _save_recon(engagement, what, host, payload):
    """Write a recon artefact where `ptx report` looks for coverage gaps."""
    d = os.path.join(engagement, "recon")
    os.makedirs(d, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{what}-{host}")[:80]
    with open(os.path.join(d, safe + ".json"), "w") as f:
        json.dump(payload, f, indent=2, default=str)


def _parse_host_port(target):
    """Split an optional :port off a target host. Returns (host, port_or_None).

    recon's help advertises host[:port], but the socket layer needs a bare hostname —
    "1.2.3.4:5001" used as a hostname fails name resolution (verified). Only a single
    trailing :digits is treated as a port; an IPv6 literal (two or more colons) is left
    intact rather than split at the wrong colon.
    """
    if target.count(":") == 1:
        h, _, p = target.partition(":")
        if p.isdigit() and h:
            return h, int(p)
    return target, None


def cmd_recon(args):
    """Ports / TLS / HTTP fingerprint. Scope-gated like every other network command."""
    sc, reason = _require_in_scope(args)
    rps = args.rate or None
    try:
        raw = sc.data.get("rate_ceiling_rps")
        ceiling = float(raw) if raw else None
    except (TypeError, ValueError):
        ceiling = None
    if ceiling:
        rps = min(ceiling, rps) if rps else ceiling
    print(f"  scope: {reason} | rate ceiling {rps or 'unset'} req/s", file=sys.stderr)

    # The help advertises host[:port]. Split it once, here, so the socket layer gets a bare
    # hostname — passing "1.2.3.4:5001" as a hostname fails name resolution. An explicit
    # port becomes the port to scan / connect when the branch has no other source. (The
    # http branch builds a URL from args.target, where host:port is already correct.)
    host, explicit_port = _parse_host_port(args.target)
    statemod.log_action(args.engagement, "recon", f"recon {args.what} {host}", host,
                        "started")
    if args.what == "ports":
        spec = args.ports or (str(explicit_port) if explicit_port else None)
        res = recon.ports(host, spec, timeout=args.timeout, rps=rps)
        wrapped = {"host": host, "ports": res, "coverage_gaps": res.get("coverage_gaps", [])}
        payload = res
    elif args.what == "tls":
        payload = recon.tls(host, explicit_port or args.port, timeout=args.timeout)
        wrapped = {"host": host, "tls": [payload],
                   "coverage_gaps": payload.get("coverage_gaps", [])}
    elif args.what == "http":
        url = args.target if "://" in args.target else f"http://{args.target}/"
        payload = recon.http(url, timeout=args.timeout)
        wrapped = {"host": host, "http": [payload],
                   "coverage_gaps": payload.get("coverage_gaps", [])}
    else:
        payload = recon.run(host, args.ports, rps=rps, timeout=args.timeout)
        wrapped = payload

    # Persist the artefact. The gaps were printed to the terminal and a *count* of them
    # was written to the action log, but the gaps themselves went nowhere — and
    # `ptx report` reads coverage gaps from log.md and the saved JSON artefacts only. So
    # "scan intercepted, SCAN INVALID" or "could not reach host, fingerprint unassessed"
    # was shown to the operator once, and then absent from the report. A gap that does
    # not survive the session is a gap the reader of the report never learns about.
    _save_recon(args.engagement, args.what, host, wrapped)
    statemod.log_action(args.engagement, "recon", f"recon {args.what} {host}", host,
                        f"open={len((wrapped.get('ports') or {}).get('open', []))} "
                        f"gaps={len(wrapped.get('coverage_gaps', []))}")
    if args.json:
        emit(args, recon.render(wrapped).split("\n"), payload); return

    print(recon.render(wrapped))
    gaps = wrapped.get("coverage_gaps") or []
    if gaps:
        print(f"\n{len(gaps)} coverage gap(s) recorded — these are things NOT tested.",
              file=sys.stderr)
        sys.exit(EXIT_NORESULT if not ((wrapped.get("ports") or {}).get("open")) else 0)


def cmd_chain(args):
    fs = fnd.all_findings(args.engagement)
    ch, de = chains.analyse(fs)
    esc = [c for c in ch if c["escalated"]]
    walked = []
    if getattr(args, "walk", False):
        sc, reason = _require_in_scope(args)
        h, rps = _client(args, sc)
        print(f"  scope: {reason} | rate ceiling {rps} req/s", file=sys.stderr)
        for f in fs:
            if f.get("class") != "exposure":
                continue
            r1 = chainwalk.walk_secret_to_identity(h, f, args.walk_endpoint)
            r1["name"] = f"{f['id']} leaked signing key -> forged identity"
            walked.append(r1)
            if args.walk_login:
                r2 = chainwalk.walk_credentials_to_session(h, f, args.walk_login)
                r2["name"] = f"{f['id']} leaked credentials -> session"
                walked.append(r2)
        # jwt-none grants "identity" in chains.GRANTS, and REQUIRES says idor, race and the
        # four business-logic classes all assume that identity. Walking it turns the
        # assumption into an observation, which is what lifts those de-escalations.
        for f in fs:
            if f.get("class") != "jwt-none":
                continue
            r3 = chainwalk.walk_alg_none_to_admin(h, f, args.walk_admin_endpoint)
            r3["name"] = (f"{f['id']} unsigned alg:none token -> admin identity accepted")
            walked.append(r3)
    body = chains.render(ch, de)
    if walked:
        body += "\n\n" + chainwalk.render(walked)
        for w in walked:
            if chainwalk.escalation_withdrawn(w):
                body += (f"\n> **{w['name']}: escalation WITHDRAWN.** The chain was "
                         f"attempted and broke. Revert this finding to its standalone "
                         f"severity.\n")
    lines = body.split("\n") + [
        "", f"{len(ch)} chain(s), {len(esc)} escalated, "
            f"{len(de)} severity assumption(s) unproven"]
    if walked:
        d = sum(1 for w in walked if w["verdict"] == "DEMONSTRATED")
        n = sum(1 for w in walked if w["verdict"] == "NOT_DEMONSTRATED")
        c = sum(1 for w in walked if w["verdict"] == "CANNOT_ATTEMPT")
        lines.append(f"walked: {d} demonstrated, {n} broke (escalation withdrawn), "
                     f"{c} could not be attempted")
    # The walked results carry the forged token / session values that proved the chain.
    # Those are live credentials; the human-readable render above already describes the
    # demonstration without them, so mask them before they reach --json or a saved report.
    def _mask_walk(w):
        out = dict(w)
        for k in list(out):
            if isinstance(out[k], str) and any(
                    t in k.lower() for t in ("token", "cookie", "credential", "password", "secret")):
                out[k] = probes._mask_secret(out[k])
        return out
    emit(args, lines, {"chains": ch, "de_escalations": de,
                       "escalated": [x["entry"] for x in esc],
                       "walked": [_mask_walk(w) for w in walked]})


def cmd_reliability(args):
    data = reliability.sync_from_engagement(
        args.engagement, findings=fnd.all_findings(args.engagement),
        suspicions=statemod.suspicions(args.engagement))
    trusted, demoted = reliability.classify(data)
    emit(args, reliability.render(data).split("\n"),
         {"probes": data, "demoted": [d["class"] for d in demoted],
          "trusted": [t["class"] for t in trusted]})


def cmd_verify(args):
    fs = fnd.all_findings(args.engagement)
    res = integrity.verify_all(args.engagement, fs)
    lines, bad = [], 0
    for r in res:
        lines.append(f"  [{'OK    ' if r['ok'] else 'BROKEN'}] {r['id']}")
        for pr in r["problems"]:
            lines.append(f"           {pr}")
        for nt in r.get("notes") or []:
            lines.append(f"           note: {nt}")
        bad += 0 if r["ok"] else 1
    lines += ["", f"{len(res) - bad}/{len(res)} findings intact"]
    emit(args, lines, {"results": res, "intact": len(res) - bad, "broken": bad})
    sys.exit(0 if bad == 0 else 1)


def cmd_finding_seal(args):
    path = os.path.join(fnd._dir(args.engagement), f"{args.id}.json")
    if not os.path.exists(path):
        print(f"no such finding: {args.id}", file=sys.stderr); sys.exit(2)
    with open(path) as f:
        rec = json.load(f)
    rec["seal"] = integrity.seal(args.engagement, rec)
    with open(path, "w") as f:
        json.dump(rec, f, indent=2)
    print(f"sealed {args.id} ({len(rec['seal']['field_list'])} fields, "
          f"{len(rec['seal']['artifacts'])} artifact(s))")


def cmd_fingerprint(args):
    sc, reason = _require_in_scope(args)
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    r = h.req(args.path or "/")
    if r.get("error") or r.get("code", 0) == 0:
        print(f"  could not reach {args.base}{args.path or '/'}: {r.get('error')}")
        return EXIT_UNREACHABLE
    comps = fingerprint.detect(r.get("headers") or {}, r.get("body") or "")
    if not comps:
        print("  no technology/version fingerprints detected (not proof of absence -- "
              "headers are trivially stripped)")
        return EXIT_NORESULT
    print(f"  {len(comps)} component(s) detected:")
    for c in comps:
        eco = f" [{c['ecosystem']}]" if c.get("ecosystem") else ""
        print(f"    {c['product']} {c['version'] or '?'}{eco}  ({c['confidence']}, {c['source']})")
    if args.cve:
        print("  --- correlating versions with OSV.dev (LIVE) ---")
        for e in fingerprint.enrich(comps, timeout=args.timeout):
            if e.get("error"):
                print(f"    {e['product']}@{e['version']}: OSV lookup error ({e['error']})")
            elif e.get("advisories", {}).get("total"):
                a = e["advisories"]
                print(f"    [VULN] {e['product']}@{e['version']} ({e['ecosystem']}): "
                      f"{a['total']} advisories ({a.get('critical', 0)}C/{a.get('high', 0)}H) "
                      f"{', '.join(e.get('cves', [])[:4])}")
            else:
                print(f"    [clean] {e['product']}@{e['version']} ({e['ecosystem']}): no OSV advisories")
        skipped = [c["product"] for c in comps if not (c.get("ecosystem") and c.get("version"))]
        if skipped:
            print(f"    not correlated (no OSV ecosystem/version): {', '.join(skipped)} "
                  "-- check vendor advisories")
        print("  NOTE: reachability UNASSESSED -- a CVE in code the app never calls is not a finding.")
    return EXIT_OK


def cmd_variants(args):
    """From one confirmed fault, sweep the same probe class across sibling endpoints.

    The seed is where the class was already confirmed; the sweep answers the question a
    single finding leaves open -- which OTHER endpoints share the fault. Each new variant
    is recorded as its own finding, because a copy-pasted flaw in five endpoints is five
    bugs to fix, not one.
    """
    sc, reason = _require_in_scope(args)
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    klass = args.klass
    seed = (args.seed_path, args.seed_param) if args.seed_path else None
    if args.from_finding:
        rec = fnd.get(args.engagement, args.from_finding)
        if not rec:
            print(f"  no such finding: {args.from_finding}")
            return EXIT_USAGE
        # The finding carries the class and (if it was recorded location-aware) where it
        # was confirmed -- so the sweep can start from a finding ID with nothing retyped.
        klass = klass or rec.get("class")
        if rec.get("endpoint") and not seed:
            seed = (rec["endpoint"], rec.get("param") or "q")
        loc = f"{seed[0]}?{seed[1]}" if seed else "no recorded location"
        print(f"  from finding {args.from_finding}: class={klass}, seed={loc}")
    if not klass:
        print("  no class to sweep: pass --class or --from-finding <PTX-ID>")
        return EXIT_USAGE
    if klass not in variants.supported():
        print(f"  class {klass!r} cannot be swept; supported: {', '.join(variants.supported())}")
        return EXIT_USAGE

    targets = []
    for t in (args.target or []):
        p, q = t.split(":", 1) if ":" in t else (t, args.default_param)
        targets.append((p, q))
    if seed and seed not in targets:
        targets.append(seed)
    if args.discover:
        targets += variants.discover_targets(h, default_param=args.default_param)
    targets = list(dict.fromkeys(targets))  # de-dup, preserve order
    if not targets:
        print("  nothing to sweep: pass --target PATH:PARAM (repeatable), --seed-path, or --discover")
        return EXIT_USAGE

    rep = variants.analyze(h, klass, targets, seed=seed)

    # Log every swept (class, endpoint) pair to the action log so `ptx coverage` counts the
    # sweep, and record each NEW variant as a finding. The seed is already a finding from
    # when it was first confirmed, so re-recording it would duplicate the ledger entry.
    # Each result is logged against ITS OWN endpoint -- _log_probe keys off args.path, which
    # is meaningless here because a sweep spans many endpoints, not the one on the command.
    for t in rep["results"]:
        v = t["verdict"]
        ep = f"{t['path']}?{t['param']}"
        outcome = ("vulnerable" if v.get("vulnerable")
                   else "inconclusive" if v.get("inconclusive") else "negative")
        statemod.log_action(args.engagement, "5-assessment", f"probe {klass} (variant sweep)",
                            ep, outcome, probe=klass, endpoint=ep, verdict=outcome)
        if v.get("vulnerable") and not (seed and (t["path"], t["param"]) == seed):
            v["endpoint"], v["param"] = t["path"], t["param"]  # so --from-finding finds it
            _record(args, v)

    lines = [f"  class `{klass}` swept across {rep['tested']} endpoint/param pair(s)"
             + (f"; seed {seed[0]}?{seed[1]}" if seed else "")]
    if seed:
        lines.append(f"  seed: {'RE-CONFIRMED' if rep['seed_confirmed'] else 'NOT reproduced on re-run'}")
    lines.append(f"  NEW variants: {len(rep['new_variants'])}   "
                 f"clean siblings: {len(rep['clean'])}   errored: {len(rep['errored'])}")
    for nv in rep["new_variants"]:
        lines.append(f"    [VULN] {nv['path']}?{nv['param']}  -- {nv['evidence'][:90]}")
    if not rep["new_variants"]:
        lines.append("    no additional endpoint shares this fault -- the issue is bounded to the seed")
    for er in rep["errored"]:
        lines.append(f"    [error] {er['path']}?{er['param']}  -- {er['evidence'][:80]}")
    emit(args, lines, {"class": klass, "seed": rep["seed"],
                       "seed_confirmed": rep["seed_confirmed"], "tested": rep["tested"],
                       "new_variants": rep["new_variants"], "clean": rep["clean"],
                       "errored": rep["errored"]})
    return EXIT_OK


def cmd_retest(args):
    """Re-run confirmed findings' own probes after a claimed fix (roadmap phase 8).

    Reports not-reproduced / still-open / inconclusive / manual per finding. A finding that
    no longer reproduces is NOT auto-marked fixed: a black-box re-run cannot distinguish a
    real fix from a WAF rule or a rate limit, so the operator confirms against the diff.
    """
    sc, reason = _require_in_scope(args)
    h, rps = _client(args, sc)
    print(f"  scope: {reason} | rate ceiling {rps} req/s")
    if args.finding:
        rec = fnd.get(args.engagement, args.finding)
        if not rec:
            print(f"  no such finding: {args.finding}")
            return EXIT_USAGE
        recs = [rec]
    else:
        recs = [r for r in fnd.all_findings(args.engagement) if r.get("status") == "confirmed"]
    if not recs:
        print("  no confirmed findings to retest")
        return EXIT_NORESULT

    counts = {"not-reproduced": 0, "open": 0, "inconclusive": 0, "manual": 0}
    lines, results = [], []
    for rec in recs:
        res = variants.retest_finding(h, rec)
        counts[res["status"]] += 1
        ep = rec.get("endpoint") or "(no location)"
        prm = rec.get("param")
        where = f"{ep}?{prm}" if prm else ep
        detail = res.get("evidence") or res.get("reason") or ""
        lines.append(f"  [{res['status'].upper():14s}] {rec['id']} {rec.get('class')} @ {where}"
                     f"  {detail[:70]}")
        statemod.log_action(args.engagement, "8-retest", f"retest {rec.get('class')}", where,
                            res["status"], probe=rec.get("class"), endpoint=where,
                            verdict=res["status"])
        results.append({"id": rec["id"], "class": rec.get("class"),
                        "endpoint": rec.get("endpoint"), "param": rec.get("param"),
                        "status": res["status"]})
    summary = [f"  retested {len(recs)} finding(s): {counts['not-reproduced']} not-reproduced, "
               f"{counts['open']} STILL OPEN, {counts['inconclusive']} inconclusive, "
               f"{counts['manual']} manual"]
    if counts["not-reproduced"]:
        summary.append("  NOTE: 'not-reproduced' means the exploit no longer works from here -- "
                       "confirm the root cause is fixed, not just filtered, before closing it.")
    emit(args, summary + lines,
         {"retested": len(recs), "counts": counts, "results": results})
    return EXIT_OK


def _redactor_path(args):
    return os.path.join(args.engagement, "redaction-map.json")


def _read_redact_input(args):
    path = getattr(args, "file", None)
    if not path or path == "-":
        return sys.stdin.read()
    with open(path) as f:
        return f.read()


def cmd_redact(args):
    """Replace subject identifiers with stable placeholders before text crosses the LLM boundary.

    The map is written into the local engagement directory and is the ONLY place the real
    values live; it must never be pasted into the model's context. The redacted text keeps the
    structure the model reasons over (URL paths, query parameters, response shape)."""
    require_scope(args)
    r = redact.Redactor.load(_redactor_path(args), subjects=args.subject or [])
    out = r.redact(_read_redact_input(args))
    r.save(_redactor_path(args))
    sys.stdout.write(out if out.endswith("\n") else out + "\n")
    counts = ", ".join(f"{k}={v}" for k, v in sorted(r.summary().items()))
    print(f"  [redacted {counts or 'nothing'}] map -> {_redactor_path(args)} "
          "(LOCAL ONLY -- never send the map to the model)", file=sys.stderr)
    return EXIT_OK


def cmd_unredact(args):
    """Operator-side only: restore redacted text from the local map."""
    require_scope(args)
    r = redact.Redactor.load(_redactor_path(args))
    sys.stdout.write(r.restore(_read_redact_input(args)))
    return EXIT_OK


def cmd_report(args):
    require_scope(args)
    result, lines = rpt.build(args.engagement)
    for l in lines:
        print(l)
    return EXIT_OK if result else 1


# --- cve reachability --------------------------------------------------------
def cmd_cve_reach(args):
    require_scope(args, authorized=True)
    try:
        audit = cve.audit_lockfile(args.path, timeout=args.timeout)
    except cve.CVEError as e:
        print(f"ERROR: {e}", file=sys.stderr); return EXIT_UNREACHABLE
    http = None
    if args.base:
        sc, reason = _require_in_scope(args)
        http, rps = _client(args, sc)
    result = reachability.assess_audit(audit, http, lockdata=audit.get("lockdata"))
    result["audit_counts"] = audit["counts"]
    emit(args, result["summary_lines"], result)
    statemod.log_action(args.engagement, "4-fingerprint", "cve reachability", args.path,
                        f"{result['counts']}")
    return EXIT_OK


# --- parser ------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="ptx", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--engagement", default="engagement", help="engagement directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scope", help="scope management — the hard safety boundary")
    ss = s.add_subparsers(dest="sub", required=True)
    i = ss.add_parser("init", help="create scope.yaml")
    i.add_argument("target"); i.add_argument("--in-scope", nargs="*")
    i.add_argument("--exclude", nargs="*", help="third parties: CDN, SSO, payment, analytics")
    i.add_argument("--authorization", help="own asset / contract ref / bounty program ID")
    i.add_argument("--type", default="blackbox", choices=["blackbox", "greybox", "whitebox"])
    i.add_argument("--destructive", action="store_true")
    i.add_argument("--rate", type=int, default=5, help="requests/sec ceiling")
    i.add_argument("--force", action="store_true"); i.add_argument("--json", action="store_true")
    i.set_defaults(fn=cmd_scope_init)
    c = ss.add_parser("check", help="test hosts against scope WITHOUT touching them")
    c.add_argument("hosts", nargs="+"); c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_scope_check)
    sh = ss.add_parser("show"); sh.add_argument("--json", action="store_true")
    sh.set_defaults(fn=cmd_scope_show)

    st = sub.add_parser("status", help="where the engagement is and what to do next")
    st.add_argument("--json", action="store_true"); st.set_defaults(fn=cmd_status)

    fp = sub.add_parser("fingerprint", help="detect stack components + versions; --cve correlates with live OSV.dev")
    fp.add_argument("--base", required=True)
    fp.add_argument("--path", default="/", help="path to fetch (default /)")
    fp.add_argument("--cve", action="store_true", help="correlate detected versions with OSV.dev (live)")
    fp.add_argument("--rate", type=int, default=0); fp.add_argument("--timeout", type=int, default=15)
    fp.set_defaults(fn=cmd_fingerprint)

    va = sub.add_parser("variants", help="from one confirmed fault, sweep the same class across sibling endpoints")
    va.add_argument("--class", dest="klass", choices=variants.supported(),
                    help="the confirmed finding's class (only injectable classes can be swept); "
                         "optional with --from-finding, which supplies it")
    va.add_argument("--from-finding", metavar="PTX-ID",
                    help="start from a recorded finding: takes its class and confirmed location as the seed")
    va.add_argument("--base", required=True)
    va.add_argument("--target", action="append",
                    help="sibling endpoint to sweep, as PATH:PARAM (repeatable)")
    va.add_argument("--seed-path", help="endpoint where the class was already confirmed")
    va.add_argument("--seed-param", default="q", help="param of the confirmed seed (default q)")
    va.add_argument("--discover", action="store_true",
                    help="auto-crawl the target for endpoints+params instead of listing them")
    va.add_argument("--default-param", default="id",
                    help="param to sweep on endpoints that advertise none (default id)")
    va.add_argument("--rate", type=int, default=0); va.add_argument("--timeout", type=int, default=15)
    va.set_defaults(fn=cmd_variants)

    rt = sub.add_parser("retest", help="re-run confirmed findings after a fix; reports not-reproduced / still-open")
    rt.add_argument("--base", required=True)
    rt.add_argument("--finding", metavar="PTX-ID", help="retest one finding (default: all confirmed)")
    rt.add_argument("--rate", type=int, default=0); rt.add_argument("--timeout", type=int, default=15)
    rt.set_defaults(fn=cmd_retest)

    rd = sub.add_parser("redact", help="replace subject identifiers with stable placeholders before text crosses the LLM boundary")
    rd.add_argument("file", nargs="?", help="file to redact (default: stdin)")
    rd.add_argument("--subject", action="append",
                    help="extra identifier to always redact (org/product/repo/person); repeatable")
    rd.set_defaults(fn=cmd_redact)

    ur = sub.add_parser("unredact", help="restore redacted text from the local map (operator-side only)")
    ur.add_argument("file", nargs="?", help="file to restore (default: stdin)")
    ur.set_defaults(fn=cmd_unredact)

    cv = sub.add_parser("cve", help="version -> CVE via live OSV.dev (never from memory)")
    cvs = cv.add_subparsers(dest="sub", required=True)
    lf = cvs.add_parser("lockfile", help="audit a package-lock.json against OSV.dev")
    lf.add_argument("path"); lf.add_argument("--timeout", type=int, default=30)
    lf.add_argument("--json", action="store_true"); lf.set_defaults(fn=cmd_cve_lockfile)
    rc = cvs.add_parser("reachability", help="is the vulnerable code actually reachable?")
    rc.add_argument("path"); rc.add_argument("--base", help="live target to check against")
    rc.add_argument("--rate", type=int, default=2); rc.add_argument("--timeout", type=int, default=30)
    rc.add_argument("--json", action="store_true"); rc.set_defaults(fn=cmd_cve_reach)
    q = cvs.add_parser("query", help="query one package version")
    q.add_argument("package"); q.add_argument("version")
    q.add_argument("--ecosystem", default="npm"); q.add_argument("--timeout", type=int, default=30)
    q.add_argument("--json", action="store_true"); q.set_defaults(fn=cmd_cve_query)

    o = sub.add_parser("osint", help="passive collection — phase 1, before touching the target")
    os_ = o.add_subparsers(dest="sub", required=True)
    for name, fn, extra in (("dns", cmd_osint_dns, []), ("subs", cmd_osint_subs, []),
                            ("emailsec", cmd_osint_emailsec, [])):
        sp = os_.add_parser(name); sp.add_argument("domain")
        sp.add_argument("--timeout", type=int, default=20); sp.add_argument("--json", action="store_true")
        sp.set_defaults(fn=fn)
    tk = os_.add_parser("takeover", help="dangling CNAMEs to claimable third-party services "
                        "(detection only — never claims anything)")
    tk.add_argument("domain")
    tk.add_argument("--hosts", help="comma-separated hosts to assess instead of enumerating")
    tk.add_argument("--timeout", type=int, default=12)
    tk.add_argument("--rate", type=int, default=5,
                    help="confirmation requests per second to third-party services")
    tk.add_argument("--json", action="store_true")
    tk.set_defaults(fn=cmd_osint_takeover)
    wb = os_.add_parser("wayback"); wb.add_argument("domain")
    wb.add_argument("--limit", type=int, default=2000); wb.add_argument("--timeout", type=int, default=40)
    wb.add_argument("--json", action="store_true"); wb.set_defaults(fn=cmd_osint_wayback)

    su = sub.add_parser("susp", help="suspicion ledger — findings stop being binary")
    sus = su.add_subparsers(dest="sub", required=True)
    a = sus.add_parser("add"); a.add_argument("surface"); a.add_argument("vclass")
    a.add_argument("--why", required=True); a.add_argument("--hypothesis", default="")
    a.add_argument("--falsification", default=""); a.add_argument("--json", action="store_true")
    a.set_defaults(fn=cmd_susp_add)
    l = sus.add_parser("list"); l.add_argument("--state"); l.add_argument("--json", action="store_true")
    l.set_defaults(fn=cmd_susp_list)
    se = sus.add_parser("set"); se.add_argument("id"); se.add_argument("state",
        choices=["suspected", "probing", "substantiated", "confirmed", "falsified"])
    se.add_argument("--note", default=""); se.add_argument("--json", action="store_true")
    se.set_defaults(fn=cmd_susp_set)

    pr = sub.add_parser("probe", help="active tests — each returns a verdict with evidence")
    pr.add_argument("probe", choices=["unauthenticated", "exposure", "headers", "idor",
                                      "sqli", "xss", "stored-xss", "cmdi", "ssrf",
                                      "traversal", "jwt-none", "redirect", "method-tamper",
                                      "ssti", "race", "negative-qty", "price-tamper",
                                      "refund-abuse", "workflow-bypass", "csrf",
                                      "acl-bypass", "user-enum", "cors", "privilege",
                                      "session-forge", "confused-deputy", "git-history-leak"],
                    help="'unauthenticated' runs every probe that needs no parameters; "
                         "the rest need --path/--param and must be named explicitly. "
                         "There is no 'all' — a probe that runs against the wrong endpoint "
                         "produces a meaningless result, not a thorough one.")
    pr.add_argument("--base", required=True)
    pr.add_argument("--path", default="/"); pr.add_argument("--param", default="q")
    pr.add_argument("--get-path", default="/"); pr.add_argument("--cookie")
    pr.add_argument("--as", dest="as_identity", metavar="NAME",
                    help="act as a stored identity instead of passing --cookie inline")
    pr.add_argument("--as-high", metavar="NAME",
                    help="the privileged identity, for the `privilege` probe")
    pr.add_argument("--seed-path", help="request that establishes the session "
                                        "(session-forge); often a login POST")
    pr.add_argument("--seed-method", default="GET")
    pr.add_argument("--seed-body", help="JSON body for the seed request")
    pr.add_argument("--forge-path", help="path of the privileged write to replay")
    pr.add_argument("--forge-body", help="JSON body of the privileged write; if omitted, "
                                         "the gated field is discovered automatically")
    pr.add_argument("--marker-field", default="message",
                    help="body field used to recognise the record we created")
    pr.add_argument("--repo", help="git repo URL or local path (git-history-leak)")
    pr.add_argument("--upstream", default="https://api.github.com",
                    help="the real API the proxy forwards to (confused-deputy)")
    pr.add_argument("--auth-path", default="/user",
                    help="an upstream path that normally needs auth (confused-deputy)")
    pr.add_argument("--private-path", default="/user/repos?visibility=private",
                    help="upstream path proving token over-scope (confused-deputy)")
    pr.add_argument("--own-id", default="1"); pr.add_argument("--other-id", default="2")
    pr.add_argument("--owner-field", default="user_id")
    pr.add_argument("--context", default="like", choices=["like", "quote", "num"])
    pr.add_argument("--canary-url"); pr.add_argument("--payload"); pr.add_argument("--marker")
    pr.add_argument("--user", help="username believed to exist (user-enum)")
    pr.add_argument("--user-field", default="username", dest="user_field",
                    help="name of the username field in the login body (default: username)")
    pr.add_argument("--data", default="{}"); pr.add_argument("--n", type=int, default=10)
    pr.add_argument("--rate", type=int, default=0,
                    help="lower the rate ceiling from scope.yaml (never raises it)")
    pr.add_argument("--timeout", type=int, default=15); pr.add_argument("--json", action="store_true")
    pr.set_defaults(fn=cmd_probe)

    ma = sub.add_parser("probe-mass-assignment", help="mass assignment with effect verification")
    ma.add_argument("--base", required=True); ma.add_argument("--path", required=True)
    ma.add_argument("--cookie"); ma.add_argument("--fields", default='{"is_admin":1,"credits":99999}')
    ma.add_argument("--discover", action="store_true",
                    help="discover privileged field names from the server's own responses "
                         "instead of guessing is_admin/credits; tries every type spelling "
                         "of a boolean gate")
    ma.add_argument("--get-path", help="listing endpoint to read records back from "
                                       "(discover mode); defaults to --path")
    ma.add_argument("--body", default="{}",
                    help="JSON body template for discover mode; the marker field is "
                         "added automatically. Example: {\"author\":\"ptx\"}")
    ma.add_argument("--marker-field", default="message",
                    help="body field used to recognise the record we created")
    ma.add_argument("--verify-path"); ma.add_argument("--verify-key", default="users")
    ma.add_argument("--verify-match-key", default="username"); ma.add_argument("--verify-match-value")
    ma.add_argument("--rate", type=int, default=0); ma.add_argument("--timeout", type=int, default=15)
    ma.add_argument("--json", action="store_true"); ma.set_defaults(fn=cmd_probe_mass_assignment)

    lg = sub.add_parser("logic", help="solve for a business-logic invariant violation (needs z3)")
    lg.add_argument("--base", required=True); lg.add_argument("--endpoint", required=True)
    lg.add_argument("--param", action="append", metavar="NAME:LO:HI",
                    help="integer parameter domain, repeatable. Example: --param discount:0:200")
    lg.add_argument("--invariant", required=True,
                    help="expression over the parameters that must never hold, e.g. "
                         "\"price*qty*(100-discount) < 0\"")
    lg.add_argument("--verify", required=True,
                    help="expression over the response JSON fields confirming the forbidden "
                         "outcome, e.g. \"total < 0\"")
    lg.add_argument("--baseline", help="JSON legitimate request used as a control")
    lg.add_argument("--method", default="POST")
    lg.add_argument("--rate", type=int, default=0); lg.add_argument("--timeout", type=int, default=15)
    lg.add_argument("--json", action="store_true"); lg.set_defaults(fn=cmd_logic)

    rc = sub.add_parser("race-consume", help="fire concurrent requests at a single-use action; judge by the state delta")
    rc.add_argument("--base", required=True)
    rc.add_argument("--state-endpoint", required=True, help="GET returning the observable state JSON")
    rc.add_argument("--action-path", required=True, help="the single-use action fired concurrently")
    rc.add_argument("--state-field", required=True, help="numeric field in the state JSON to watch")
    rc.add_argument("--unit", required=True, help="state change ONE success produces (e.g. 50)")
    rc.add_argument("--body", help="JSON body for the action")
    rc.add_argument("--method", default="POST")
    rc.add_argument("--requests", type=int, default=8, help="concurrent requests to fire (default 8)")
    rc.add_argument("--rate", type=int, default=0); rc.add_argument("--timeout", type=int, default=15)
    rc.add_argument("--json", action="store_true"); rc.set_defaults(fn=cmd_race_consume)

    ds = sub.add_parser("double-spend", help="replay a one-time action to test for double-spend / coupon reuse")
    ds.add_argument("--base", required=True)
    ds.add_argument("--state-endpoint", required=True, help="GET returning the observable state JSON")
    ds.add_argument("--action-path", required=True, help="the one-time action, applied twice")
    ds.add_argument("--state-field", required=True, help="numeric field in the state JSON to watch (e.g. balance)")
    ds.add_argument("--body", help="JSON body for the action")
    ds.add_argument("--method", default="POST")
    ds.add_argument("--rate", type=int, default=0); ds.add_argument("--timeout", type=int, default=15)
    ds.add_argument("--json", action="store_true"); ds.set_defaults(fn=cmd_double_spend)

    cl = sub.add_parser("probe-credential-leak", help="find a usable credential embedded in a response")
    cl.add_argument("--base", required=True); cl.add_argument("--endpoint", required=True)
    cl.add_argument("--method", default="GET")
    cl.add_argument("--rate", type=int, default=0); cl.add_argument("--timeout", type=int, default=15)
    cl.add_argument("--json", action="store_true"); cl.set_defaults(fn=cmd_probe_credential_leak)

    ss = sub.add_parser("session", help="named identities, so a probe can act as a "
                                        "specific user — cookies stored 0600")
    sss = ss.add_subparsers(dest="sub", required=True)
    sl = sss.add_parser("login", help="POST credentials and store the returned session")
    sl.add_argument("name", help="the label other commands refer to, e.g. 'alice'")
    sl.add_argument("--base", required=True); sl.add_argument("--path", default="/login")
    sl.add_argument("--user", required=True); sl.add_argument("--password", required=True)
    sl.add_argument("--user-field", default="username"); sl.add_argument("--pass-field", default="password")
    sl.add_argument("--role", default="", help="what this identity is for, e.g. 'admin'")
    sl.add_argument("--note", default="")
    sl.add_argument("--rate", type=int, default=0); sl.add_argument("--timeout", type=int, default=15)
    sl.add_argument("--json", action="store_true"); sl.set_defaults(fn=cmd_session)
    sli = sss.add_parser("list"); sli.add_argument("--json", action="store_true")
    sli.set_defaults(fn=cmd_session)
    sr = sss.add_parser("remove"); sr.add_argument("name"); sr.set_defaults(fn=cmd_session)

    dc = sub.add_parser("discover", help="find the endpoints that exist, measured "
                                          "against a not-found baseline")
    dc.add_argument("--base", required=True)
    dc.add_argument("--start", nargs="*", default=["/"],
                    help="paths to begin from; referenced paths are followed from here")
    dc.add_argument("--wordlist", help="one path per line; defaults to a small built-in "
                                       "list, because a big wordlist against a soft-404 "
                                       "target measures noise")
    dc.add_argument("--limit", type=int, default=250, help="max paths to request")
    dc.add_argument("--depth", type=int, default=2, help="crawl depth from each start path")
    dc.add_argument("--methods", action="store_true",
                    help="ask OPTIONS/POST/PUT/DELETE on each discovered path")
    dc.add_argument("--rate", type=int, default=0); dc.add_argument("--timeout", type=int, default=15)
    dc.add_argument("--json", action="store_true"); dc.set_defaults(fn=cmd_discover)

    fi = sub.add_parser("finding", help="findings — validated records, not free text")
    fis = fi.add_subparsers(dest="sub", required=True)
    fl = fis.add_parser("list"); fl.add_argument("--json", action="store_true")
    fl.set_defaults(fn=cmd_finding_list)
    fv = fis.add_parser("validate", help="refuses findings lacking evidence or impact")
    fv.add_argument("--json", action="store_true"); fv.set_defaults(fn=cmd_finding_validate)
    fs = fis.add_parser("set")
    fs.add_argument("id"); fs.add_argument("--impact"); fs.add_argument("--remediation")
    fs.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "Info"])
    fs.add_argument("--reproduction"); fs.add_argument("--artifact", action="append")
    fs.add_argument("--status", choices=["confirmed", "refuted", "needs-review"],
                    help="mark a finding refuted to feed the Memory Loop")
    fs.add_argument("--refute-reason",
                    help="why the finding is wrong; required with --status refuted")
    fs.add_argument("--json", action="store_true"); fs.set_defaults(fn=cmd_finding_set)

    cv2 = sub.add_parser("coverage", help="what was tested and what was not")
    cv2.add_argument("--json", action="store_true"); cv2.set_defaults(fn=cmd_coverage)

    rc = sub.add_parser("recon", help="ports, TLS and HTTP fingerprint — scope-gated")
    rcs = rc.add_subparsers(dest="sub", required=True)
    for nm, hlp in (("ports", "TCP connect scan (no raw sockets, no root)"),
                    ("tls", "certificate and protocol inspection"),
                    ("http", "server fingerprint, cookies, methods, identity hints"),
                    ("run", "all of the above on whatever is listening")):
        sp = rcs.add_parser(nm, help=hlp)
        sp.add_argument("target", help="host[:port], checked against scope.yaml")
        sp.add_argument("--ports", help="e.g. '80,443,8000-8010' (ports/run only)")
        sp.add_argument("--port", type=int, default=443, help="TLS port (tls only)")
        sp.add_argument("--timeout", type=float, default=1.5)
        sp.add_argument("--rate", type=int, default=0,
                        help="lower the rate ceiling from scope.yaml (never raises it)")
        sp.add_argument("--json", action="store_true")
        sp.set_defaults(fn=cmd_recon, what=nm)

    cn = sub.add_parser("chain", help="attack chains: what each finding unlocks, and which "
                                      "severities assume more than was proven")
    cn.add_argument("--walk", action="store_true",
                    help="actually attempt the chains against --base instead of inferring")
    cn.add_argument("--base", help="target for --walk (scope-checked)")
    cn.add_argument("--walk-endpoint", default="/api/me",
                    help="endpoint that consumes a token, for the identity chain")
    cn.add_argument("--walk-login", help="login path for the credentials chain")
    cn.add_argument("--walk-admin-endpoint", default="/api/admin/users",
                    help="an endpoint that should require admin, for the alg:none walk")
    cn.add_argument("--rate", type=int, default=0)
    cn.add_argument("--timeout", type=int, default=15)
    cn.add_argument("--json", action="store_true"); cn.set_defaults(fn=cmd_chain)

    rl = sub.add_parser("reliability", help="per-probe false-positive history (Memory Loop)")
    rl.add_argument("--json", action="store_true"); rl.set_defaults(fn=cmd_reliability)

    vf = sub.add_parser("verify", help="check evidence integrity against the seals")
    vf.add_argument("--json", action="store_true"); vf.set_defaults(fn=cmd_verify)

    sl = sub.add_parser("seal", help="seal a finding's evidence under a SHA-256 digest")
    sl.add_argument("id"); sl.set_defaults(fn=cmd_finding_seal)

    bl = pr  # business-logic options live on the same probe parser
    bl.add_argument("--item-field", default="sku", help="product field (negative-qty, price-tamper)")
    bl.add_argument("--sku", help="product identifier to order")
    bl.add_argument("--qty-field", default="qty")
    bl.add_argument("--qty", type=int, default=-3, help="negative quantity to submit")
    bl.add_argument("--price-field", default="unit_price")
    bl.add_argument("--tampered-price", type=float, default=0.01)
    bl.add_argument("--refund-amount", type=float, default=5000.0)
    bl.add_argument("--refund-order", type=int, default=999999,
                    help="an order id that does not exist")
    bl.add_argument("--gate-field", default="validated",
                    help="the client-supplied step flag (workflow-bypass)")
    bl.add_argument("--balance-path", help="endpoint returning the account balance")
    bl.add_argument("--balance-field", default="credits",
                    help="JSON field holding the balance")
    bl.add_argument("--samesite", help="SameSite value of the session cookie, if known")
    # CSRF needs a way to observe the state change. Same idea as the business-logic
    # probes: the verdict comes from the effect, never from the status code.
    bl.add_argument("--verify-path", help="endpoint that reveals the state (csrf)")
    bl.add_argument("--verify-key", default="email",
                    help="JSON field holding the state to check (csrf)")
    bl.add_argument("--verify-value", help="substring proving the change took effect (csrf)")

    rp = sub.add_parser("report", help="generate report — BLOCKS if any finding is invalid")
    rp.add_argument("--json", action="store_true"); rp.set_defaults(fn=cmd_report)

    ck = sub.add_parser("selfcheck", help="pre-report checklist — blocks delivery on failure")
    ck.add_argument("--json", action="store_true"); ck.set_defaults(fn=cmd_selfcheck)
    return p


def main():
    args = build_parser().parse_args()
    try:
        sys.exit(args.fn(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
