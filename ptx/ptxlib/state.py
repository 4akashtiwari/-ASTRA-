"""
Engagement state, action log, and the Suspicion Ledger.

The Suspicion Ledger is what stops findings being binary. Everything that might be
vulnerable gets a record with a lifecycle, so nothing is lost and no phase can be
declared complete while suspicions sit unprobed.
"""
import json, os, time
from contextlib import contextmanager

try:
    import fcntl
except ImportError:                                  # pragma: no cover - Windows
    fcntl = None


@contextmanager
def _locked(engagement):
    """Hold an exclusive lock across a read-modify-write of state.json.

    `state.json` is rewritten whole on every mutation, and an agent orchestrating parallel
    probes — which is exactly the architecture this toolkit is built for — runs several
    `ptx` processes against one engagement at once. Without a lock, two processes read the
    same state, each append their own entry, and the last write wins: measured 20
    concurrent probe commands leaving 13 suspicions, with 7 silently gone.

    The suspicion ledger is the audit trail. Losing entries from it does not crash anything;
    it just quietly understates what was examined, and the reliability ledger and the
    report are both derived from it.
    """
    os.makedirs(engagement, exist_ok=True)
    if fcntl is None:
        yield
        return
    with open(_p(engagement, ".lock"), "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)

STATES = ("suspected", "probing", "substantiated", "confirmed", "falsified")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _p(engagement, name):
    return os.path.join(engagement, name)


def init(engagement):
    os.makedirs(engagement, exist_ok=True)
    os.makedirs(os.path.join(engagement, "artifacts"), exist_ok=True)
    os.makedirs(os.path.join(engagement, "osint"), exist_ok=True)
    os.makedirs(os.path.join(engagement, "findings"), exist_ok=True)
    sp = _p(engagement, "state.json")
    if not os.path.exists(sp):
        with open(sp, "w") as f:
            json.dump({"phase": "0-authorization", "action_count": 0, "scope_blocks": 0,
                       "finding_count": 0, "suspicions": [], "created": _now()}, f, indent=2)
    lp = _p(engagement, "log.md")
    if not os.path.exists(lp):
        with open(lp, "w") as f:
            f.write(f"# Engagement log\n\n## [{_now()}] phase:0 tier:sentinel\n"
                    f"CMD: ptx scope init\nRESULT: scope recorded, state initialised\n")
    return sp


def load(engagement):
    sp = _p(engagement, "state.json")
    if not os.path.exists(sp):
        init(engagement)
    with open(sp) as f:
        return json.load(f)


def _save(engagement, st):
    """Write state.json atomically.

    A process killed mid-write used to leave a truncated file, and every later command
    then failed to load the engagement — losing the whole history to recover one write.
    Writing to a sibling and renaming makes the change atomic on POSIX.
    """
    p = _p(engagement, "state.json")
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


# Structured history, capped so a long engagement cannot grow state.json without bound.
MAX_ACTIONS = 4000


def log_action(engagement, phase, action, target, result, probe=None, endpoint=None,
               verdict=None, inconclusive_reason=None, extra=None):
    """Record an action as prose for humans AND as a structured entry for the tooling.

    The prose-only version was the reason no coverage analysis was possible: the
    engagement's entire history existed as markdown, so nothing could answer "which probe
    classes were applied to which endpoints". A log a program cannot read is a log that
    only supports claims, not checks.
    """
    with _locked(engagement):
        st = load(engagement)
        st["action_count"] = st.get("action_count", 0) + 1
        st["phase"] = phase
        entry = {"ts": _now(), "phase": phase, "action": action, "target": target,
                 "result": result}
        if probe is not None:
            entry["probe"] = probe
        if endpoint is not None:
            entry["endpoint"] = endpoint
        if verdict is not None:
            entry["verdict"] = verdict
        if inconclusive_reason is not None:
            entry["inconclusive_reason"] = inconclusive_reason
        # Structured measurements, for the same reason the entry is JSON at all: a count
        # buried in the prose cannot be checked later, only quoted.
        for k, v in (extra or {}).items():
            entry[k] = v
        # Append-only JSONL, NOT a list inside state.json. Embedding it there made every
        # write rewrite the whole history: measured 0.97 ms/action at 200 entries rising to
        # 7.89 ms at 2000, so a long engagement got steadily slower — O(n^2) on the one
        # operation that runs most often.
        with open(_p(engagement, "actions.jsonl"), "a") as f:
            f.write(json.dumps(entry) + "\n")
        _save(engagement, st)
        with open(_p(engagement, "log.md"), "a") as f:
            f.write(f"\n## [{_now()}] phase:{phase}\nCMD: ptx {action} {target}\n"
                    f"RESULT: {result}\n")


def actions(engagement):
    """Structured history, most recent MAX_ACTIONS entries.

    Reads an append-only JSONL file. Corrupt or partial trailing lines are skipped rather
    than raising, because a truncated final line from an interrupted run must not make the
    whole history unreadable.
    """
    p = _p(engagement, "actions.jsonl")
    if not os.path.exists(p):
        # Fall back to any actions embedded in state.json by an older version.
        return load(engagement).get("actions") or []
    out = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out[-MAX_ACTIONS:]


def probe_coverage(engagement):
    """The (probe_class, endpoint) pairs actually exercised, from the structured log."""
    seen = set()
    for a in actions(engagement):
        if a.get("probe") and a.get("endpoint"):
            seen.add((a["probe"], a["endpoint"]))
    return seen


# --- suspicion ledger --------------------------------------------------------
def suspicions(engagement):
    return load(engagement).get("suspicions", [])


def add_suspicion(engagement, surface, vclass, why, hypothesis="", falsification=""):
    with _locked(engagement):
        st = load(engagement)
        susp = st.setdefault("suspicions", [])
        sid = f"SUSP-{len(susp) + 1:03d}"
        rec = {"id": sid, "surface": surface, "class": vclass, "why_suspicious": why,
               "hypothesis": hypothesis, "falsification": falsification,
               "state": "suspected", "note": "", "created_at": _now(), "updated_at": _now()}
        susp.append(rec)
        _save(engagement, st)
        with open(_p(engagement, "log.md"), "a") as f:
            f.write(f"\n## [{_now()}] phase:suspicion tier:1\n"
                    f"SUSPICION {sid} raised on {surface} [{vclass}]\nWHY: {why}\n"
                    f"FALSIFY BY: {falsification or 'not specified'}\n")
        return rec


def set_suspicion_state(engagement, sid, new_state, note=""):
    with _locked(engagement):
        if new_state not in STATES:
            raise ValueError(f"state must be one of {STATES}")
        st = load(engagement)
        for s in st.get("suspicions", []):
            if s["id"] == sid:
                s["state"] = new_state
                s["updated_at"] = _now()
                if note:
                    s["note"] = note
                if new_state == "confirmed":
                    st["finding_count"] = st.get("finding_count", 0) + 1
                _save(engagement, st)
                with open(_p(engagement, "log.md"), "a") as f:
                    f.write(f"\n## [{_now()}] phase:suspicion\n"
                            f"{sid} -> {new_state}" + (f"\nNOTE: {note}" if note else "") + "\n")
                return s
        return None
