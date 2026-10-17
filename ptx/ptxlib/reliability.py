"""The Memory Loop — per-probe reliability, learned from outcomes.

A probe that has produced false positives before will produce them again, and the only
defence is to remember. This module tracks, per probe class, how often its VULNERABLE
verdict survived contact with a human or with the finding validator, and demotes probes
whose verdicts have stopped being trustworthy from *evidence* to *lead generation*.

That distinction is the point. A demoted probe still runs and still reports; its output
is labelled a lead rather than a finding, and the report says so. Throwing the probe away
would lose coverage; trusting it unchanged would keep producing false positives, which is
the measured failure mode of automated testing.

Outcomes come from real signals only — a finding explicitly refuted, or a suspicion moved
to `falsified`. Nothing here infers an outcome from a probe's own confidence.
"""

import json
import os

# Shared with state.py: the same exclusive lock guards every read-modify-write of
# engagement state, so a probe and a reliability update cannot interleave.
from .state import _locked

# A third of verdicts wrong demotes the probe. At the minimum sample size the possible
# rates are 0, 1/3, 2/3 and 1, so a threshold anywhere below 1/3 means "one refutation is
# enough" and anything above it means "two are". One is the right answer: this project
# weights a false positive heavier than a true positive precisely because inflated
# findings are the measured failure mode of automated testing.
THRESHOLD_FP = 0.25
MIN_SAMPLES = 3          # below this, the rate is noise and the probe stays trusted


def _path(engagement):
    return os.path.join(engagement, "reliability.json")


def load(engagement):
    p = _path(engagement)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}


def _save(engagement, data):
    """Write atomically. A kill mid-write must not truncate the ledger — it is the only
    record of which probe classes have earned or lost standing."""
    os.makedirs(engagement, exist_ok=True)
    p = _path(engagement)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def record(engagement, probe_class, outcome):
    """outcome is one of: confirmed, refuted, inconclusive."""
    if outcome not in ("confirmed", "refuted", "inconclusive"):
        raise ValueError(f"unknown outcome {outcome!r}")
    # Same lost-update race that cost state.json seven of twenty suspicions: a
    # read-modify-write of a file that is rewritten whole. Two concurrent `ptx reliability`
    # runs would each read the same counts, each add one, and one increment would vanish —
    # quietly biasing the false-positive rate the demotion decision is made from.
    with _locked(engagement):
        data = load(engagement)
        e = data.setdefault(probe_class, {"confirmed": 0, "refuted": 0, "inconclusive": 0,
                                          "demoted": False})
        e[outcome] = e.get(outcome, 0) + 1
        e["demoted"] = _should_demote(e)
        _save(engagement, data)
        return data[probe_class]


def _should_demote(e):
    decided = e.get("confirmed", 0) + e.get("refuted", 0)
    if decided < MIN_SAMPLES:
        return False
    return (e.get("refuted", 0) / decided) >= THRESHOLD_FP


def fp_rate(e):
    decided = e.get("confirmed", 0) + e.get("refuted", 0)
    if not decided:
        return None
    return e.get("refuted", 0) / decided


def sync_from_engagement(engagement, findings=None, suspicions=None):
    """Derive outcomes from engagement state so the ledger cannot drift from reality.

    A finding still standing and validated counts as a confirmed verdict for its probe
    class. A finding a human refuted counts against it. This is deliberately the only
    way the ledger is populated during normal use.
    """
    data = load(engagement)
    for f in findings or []:
        cls = f.get("class")
        if not cls:
            continue
        st = f.get("status", "confirmed")
        if st == "refuted":
            outcome = "refuted"
        elif st == "confirmed":
            outcome = "confirmed"
        else:
            continue
        e = data.setdefault(cls, {"confirmed": 0, "refuted": 0, "inconclusive": 0,
                                  "demoted": False})
        key = "_synced_" + f.get("id", "")
        previous = e.get(key)
        if previous == outcome:
            continue
        # The dedupe key used to be a bare boolean, so once a finding had been counted as
        # confirmed it could never be counted again — and a finding is ALWAYS created
        # confirmed and refuted later, which is the only sequence that ever happens in
        # practice. The result was a Memory Loop that could not observe a refutation at
        # all: `refuted` stayed 0 and every probe stayed "trusted" no matter how often a
        # human rejected its output. Store the outcome instead, and move the count when
        # it changes, so the ledger reflects what the findings currently say.
        if previous is True:
            # A ledger written before outcomes were tracked stored a bare boolean, so the
            # original outcome is unrecoverable. A finding starts life confirmed and is
            # only later refuted, so "confirmed" is the sound assumption; guessing wrong
            # here would leave a phantom count in the ledger forever.
            previous = "confirmed"
        if previous:
            e[previous] = max(0, e.get(previous, 0) - 1)
        e[outcome] = e.get(outcome, 0) + 1
        e[key] = outcome
    # A falsified suspicion means the probe ran and correctly found nothing — the
    # *suspicion* was falsified, not the probe's verdict. Two different senses of
    # "refuted" were being added into the same counter, so a probe that correctly
    # reported a clean result four times was demoted as unreliable: "4/4 verdicts
    # refuted — output is a lead to verify, not a finding". The better a probe was at
    # reporting clean results, the faster it lost standing. On a hardened target the
    # Memory Loop would demote every class, and the operator would be told to distrust
    # the tool precisely when it was working.
    #
    # Correct negatives are still worth counting — they show the probe was exercised —
    # but they must never enter the false-positive rate, which is a ratio of findings
    # confirmed against findings a human refuted.
    for s in suspicions or []:
        if s.get("state") == "falsified" and s.get("class"):
            e = data.setdefault(s["class"], {"confirmed": 0, "refuted": 0,
                                             "inconclusive": 0, "demoted": False})
            k = "_synced_sus_" + str(s.get("id", ""))
            if not e.get(k):
                e["correct_negative"] = e.get("correct_negative", 0) + 1
                e[k] = True
    for e in data.values():
        e["demoted"] = _should_demote(e)
    _save(engagement, data)
    return data


def classify(data):
    """Split probe classes into trusted and demoted, with the numbers that decided it."""
    trusted, demoted = [], []
    for cls, e in sorted(data.items()):
        if cls.startswith("_"):
            continue
        row = {"class": cls, "confirmed": e.get("confirmed", 0),
               "refuted": e.get("refuted", 0),
               "inconclusive": e.get("inconclusive", 0),
               "correct_negative": e.get("correct_negative", 0),
               "fp_rate": fp_rate(e)}
        decided = row["confirmed"] + row["refuted"]
        if decided < MIN_SAMPLES:
            row["note"] = f"only {decided} decided outcome(s); too few to judge"
            trusted.append(row)
        elif e.get("demoted"):
            row["note"] = (f"{row['refuted']}/{decided} verdicts refuted — output is a "
                           f"lead to verify, not a finding")
            demoted.append(row)
        else:
            row["note"] = f"{row['confirmed']}/{decided} verdicts held"
            trusted.append(row)
    return trusted, demoted


def render(data):
    trusted, demoted = classify(data)
    L = ["## Probe reliability (Memory Loop)", ""]
    if not trusted and not demoted:
        return ("## Probe reliability (Memory Loop)\n\n_No probe has enough decided "
                "outcomes to judge yet._")
    L.append("A probe that has produced false positives will produce them again. These "
             "rates come from findings that were confirmed or refuted, never from a "
             "probe's own confidence.")
    L.append("")
    L.append("| probe | confirmed | refuted | correct negatives | FP rate | standing |")
    L.append("|---|---|---|---|---|---|")
    for r in trusted + demoted:
        rate = "n/a" if r["fp_rate"] is None else f"{r['fp_rate']:.0%}"
        standing = "**DEMOTED to lead-generation**" if r in demoted else "trusted"
        L.append(f"| `{r['class']}` | {r['confirmed']} | {r['refuted']} | "
                 f"{r.get('correct_negative', 0)} | {rate} | {standing} |")
    L.append("")
    L.append("_Correct negatives_ are runs where the probe found nothing and nothing was "
             "there to find. They show a class was exercised; they are deliberately "
             "excluded from the FP rate, which measures findings a human refuted against "
             "findings that stood.")
    L.append("")
    if demoted:
        L.append("Demoted probes still run. Their output is a lead requiring independent "
                 "confirmation before it may be written up as a finding.")
    return "\n".join(L)
