"""Randomised differential testing for the probes.

The benchmark has a structural weakness: I wrote both the vulnerable target and the
oracles that grade against it. A probe could score 59/59 by being tuned to those specific
endpoints rather than by detecting the vulnerability class. Nothing inside that loop can
tell the difference.

This harness breaks the loop. A seeded generator builds an application whose every
endpoint is randomly either vulnerable or correctly implemented, and ground truth comes
from the *generator's own decisions* — not from a hand-written oracle list. The probes
are then run against applications they have never seen.

What this can prove that the benchmark cannot: that detection generalises across
implementation styles. A concatenated query can be built many ways, and a probe that only
recognises one of them is overfitted. Across enough seeds, overfitting shows up as a
detection rate below 1.0 and, more importantly, a false-positive rate above 0.

Run:  python3 tests/property_targets.py [SEEDS]     (default 12, env PTX_PROP_SEEDS)
"""

import json
import os
import random
import sys
import threading
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ptx"))
sys.path.insert(0, ROOT)

try:
    from flask import Flask, request, jsonify
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

if HAVE_FLASK:
    from werkzeug.serving import make_server


# --------------------------------------------------------------------------- generators
# Each returns (route_fn, vulnerable_bool). The bool is the ground truth and is recorded
# at generation time, before any probe runs.

def gen_sqli(rng, db):
    """A search endpoint, randomly concatenated or bound."""
    vuln = rng.random() < 0.5
    style = rng.choice(["like", "quoted", "numeric"]) if vuln else rng.choice(["like", "quoted"])

    def route():
        q = request.args.get("q", "")
        if vuln:
            if style == "like":
                rows = [r for r in db if q.strip("%' ") and q.strip("%' ") in r["name"]] \
                       if "'" not in q else _raw_like(db, q)
                rows = _raw_like(db, q)
            elif style == "quoted":
                rows = _raw_quoted(db, q)
            else:
                rows = _raw_numeric(db, q)
        else:
            rows = [r for r in db if q.strip("%") in r["name"]]
        return jsonify({"count": len(rows), "rows": rows})
    return route, vuln


def _raw_like(db, q):
    """Emulate `SELECT * FROM t WHERE name LIKE '%{q}%'` by interpreting the SQL."""
    inner = q
    if inner.startswith("%"):
        inner = inner[1:]
    if inner.endswith("%"):
        inner = inner[:-1]
    if "'" in inner or "--" in inner:
        return _eval_predicate(db, inner)
    return [r for r in db if inner in r["name"]]


def _raw_quoted(db, q):
    if "'" in q or "--" in q:
        return _eval_predicate(db, q)
    return [r for r in db if r["name"] == q]


def _raw_numeric(db, q):
    if "AND" in q.upper() or "--" in q:
        return _eval_predicate(db, q.split("AND")[0].strip())
    try:
        return [r for r in db if r["id"] == int(q)]
    except ValueError:
        raise ValueError("near \"\": syntax error")


def _eval_predicate(db, expr):
    """Tiny SQL-subset evaluator, so boolean differential has something real to detect.

    This is the harness, not the probe, and it was wrong first: it matched only the bare
    `1=1` form, so the standard `'1'='1` payload evaluated to nothing, both branches
    returned zero rows, and the probe correctly reported INCONCLUSIVE. That disagreement
    was the emulator's fault, and fixing the probe for it would have been exactly wrong.

    A second version was also wrong, differently: stripping whitespace before matching
    glued the AND keyword onto its operand, so `AND'1'='1` parsed as `AND1 = 1` and every
    comparison looked false. Keywords are removed first, then each term is evaluated.
    """
    import re as _re
    e = expr.replace("--", " ")
    # Drop SQL keywords before comparing operands, or they become part of the operand.
    e = _re.sub(r"\b(AND|OR|WHERE|SELECT|FROM|UNION)\b", " ", e, flags=_re.I)
    terms = [t.strip() for t in _re.split(r"\s+", e) if t.strip()]
    if not terms:
        return list(db)
    decided = False
    for t in terms:
        m = _re.match(r"^[\'\"`]?(\w+)[\'\"`]?\s*=\s*[\'\"`]?(\w+)[\'\"`]?$", t)
        if not m:
            continue
        decided = True
        if m.group(1) != m.group(2):
            return []
    if not decided:
        needle = expr.strip().strip(chr(39)+chr(34)+' ')
        return [r for r in db if needle and needle in r["name"]]
    return list(db)


def gen_xss(rng):
    vuln = rng.random() < 0.5
    encoder = rng.choice(["html_escape", "json_only", "strip_tags"]) if not vuln else None

    def route():
        name = request.args.get("name", "")
        if vuln:
            return f"<html><body>Hello {name}</body></html>", 200, \
                   {"Content-Type": "text/html"}
        if encoder == "html_escape":
            import html
            body = html.escape(name)
        elif encoder == "json_only":
            return jsonify({"greeting": name})
        else:
            import re as _re
            body = _re.sub(r"<[^>]*>", "", name)
        return f"<html><body>Hello {body}</body></html>", 200, {"Content-Type": "text/html"}
    return route, vuln


def gen_cmdi(rng):
    vuln = rng.random() < 0.5

    def route():
        host = request.args.get("host", "")
        if vuln:
            import subprocess
            try:
                out = subprocess.run(f"echo ping {host}", shell=True, capture_output=True,
                                     text=True, timeout=5)
                return jsonify({"output": out.stdout})
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        import re as _re
        if not _re.match(r"^[A-Za-z0-9.\-]+$", host):
            return jsonify({"error": "invalid host"}), 400
        return jsonify({"output": f"ping {host} (simulated)\n"})
    return route, vuln


def gen_traversal(rng, basedir, secret_rel):
    vuln = rng.random() < 0.5

    def route():
        f = request.args.get("file", "")
        if vuln:
            p = os.path.join(basedir, f)
        else:
            p = os.path.realpath(os.path.join(basedir, f))
            if not p.startswith(os.path.realpath(basedir) + os.sep):
                return jsonify({"error": "forbidden"}), 403
        try:
            with open(p) as fh:
                return fh.read(), 200, {"Content-Type": "text/plain"}
        except Exception:
            return jsonify({"error": "not found"}), 404
    return route, vuln


def gen_redirect(rng):
    vuln = rng.random() < 0.5
    allow = ["/", "/home", "/dashboard"]

    def route():
        nxt = request.args.get("next", "/")
        if vuln:
            from flask import redirect as _r
            return _r(nxt)
        if nxt not in allow:
            from flask import redirect as _r
            return _r("/")
        from flask import redirect as _r
        return _r(nxt)
    return route, vuln


def gen_headers(rng):
    """Security headers present or absent — the ground truth is which were set.

    The coin flip decides the VERDICT first and the headers follow from it. It used to be
    the other way round: five independent flips, vulnerable if any was missing. A safe
    variant then needed all five heads — 1 in 32 — so across 60 seeds the generator
    produced 60 vulnerable endpoints and zero safe ones. The class still reported 0 FP
    and 0 FN, because a probe that answered "vulnerable" unconditionally would have
    scored perfectly against it. Skewed ground truth is vacuous ground truth.
    """
    hdrs = ("Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy",
            "X-Content-Type-Options", "Referrer-Policy")
    vuln = rng.random() < 0.5
    if vuln:
        # drop at least one, so the variant is genuinely vulnerable
        sets = {h: (rng.random() < 0.5) for h in hdrs}
        if all(sets.values()):
            sets[rng.choice(hdrs)] = False
    else:
        sets = {h: True for h in hdrs}

    def route():
        resp = jsonify({"ok": True})
        for h, on in sets.items():
            if on:
                resp.headers[h] = "test-value"
        return resp
    return route, vuln, sets


def gen_ssti(rng):
    vuln = rng.random() < 0.5

    def route():
        # probes.Http posts JSON, which is also what the benchmark target reads. An
        # earlier version read request.form, so the payload never arrived and the probe
        # correctly reported no template injection — a harness bug, not a probe one.
        tpl = ((request.json or {}) if request.is_json else {}).get("template") \
              or request.form.get("template", "")
        if vuln:
            class U:
                pass
            try:
                return tpl.format(user=U()), 200, {"Content-Type": "text/plain"}
            except Exception as e:
                return str(e), 500
        return f"<p>{tpl}</p>", 200, {"Content-Type": "text/html"}   # echoes, no eval
    return route, vuln


# --- business logic -----------------------------------------------------------
# These four cannot be distinguished by comparing two responses: a correctly-rejected
# negative quantity and an accepted one both return HTTP 200. Ground truth is the
# generator's own coin flip; the probe must observe the resulting account state to agree.

def gen_negative_qty(rng, acct, catalog):
    vuln = rng.random() < 0.5

    def route():
        d = (request.json or {}) if request.is_json else {}
        sku = d.get("sku")
        qty = d.get("qty", 1)
        if sku not in catalog:
            return jsonify({"error": "no such product"}), 404
        if not vuln and (not isinstance(qty, int) or isinstance(qty, bool) or qty < 1):
            return jsonify({"error": "quantity must be a positive integer"}), 422
        total = catalog[sku] * qty
        acct["credits"] -= total          # vulnerable path lets a negative total credit
        return jsonify({"sku": sku, "qty": qty, "total": total,
                        "credits": acct["credits"]})
    return route, vuln


def gen_price_tamper(rng, catalog, orders, counter):
    vuln = rng.random() < 0.5

    def route():
        d = (request.json or {}) if request.is_json else {}
        sku = d.get("sku")
        qty = d.get("qty", 1)
        if sku not in catalog:
            return jsonify({"error": "no such product"}), 404
        if not isinstance(qty, int) or isinstance(qty, bool) or qty < 1:
            return jsonify({"error": "quantity must be a positive integer"}), 422
        # vulnerable: the client chooses the price. safe: the catalog does, and the
        # submitted value is echoed back so the substitution is visibly inert.
        unit = d.get("unit_price", catalog[sku]) if vuln else catalog[sku]
        total = float(unit) * qty
        counter[0] += 1
        orders[counter[0]] = {"sku": sku, "qty": qty, "unit_price": float(unit),
                              "total": total, "state": "paid", "refunded": 0.0}
        return jsonify({"order": counter[0], "sku": sku, "unit_price": float(unit),
                        "total": total, "catalog_price": catalog[sku],
                        "client_price_ignored": d.get("unit_price")})
    return route, vuln


def gen_refund(rng, acct, orders):
    vuln = rng.random() < 0.5

    def route():
        d = (request.json or {}) if request.is_json else {}
        oid = d.get("order_id")
        if vuln:
            amount = float(d.get("amount", 0))     # attacker chooses both order and amount
            acct["credits"] += amount
            return jsonify({"refunded": amount, "credits": acct["credits"]})
        row = orders.get(oid)
        if not row or row["state"] != "paid":
            return jsonify({"error": "no such order"}), 404
        remaining = row["total"] - row["refunded"]
        if remaining <= 0:
            return jsonify({"error": "already refunded"}), 409
        row["refunded"] = row["total"]
        acct["credits"] += remaining
        return jsonify({"refunded": remaining, "credits": acct["credits"]})
    return route, vuln


def gen_workflow(rng, steps, orders, counter):
    vuln = rng.random() < 0.5

    def validate():
        counter[0] += 1
        steps[counter[0]] = {"validated": True, "paid": False}
        return jsonify({"order": counter[0], "validated": True})

    def confirm():
        d = (request.json or {}) if request.is_json else {}
        oid = d.get("order")
        if vuln:
            # the gate is whatever the client asserts
            if not d.get("validated"):
                return jsonify({"error": "not validated"}), 409
            counter[0] += 1
            orders[counter[0]] = {"sku": "WIDGET", "qty": 1, "unit_price": 0.0,
                                  "total": 0.0, "state": "confirmed", "refunded": 0.0}
            return jsonify({"order": counter[0], "state": "confirmed"})
        row = steps.get(oid)
        if not row or not row["validated"]:
            return jsonify({"error": "validation step not completed"}), 409
        counter[0] += 1
        orders[counter[0]] = {"sku": "WIDGET", "qty": 1, "unit_price": 0.0,
                              "total": 0.0, "state": "confirmed", "refunded": 0.0}
        return jsonify({"order": counter[0], "state": "confirmed"})

    def route():
        return confirm()
    route.validate = validate
    return route, vuln


def gen_csrf(rng, acct):
    """CSRF with two independent randomised defences.

    Ground truth is the COMBINATION: the endpoint is only exploitable if it fails to check
    Origin AND the session cookie is not SameSite=Strict/Lax. Generating the two
    independently is what makes this worth doing — a probe that only looked at one of them
    would score perfectly against a generator that only varied one.

    The probe is handed the login response headers rather than the SameSite value, so the
    derivation path inside the probe is exercised too.
    """
    origin_checked = rng.random() < 0.5
    samesite = rng.choice([None, "Lax", "Strict", "None", "None"])
    vuln = (not origin_checked) and (samesite or "").lower() not in ("strict", "lax")

    def login():
        resp = jsonify({"ok": True})
        cookie = f"sid=prop{rng.randrange(10**8)}; Path=/"
        if samesite:
            cookie += f"; SameSite={samesite}"
        resp.headers["Set-Cookie"] = cookie
        return resp

    def current():
        return jsonify({"email": acct.get("email", "user@acme.test")})

    def change():
        origin = request.headers.get("Origin", "")
        if origin_checked and origin and "acme.test" not in origin:
            return jsonify({"error": "cross-origin request rejected"}), 403
        d = (request.json or {}) if request.is_json else {}
        new = d.get("email")
        if not new:
            return jsonify({"error": "email required"}), 400
        acct["email"] = new
        return jsonify({"ok": True, "email": new})

    return login, current, change, vuln, {"origin_checked": origin_checked,
                                          "samesite": samesite}


def build_app(seed, workdir):
    """Build one random application. Returns (app, ground_truth, server)."""
    rng = random.Random(seed)
    app = Flask(f"prop{seed}")
    app.config["JSON_SORT_KEYS"] = False

    db = [{"id": i, "name": n} for i, n in enumerate(
        ["alice", "bob", "carol", "dave", "erin"], start=1001)]

    basedir = os.path.join(workdir, f"pub{seed}")
    os.makedirs(basedir, exist_ok=True)
    with open(os.path.join(basedir, "hello.txt"), "w") as f:
        f.write("public file")
    secret = os.path.join(workdir, f"secret{seed}.txt")
    with open(secret, "w") as f:
        f.write(f"PTXPROP{seed}SECRET")

    truth = {}
    r, v = gen_sqli(rng, db);  app.add_url_rule("/search", "search", r);        truth["sqli"] = v
    r, v = gen_xss(rng);       app.add_url_rule("/greet", "greet", r);          truth["xss"] = v
    r, v = gen_cmdi(rng);      app.add_url_rule("/api/ping", "ping", r);        truth["cmdi"] = v
    r, v = gen_traversal(rng, basedir, secret)
    app.add_url_rule("/download", "download", r);                               truth["traversal"] = v
    r, v = gen_redirect(rng);  app.add_url_rule("/redirect", "redirect", r);    truth["redirect"] = v
    r, v = gen_ssti(rng);      app.add_url_rule("/api/render", "render", r,
                                                methods=["POST"]);             truth["ssti"] = v
    r, v, sets = gen_headers(rng); app.add_url_rule("/", "root", r);            truth["headers"] = v

    # business logic: shared mutable account state, so the probes must observe effects
    acct = {"credits": 100.0}
    catalog = {"WIDGET": 49.0, "GADGET": 199.0}
    orders = {9001: {"sku": "WIDGET", "qty": 1, "unit_price": 49.0, "total": 49.0,
                     "state": "paid", "refunded": 0.0}}
    steps = {}
    counter = [9100]
    r, v = gen_negative_qty(rng, acct, catalog)
    app.add_url_rule("/api/cart", "cart", r, methods=["POST"]);      truth["negative-qty"] = v
    r, v = gen_price_tamper(rng, catalog, orders, counter)
    app.add_url_rule("/api/checkout", "checkout", r, methods=["POST"]); truth["price-tamper"] = v
    r, v = gen_refund(rng, acct, orders)
    app.add_url_rule("/api/refund", "refund", r, methods=["POST"]);  truth["refund-abuse"] = v
    r, v = gen_workflow(rng, steps, orders, counter)
    app.add_url_rule("/api/order/confirm", "confirm", r, methods=["POST"])
    app.add_url_rule("/api/order/validate", "validate", r.validate, methods=["POST"])
    truth["workflow-bypass"] = v

    @app.route("/api/credits")
    def _credits():
        return jsonify({"credits": acct["credits"]})

    _login, _current, _change, csrf_vuln, csrf_meta = gen_csrf(rng, acct)
    app.add_url_rule("/login2", "login2", _login, methods=["POST"])
    app.add_url_rule("/api/email/current", "email_current", _current)
    app.add_url_rule("/api/email/change", "email_change", _change, methods=["POST"])
    truth["csrf"] = csrf_vuln
    meta_extra = {"csrf": csrf_meta}

    # error handling: a concatenated query that breaks must surface as a server error,
    # which is what makes error-based detection meaningful
    @app.errorhandler(ValueError)
    def _vh(e):
        return f"syntax error near: {e}", 500

    @app.errorhandler(Exception)
    def _eh(e):
        return f"sqlite3.OperationalError: {e}", 500

    srv = make_server("127.0.0.1", 0, app, threaded=True)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return app, truth, srv, port, secret, {"seed": seed, "header_sets": sets,
                                           "csrf": csrf_meta}


def evaluate(seed, workdir, verbose=False):
    """Build one app, run the probes, compare to ground truth."""
    from ptxlib import probes

    app, truth, srv, port, secret, meta = build_app(seed, workdir)
    base = f"http://127.0.0.1:{port}"
    time.sleep(0.15)
    h = probes.Http(base, rps=200, timeout=8)

    results = {}
    try:
        results["sqli"] = probes.probe_sqli(h, "/search", "q", ctx="like")["vulnerable"]
        results["xss"] = probes.probe_xss(h, "/greet", "name")["vulnerable"]
        results["cmdi"] = probes.probe_cmdi(h, "/api/ping", "host")["vulnerable"]
        results["traversal"] = probes.probe_traversal(
            h, "/download", "file", "../" + os.path.basename(secret),
            f"PTXPROP{seed}SECRET")["vulnerable"]
        results["redirect"] = probes.probe_redirect(h, "/redirect", "next")["vulnerable"]
        results["ssti"] = probes.probe_ssti(h, "/api/render")["vulnerable"]
        results["headers"] = probes.probe_headers(h, "/")["vulnerable"]

        def _bal(hh, hdr=None):
            try:
                return json.loads(hh.req("/api/credits", headers=hdr)["body"]).get("credits")
            except Exception:
                return None

        results["negative-qty"] = probes.probe_negative_quantity(
            h, "/api/cart", "sku", "WIDGET", balance_fn=_bal)["vulnerable"]
        results["price-tamper"] = probes.probe_price_tamper(
            h, "/api/checkout", "sku", "GADGET")["vulnerable"]
        results["refund-abuse"] = probes.probe_refund_abuse(
            h, "/api/refund", balance_fn=_bal)["vulnerable"]
        results["workflow-bypass"] = probes.probe_workflow_bypass(
            h, "/api/order/confirm")["vulnerable"]

        # CSRF: log in through the generated route so the probe derives SameSite from the
        # real Set-Cookie header rather than being told the answer.
        lr = h.req("/login2", "POST", {})
        sid = [c.value for c in h.jar if c.name == "sid"]

        def _email_changed(hh, hdr):
            try:
                cur = json.loads(hh.req("/api/email/current", headers=hdr)["body"]).get("email", "")
                return "evil.example" in str(cur)
            except Exception:
                return False

        results["csrf"] = probes.probe_csrf(
            h, "/api/email/change", {"email": "pwned@evil.example"},
            ("sid=" + sid[0]) if sid else None, _email_changed,
            login_headers=lr.get("headers"))["vulnerable"]
    finally:
        srv.shutdown()

    tp = fp = tn = fn = 0
    detail = []
    for k, actual in results.items():
        expected = truth[k]
        if expected and actual:      tp += 1; verdict = "TP"
        elif expected and not actual: fn += 1; verdict = "FN"
        elif actual and not expected: fp += 1; verdict = "FP"
        else:                        tn += 1; verdict = "TN"
        detail.append({"class": k, "expected": expected, "actual": actual, "verdict": verdict})
    return {"seed": seed, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "detail": detail,
            "meta": meta}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PTX_PROP_SEEDS", "12"))
    if not HAVE_FLASK:
        print("flask unavailable — property tests skipped (not passed)")
        return 4
    import tempfile, shutil
    workdir = tempfile.mkdtemp()
    TP = FP = TN = FN = 0
    failures = []
    print(f"randomised differential testing — {n} generated applications\n")
    for seed in range(n):
        r = evaluate(seed, workdir)
        TP += r["tp"]; FP += r["fp"]; TN += r["tn"]; FN += r["fn"]
        bad = [d for d in r["detail"] if d["verdict"] in ("FP", "FN")]
        flag = "  " if not bad else "!!"
        print(f"{flag} seed {seed:3d}: TP={r['tp']} TN={r['tn']} FP={r['fp']} FN={r['fn']}"
              + (f"   <- {[(d['class'], d['verdict']) for d in bad]}" if bad else ""))
        failures += [dict(d, seed=seed) for d in bad]
    shutil.rmtree(workdir, ignore_errors=True)

    total = TP + FP + TN + FN
    print(f"\n{'='*64}")
    print(f"  decisions        : {total} across {n} generated applications")
    print(f"  true positives   : {TP}")
    print(f"  true negatives   : {TN}")
    print(f"  FALSE POSITIVES  : {FP}")
    print(f"  false negatives  : {FN}")
    det = (TP + TN) / total if total else 0
    fpr = FP / (FP + TN) if (FP + TN) else 0
    print(f"  accuracy         : {det:.3f}")
    print(f"  false-pos rate   : {fpr:.3f}   (the metric that matters most)")
    if failures:
        print(f"\n  disagreeing cases:")
        for f in failures[:20]:
            print(f"    seed {f['seed']} {f['class']}: expected={f['expected']} "
                  f"probe={f['actual']} ({f['verdict']})")
    return 0 if (FP == 0 and FN == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
