#!/usr/bin/env python3
"""
DRY-RUN TARGET v2 — deliberately vulnerable web application, expanded.
19 planted vulnerabilities across 15 classes, for benchmark scoring.
LOCALHOST ONLY. Never deploy anywhere reachable.
"""
import os, sqlite3, subprocess, itertools, threading, time, json, base64, urllib.request
from flask import Flask, request, jsonify, g, make_response

app = Flask(__name__)
app.config["DEBUG"] = True
DB = "/tmp/dryrun2.db"
SECRET_KEY = "ptx_super_secret_key_do_not_leak_9f3a"

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(exc=None):
    d = g.pop("db", None)
    if d is not None: d.close()

def seed():
    if os.path.exists(DB): os.remove(DB)
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT,
                       is_admin INT, role TEXT, credits INT, bio TEXT);
    CREATE TABLE invoices(id INTEGER PRIMARY KEY, user_id INT, customer TEXT,
                          address TEXT, card_last4 TEXT, amount REAL);
    CREATE TABLE comments(id INTEGER PRIMARY KEY, user_id INT, body TEXT);
    CREATE TABLE redemptions(code TEXT PRIMARY KEY, used INT DEFAULT 0);
    CREATE TABLE products(sku TEXT PRIMARY KEY, name TEXT, price REAL);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, sku TEXT, qty INT,
                        unit_price REAL, total REAL, state TEXT);
    INSERT INTO products VALUES
      ('WIDGET','Blue widget',49.00), ('GADGET','Red gadget',199.00);
    INSERT INTO users VALUES
      (1,'alice','alice@acme.test',0,'user',100,'hello'),
      (2,'bob','bob@acme.test',0,'user',100,''),
      (3,'carol','carol@acme.test',1,'admin',100,'');
    INSERT INTO invoices VALUES
      (1001,1,'Alice Anderson','12 Rose St, Pune','4242',1200.00),
      (1002,1,'Alice Anderson','12 Rose St, Pune','4242', 340.50),
      (1003,2,'Bob Bhatti','88 Lake Rd, Kochi','8813', 990.00),
      (1004,2,'Bob Bhatti','88 Lake Rd, Kochi','8813',  75.25),
      (1005,3,'Carol Chawla','5 Hill Rd, Shimla','1007',5400.00);
    INSERT INTO redemptions VALUES ('WELCOME50',0);
    INSERT INTO orders VALUES (9001,1,'WIDGET',1,49.00,49.00,'paid');
    """)
    c.commit(); c.close()

_counter = itertools.count(1000)
_sessions = {}

def get_session():
    tok = request.cookies.get("sid")
    if tok in _sessions: return _sessions[tok], tok
    return None, None

def make_session(uid):
    tok = str(next(_counter))          # VULN: predictable sequential token
    _sessions[tok] = {"uid": uid}; return tok

@app.after_request
def headers(resp):
    for h in ("Content-Security-Policy","X-Frame-Options","X-Content-Type-Options",
              "Strict-Transport-Security","Referrer-Policy"):
        resp.headers.pop(h, None)
    resp.headers["Server"] = "Werkzeug/2.0 Python/3.13"
    resp.headers["X-Powered-By"] = "Flask"
    # VULN 14: permissive CORS with credentials
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# --- 1. IDOR ---------------------------------------------------------------
@app.route("/api/invoices/<int:iid>")
def invoice(iid):
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    row = db().execute(f"SELECT * FROM invoices WHERE id={iid}").fetchone()
    if not row: return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))

# --- 2. SQL injection ------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    sql = f"SELECT id, customer, amount FROM invoices WHERE customer LIKE '%{q}%'"
    try:
        rows = [dict(r) for r in db().execute(sql).fetchall()]
        return jsonify({"results": rows, "count": len(rows)})
    except Exception as e:
        return f"<h1>Database error</h1><pre>{e}</pre><pre>{sql}</pre>", 500

# --- 3. reflected XSS ------------------------------------------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "stranger")
    return f"<html><body><h1>Hello {name}!</h1></body></html>"

# --- 4. command injection --------------------------------------------------
@app.route("/api/ping")
def ping():
    host = request.args.get("host", "")
    out = subprocess.run(f"ping -c 1 {host}", shell=True,
                         capture_output=True, text=True, timeout=10)
    return jsonify({"stdout": out.stdout, "stderr": out.stderr, "rc": out.returncode})

# --- 5. exposed secrets ----------------------------------------------------
@app.route("/.env")
def dot_env():
    body = ("DB_HOST=prod-db.internal.acme.test\nDB_PASS=Sup3rS3cret!prod\n"
            f"APP_SECRET={SECRET_KEY}\nAWS_ACCESS_KEY_ID=" "AKIA" "IOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "STRIPE_KEY=" "sk_live_" "51HxExampleNotRealKey0000000000\n")
    return make_response(body, 200, {"Content-Type": "text/plain"})

@app.route("/static/app.js")
def app_js():
    js = ("const API='https://api.acme.test/v2';\n"
          "const MAPS_KEY='AIzaSyDExampleLeakedKey0000000000000';\n"
          "const ADMIN_TOKEN='eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1aWQiOjN9.';\n")
    return make_response(js, 200, {"Content-Type": "application/javascript"})

# --- 6. missing function-level authz ---------------------------------------
@app.route("/admin/users")
def admin_users():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    rows = [dict(r) for r in db().execute("SELECT * FROM users").fetchall()]
    return jsonify({"users": rows})

# --- 7. race condition -----------------------------------------------------
@app.route("/api/redeem", methods=["POST"])
def redeem():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    code = request.json.get("code", "")
    row = db().execute("SELECT used FROM redemptions WHERE code=?", (code,)).fetchone()
    if not row: return jsonify({"error": "no such code"}), 404
    time.sleep(0.15)
    if row["used"]: return jsonify({"error": "already redeemed"}), 409
    db().execute("UPDATE redemptions SET used=1 WHERE code=?", (code,))
    db().commit()
    return jsonify({"status": "credited", "amount": 50})

# --- 8. stored XSS (no escaping on read OR write) --------------------------
@app.route("/api/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        sess, _ = get_session()
        if not sess: return jsonify({"error": "auth required"}), 401
        body = request.json.get("body", "")
        db().execute("INSERT INTO comments(user_id, body) VALUES(?,?)",
                     (sess["uid"], body))
        db().commit()
        return jsonify({"ok": True})
    rows = db().execute("SELECT * FROM comments").fetchall()
    html = "".join(f"<div>{r['body']}</div>" for r in rows)   # unescaped sink
    return f"<html><body>{html}</body></html>"

# --- 9. SSRF ---------------------------------------------------------------
@app.route("/api/fetch")
def fetch():
    url = request.args.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=5) as r:   # no allowlist
            data = r.read(4096).decode("utf-8", "replace")
        return jsonify({"status": "ok", "body": data})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

# --- 10. path traversal ----------------------------------------------------
@app.route("/download")
def download():
    name = request.args.get("file", "")
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", name)  # no canonicalisation
    try:
        with open(path) as f:
            return make_response(f.read(), 200, {"Content-Type": "text/plain"})
    except Exception as e:
        return jsonify({"error": str(e)}), 404

# --- 11. JWT alg=none / unsigned token accepted ----------------------------
@app.route("/api/me")
def me():
    auth = request.headers.get("Authorization", "")
    tok = auth.replace("Bearer ", "") if auth else ""
    if not tok: return jsonify({"error": "no token"}), 401
    try:
        parts = tok.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        # VULN: signature in parts[2] is never verified
        return jsonify({"header": header, "claims": claims, "granted": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- 12. open redirect -----------------------------------------------------
@app.route("/redirect")
def redirect_ep():
    target = request.args.get("next", "/")
    resp = make_response("", 302)
    resp.headers["Location"] = target      # no allowlist
    return resp

# --- 13. mass assignment ---------------------------------------------------
@app.route("/api/profile", methods=["POST"])
def profile():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    data = request.json or {}
    allowed = ("bio",)                     # intent
    # VULN: applies every supplied key, including is_admin / role / credits
    sets, vals = [], []
    for k, v in data.items():
        sets.append(f"{k}=?"); vals.append(v)
    if not sets: return jsonify({"ok": True, "changed": []})
    vals.append(sess["uid"])
    db().execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
    db().commit()
    return jsonify({"ok": True, "changed": list(data.keys())})

# --- 15. exposed dependency manifest ---------------------------------------
@app.route("/package-lock.json")
def lockfile():
    body = json.dumps({"name": "acme-billing", "lockfileVersion": 3, "packages": {
        "node_modules/express": {"version": "4.16.0"},
        "node_modules/lodash": {"version": "4.17.4"},
        "node_modules/minimist": {"version": "0.2.1"},
        "node_modules/jsonwebtoken": {"version": "8.5.0"}}}, indent=2)
    return make_response(body, 200, {"Content-Type": "application/json"})

# --- 16. no rate limiting + user enumeration -------------------------------
@app.route("/login", methods=["POST"])
def login():
    u = request.json.get("username")
    row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if not row:
        return jsonify({"error": "no such user"}), 404    # enumerable
    tok = make_session(row["id"])
    resp = make_response(jsonify({"ok": True, "uid": row["id"]}))
    resp.set_cookie("sid", tok)                            # no flags
    return resp

# --- 17. HTTP method tampering ---------------------------------------------
@app.route("/api/account", methods=["GET", "POST"])
def account():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    if request.method == "GET":
        return jsonify({"id": sess["uid"], "note": "deletion requires POST /api/account"})
    # VULN: honours X-HTTP-Method-Override, so a GET can delete via header
    return jsonify({"deleted": True, "id": sess["uid"]})

@app.route("/api/account/delete", methods=["GET", "POST", "DELETE"])
def account_delete():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    # VULN: trusts a client-supplied method override header
    override = request.headers.get("X-HTTP-Method-Override", "").upper()
    if override == "DELETE" or request.method == "DELETE":
        return jsonify({"deleted": True, "id": sess["uid"]})
    return jsonify({"error": "use DELETE"}), 405

# --- 18. template injection (naive format-string eval) ---------------------
@app.route("/api/render", methods=["POST"])
def render():
    tmpl = (request.json or {}).get("template", "")
    ctx = {"user": "alice", "credits": 100}
    try:
        # VULN: user-controlled format string against a live context
        out = tmpl.format(**ctx)
        return jsonify({"rendered": out})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- 19. negative quantity accepted (business logic) -----------------------
@app.route("/api/cart", methods=["POST"])
def cart():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    sku, qty = d.get("sku", ""), d.get("qty", 1)
    row = db().execute("SELECT price FROM products WHERE sku=?", (sku,)).fetchone()
    if not row: return jsonify({"error": "no such product"}), 404
    # VULN: qty is never validated, so a negative quantity produces a negative total
    # and the balance is credited instead of charged.
    total = row["price"] * qty
    db().execute("UPDATE users SET credits = credits - ? WHERE id=?", (total, sess["uid"]))
    db().commit()
    return jsonify({"sku": sku, "qty": qty, "total": total,
                    "credits": db().execute("SELECT credits FROM users WHERE id=?",
                                            (sess["uid"],)).fetchone()["credits"]})


# --- 20. client-supplied unit price (business logic) -----------------------
@app.route("/api/checkout", methods=["POST"])
def checkout():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    sku = d.get("sku", "")
    # VULN: the price is taken from the request body instead of looked up
    unit = d.get("unit_price")
    row = db().execute("SELECT price FROM products WHERE sku=?", (sku,)).fetchone()
    if not row: return jsonify({"error": "no such product"}), 404
    if unit is None: unit = row["price"]
    qty = max(1, int(d.get("qty", 1)))
    total = float(unit) * qty
    oid = next(_counter)
    db().execute("INSERT INTO orders VALUES (?,?,?,?,?,?,'paid')",
                 (oid, sess["uid"], sku, qty, float(unit), total))
    db().execute("UPDATE users SET credits = credits - ? WHERE id=?", (total, sess["uid"]))
    db().commit()
    return jsonify({"order": oid, "sku": sku, "unit_price": float(unit), "total": total,
                    "catalog_price": row["price"]})


# --- 21. refund without a matching order (business logic) ------------------
@app.route("/api/refund", methods=["POST"])
def refund():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    oid, amount = d.get("order_id"), d.get("amount")
    # VULN: credits the caller without checking that the order exists, belongs to them,
    # was paid, or has not already been refunded.
    if amount is None: return jsonify({"error": "amount required"}), 400
    db().execute("UPDATE users SET credits = credits + ? WHERE id=?",
                 (float(amount), sess["uid"]))
    db().commit()
    return jsonify({"refunded": float(amount), "order": oid,
                    "credits": db().execute("SELECT credits FROM users WHERE id=?",
                                            (sess["uid"],)).fetchone()["credits"]})


# --- 22. workflow bypass via client-trusted state (business logic) ---------
@app.route("/api/order/confirm", methods=["POST"])
def order_confirm():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    # VULN: the step gate is a flag the client supplies, so the validation step can be
    # skipped entirely by asserting it already happened.
    if not d.get("validated"):
        return jsonify({"error": "validation step not completed"}), 409
    oid = next(_counter)
    db().execute("INSERT INTO orders VALUES (?,?,?,?,?,?,'confirmed')",
                 (oid, sess["uid"], d.get("sku", "WIDGET"), 1, 0.0, 0.0))
    db().commit()
    return jsonify({"order": oid, "state": "confirmed",
                    "message": "order confirmed without payment or validation"})


# --- 23. CSRF on a state-changing endpoint ---------------------------------
@app.route("/api/email/change", methods=["POST"])
def email_change():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    new = d.get("email", "")
    if not new: return jsonify({"error": "email required"}), 400
    # VULN: no Origin/Referer check and no token. The session cookie is SameSite unset,
    # so a browser attaches it to a cross-site form post automatically.
    db().execute("UPDATE users SET email=? WHERE id=?", (new, sess["uid"]))
    db().commit()
    return jsonify({"ok": True, "email": new})


@app.route("/api/email/current", methods=["GET"])
def email_current():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    row = db().execute("SELECT email FROM users WHERE id=?", (sess["uid"],)).fetchone()
    return jsonify({"email": row["email"]})


@app.route("/api/credits", methods=["GET"])
def credits():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    return jsonify({"credits": db().execute(
        "SELECT credits FROM users WHERE id=?", (sess["uid"],)).fetchone()["credits"]})


# --- 26. moderation bypass: the guard tests the VALUE, not the presence of the key
#
# Planted from a live engagement (2026-09-11, a guestbook behind a tunnel). The
# moderation queue was the only control between an anonymous visitor and the public
# page. The developer did guard the privileged field, and the guard works -- for the
# one spelling they tested. `approved: true` is refused; 1, "true" and "yes" all store
# as approved and publish immediately. The correct question is "did the client send
# this key at all", not "is it True".
_GUESTBOOK = []

@app.route("/api/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        data = request.json or {}
        if not data.get("author") or not data.get("message"):
            return jsonify({"error": "Author and message are required."}), 400
        # VULN: rejects only the literal boolean True.
        if data.get("approved") is True:
            return jsonify({"error": "Unauthorized parameter: guest submissions "
                                     "cannot set approval state."}), 403
        rec = {"id": len(_GUESTBOOK) + 1, "author": str(data.get("author")),
               "message": str(data.get("message")), "date": "2026-09-11",
               "approved": bool(data.get("approved"))}
        _GUESTBOOK.append(rec)
        if rec["approved"]:
            return jsonify({"success": True,
                            "message": "Note published to the guestbook.",
                            "note": rec}), 201
        return jsonify({"success": True, "message": "Pending moderation.", "note": rec})
    # The public listing only ever shows approved notes -- which is what makes a
    # record appearing here the proof that the gate was passed.
    return jsonify({"notes": [r for r in _GUESTBOOK if r["approved"]]})

# --- N07 the same guestbook, written correctly ------------------------------
#
# The falsification twin of V26. It must look identical from the outside -- same
# endpoint shape, same echoed record, same server-assigned "approved" default -- so
# that a probe reporting V26 cannot simply be reporting any create endpoint that
# echoes a boolean. The only difference is that unknown keys are rejected against
# an allowlist instead of being checked one value at a time.
_SAFE_GUESTBOOK = []

@app.route("/api/guestbook-safe", methods=["GET", "POST"])
def guestbook_safe():
    if request.method == "POST":
        data = request.json or {}
        # Correct: reject any key a guest is not allowed to set, whatever its value.
        unexpected = set(data) - {"author", "message"}
        if unexpected:
            return jsonify({"error": "Unauthorized parameter: %s"
                            % ", ".join(sorted(unexpected))}), 403
        if not data.get("author") or not data.get("message"):
            return jsonify({"error": "Author and message are required."}), 400
        rec = {"id": len(_SAFE_GUESTBOOK) + 1, "author": str(data["author"]),
               "message": str(data["message"]), "date": "2026-09-11",
               "approved": False}
        _SAFE_GUESTBOOK.append(rec)
        return jsonify({"success": True, "message": "Pending moderation.", "note": rec})
    return jsonify({"notes": [r for r in _SAFE_GUESTBOOK if r["approved"]]})

# --- 27. IDOR whose ownership field is NOT called user_id -------------------
#
# The same authorisation flaw as V01, with a different column name. The tool's old
# probe decided the verdict from one hardcoded field name, so this endpoint -- a real
# cross-user read -- was reported clean. Nothing about the vulnerability changed; only
# the spelling of the field that proves it.
@app.route("/api/tickets/<int:tid>")
def ticket(tid):
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    # VULN: no ownership predicate. Any authenticated caller reads any ticket.
    rows = {1: {"id": 1, "subject": "cannot log in", "author_id": 1, "status": "open"},
            2: {"id": 2, "subject": "billing query", "author_id": 2, "status": "closed"},
            3: {"id": 3, "subject": "api rate limit", "author_id": 2, "status": "open"}}
    if tid not in rows: return jsonify({"error": "not found"}), 404
    return jsonify(rows[tid])

# --- N08 the falsification twin: a public object, readable by anyone ----------
#
# Also ID-scoped, also returns differing bodies per ID, also carries a numeric field
# ending in _id. But it is public: no session is required, so reading ID 2 as user A
# is not an authorisation failure. A probe that flags this is reporting "an endpoint
# that returns different objects for different IDs".
@app.route("/api/articles/<int:aid>")
def article(aid):
    rows = {1: {"id": 1, "title": "on minimal tools", "category_id": 7, "views": 120},
            2: {"id": 2, "title": "sqlite in production", "category_id": 9, "views": 843}}
    if aid not in rows: return jsonify({"error": "not found"}), 404
    return jsonify(rows[aid])

# --- 28. session token the client can rewrite -------------------------------
#
# Planted from a live engagement (2026-09-11). The session is base64-encoded JSON
# carrying user_id and role, with no signature. Base64 is encoding, not integrity, so
# any client can decode it, set role to "admin", and re-encode it. HttpOnly is set and
# does nothing at all against this -- it stops JavaScript reading the cookie, not an
# attacker composing the request.
#
# The role check bites on a WRITE, which is why a probe that only replays reads finds
# nothing here: GET returns the same bytes to a guest and an admin.
import base64 as _b64, json as _json, hmac as _hmac, hashlib as _hashlib

_FORGE_NOTES = []
_SIGNING_KEY = b"a-real-server-side-secret"

def _forge_session(uid, role):
    return _b64.b64encode(_json.dumps({"user_id": uid, "role": role}).encode()).decode()

@app.route("/api/guestbook-session", methods=["GET", "POST"])
def guestbook_session():
    resp = None
    if request.method == "POST":
        data = request.json or {}
        if not data.get("author") or not data.get("message"):
            return jsonify({"error": "Author and message are required."}), 400
        # VULN: the role is read straight out of a cookie the client wrote.
        role = "guest"
        raw = request.cookies.get("session", "")
        try:
            role = _json.loads(_b64.b64decode(raw + "==").decode()).get("role", "guest")
        except Exception:
            pass
        if role != "admin" and data.get("approved") is True:
            return jsonify({"error": "Unauthorized parameter: guest submissions "
                                     "cannot set approval state."}), 403
        rec = {"id": len(_FORGE_NOTES) + 1, "author": str(data["author"]),
               "message": str(data["message"]), "date": "2026-09-11",
               "approved": bool(data.get("approved"))}
        _FORGE_NOTES.append(rec)
        body = {"success": True, "note": rec,
                "message": ("Note published to the guestbook." if rec["approved"]
                            else "Pending moderation.")}
        code = 201 if rec["approved"] else 200
        resp = make_response(jsonify(body), code)
        if "session" not in request.cookies:
            resp.set_cookie("session", _forge_session(rec["id"], "guest"), httponly=True)
        return resp
    return jsonify({"notes": [r for r in _FORGE_NOTES if r["approved"]]})

# --- N09 the same guestbook with a signed session ----------------------------
#
# The falsification twin. Identical route shape, identical role check, identical
# gated field -- but the token carries an HMAC the client cannot produce. A probe
# that reports this one is detecting "a cookie that decodes to JSON", not forgery.
def _sign(payload):
    return _hmac.new(_SIGNING_KEY, payload.encode(), _hashlib.sha256).hexdigest()[:32]

def _signed_session(uid, role):
    """A real three-part token: header.payload.signature.

    Deliberately NOT `payload.signature`. The two-part shape is undecodable by a client
    that tries the JWT payload segment, which made this falsification target vacuous --
    a probe reported it clean because it could not read the token at all, not because
    the signature was checked. A three-part token decodes fine, so the ONLY thing that
    can save it is the server refusing the forged signature. That is the guard under
    test, and now it is actually exercised.
    """
    hdr = _b64.urlsafe_b64encode(
        _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = _b64.urlsafe_b64encode(
        _json.dumps({"user_id": uid, "role": role}).encode()).decode().rstrip("=")
    return hdr + "." + payload + "." + _sign(payload)

_SIGNED_NOTES = []

@app.route("/api/guestbook-signed", methods=["GET", "POST"])
def guestbook_signed():
    if request.method == "POST":
        data = request.json or {}
        if not data.get("author") or not data.get("message"):
            return jsonify({"error": "Author and message are required."}), 400
        role = "guest"
        raw = request.cookies.get("session", "")
        if raw.count(".") == 2:
            _hdr, payload, sig = raw.split(".")
            if sig and _hmac.compare_digest(sig, _sign(payload)):
                try:
                    role = _json.loads(_b64.b64decode(payload + "==").decode()).get("role", "guest")
                except Exception:
                    role = "guest"
            # a bad signature means the claims are ignored entirely -- role stays guest
        if role != "admin" and data.get("approved") is True:
            return jsonify({"error": "Unauthorized parameter: guest submissions "
                                     "cannot set approval state."}), 403
        rec = {"id": len(_SIGNED_NOTES) + 1, "author": str(data["author"]),
               "message": str(data["message"]), "date": "2026-09-11",
               "approved": bool(data.get("approved"))}
        _SIGNED_NOTES.append(rec)
        body = {"success": True, "note": rec,
                "message": ("Note published to the guestbook." if rec["approved"]
                            else "Pending moderation.")}
        code = 201 if rec["approved"] else 200
        resp = make_response(jsonify(body), code)
        if "session" not in request.cookies:
            resp.set_cookie("session", _signed_session(rec["id"], "guest"), httponly=True)
        return resp
    return jsonify({"notes": [r for r in _SIGNED_NOTES if r["approved"]]})

# --- N03 an endpoint that reflects input into a JSON response ----------------
#
# The guard under test is the probe's Content-Type check: reflected markup is only
# script if a browser parses it as markup. To exercise that guard the target has to
# actually reflect the payload -- an endpoint that echoes nothing would report clean
# whether or not the check existed, which is the vacuity this file keeps finding.
@app.route("/api/echo")
def echo_json():
    text = request.args.get("text", "")
    return jsonify({"echo": text, "length": len(text)})

@app.route("/benchmark/reset-redemption", methods=["POST"])
def reset_redemption():
    """Re-arm the single-use code without touching any other state.

    The scorecard's race oracle consumes WELCOME50 (it is single-use globally), so the
    tool's own race probe needs the code re-armed or it measures an exhausted resource
    and reports a miss that is not its fault. A full /benchmark/reset would also clear
    the session store and every later oracle depends on that.
    """
    db().execute("UPDATE redemptions SET used=0")
    db().commit()
    return jsonify({"rearmed": "WELCOME50"})

@app.route("/benchmark/reset", methods=["POST"])
def reset():
    """Restore pristine DB state so the benchmark is idempotent across runs."""
    close()
    seed()
    _sessions.clear()
    return jsonify({"reset": True})

@app.route("/")
def index():
    return ("<html><body><h1>Acme Billing</h1>"
            "<a href='/greet'>greet</a> <a href='/search'>search</a> "
            "<a href='/api/comments'>comments</a></body></html>")

# --- V24: authorisation bypass by path normalisation -----------------------------
# A guard written as a string match on the request path. It is case-sensitive, so the
# same resource spelled differently walks straight past it. This is a real and common
# bug: the rule reads correctly in review, and it does block the spelling the developer
# tested. What it blocks is a string, not a route.
@app.before_request
def _guard_admin_panel():
    # Scoped to /admin/panel ONLY. The first version of this guard matched
    # p.startswith("/admin/"), which silently disabled V07 (missing function-level authz on
    # /admin/users) — the scorecard went 23/23 -> 22/24 and the regression read as a probe
    # failure rather than what it was: the fixture protecting a route it was never meant to
    # protect. A planted vulnerability must not change any other planted vulnerability.
    if request.path == "/admin/panel":
        return jsonify({"error": "forbidden"}), 403

# Registered under every case spelling, the way a case-insensitive back end (IIS, Windows,
# most Java containers) actually behaves. The guard above is case-sensitive, so the rule
# blocks the one spelling its author tested and the back end happily serves the rest.
@app.route("/admin/panel")
@app.route("/Admin/panel")
@app.route("/ADMIN/panel")
@app.route("/admin/PANEL")
@app.route("/ADMIN/PANEL")
@app.route("/Admin/Panel")
def _admin_panel():
    return jsonify({"users": [{"id": 1, "email": "root@acme.test", "role": "admin"},
                              {"id": 2, "email": "alice@acme.test", "role": "user"}],
                    "panel": "billing administration"})


seed()
# ---- confused-deputy fixture: an upstream that needs a header, an open proxy that spends
# the credential, and a hardened twin that does not. Mirrors the live amitxd.in backend bug.
_DEP_SECRET = "bench-dep-secret"

@app.route("/api/upstream/<path:rest>")
def upstream(rest):
    if request.headers.get("X-Internal") != _DEP_SECRET:
        return jsonify({"error": "requires auth"}), 401
    if request.args.get("visibility") == "private":
        return jsonify([{"name": "r", "private": True}])
    if rest == "user":
        return jsonify({"login": "deputy"})
    # Unknown paths do not exist, authenticated or not -- keeps the probe's liveness
    # control honest for the genuinely-open proxy.
    return jsonify({"error": "not found"}), 404

def _forward(ep, with_cred):
    import urllib.request as _ur
    req = _ur.Request("http://127.0.0.1:5001/api/upstream" + ep)
    if with_cred:
        req.add_header("X-Internal", _DEP_SECRET)
    try:
        with _ur.urlopen(req, timeout=5) as r:
            return r.read(), r.code
    except _ur.HTTPError as e:
        return e.read(), e.code

@app.route("/proxy/open")
def proxy_open():
    body, code = _forward(request.args.get("endpoint", "/user"), True)
    return body, code, {"Content-Type": "application/json"}

@app.route("/proxy/safe")
def proxy_safe():
    body, code = _forward(request.args.get("endpoint", "/user"), False)
    return body, code, {"Content-Type": "application/json"}

@app.route("/proxy/stale")
def proxy_stale():
    """A lying cache: answers an authenticated-looking 200 for EVERY endpoint, including
    paths that cannot exist. The probe's liveness control must see through it and decline,
    so this is the falsification twin for the stale-cache false positive."""
    ep = request.args.get("endpoint", "/user")
    if "visibility=private" in ep:
        return jsonify([{"name": "stale", "private": True}]), 200
    return jsonify({"login": "stale"}), 200

@app.route("/api/checkout-logic", methods=["POST"])
def checkout_logic():
    # V30 VULN: discount is trusted from the client with no upper bound, so a solved
    # discount > 100 drives the total negative and the server returns it.
    d = request.json or {}
    price = int(d.get("price", 0)); qty = int(d.get("qty", 0)); discount = int(d.get("discount", 0))
    total = price * qty * (100 - discount) // 100
    return jsonify({"total": total, "currency": "USD"})


@app.route("/api/checkout-safe", methods=["POST"])
def checkout_safe():
    # N12 SAFE: the invariant is enforced server-side; an over-100% discount is rejected.
    d = request.json or {}
    try:
        price = int(d.get("price", 0)); qty = int(d.get("qty", 0)); discount = int(d.get("discount", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "bad input"}), 400
    if not (0 <= discount <= 100) or price < 0 or qty < 0:
        return jsonify({"error": "discount must be 0-100"}), 400
    total = price * qty * (100 - discount) // 100
    return jsonify({"total": total, "currency": "USD"})


@app.route("/api/clone-info")
def clone_info():
    # V31 VULN: an anonymous caller is handed a usable git-clone token in the response body.
    return jsonify({"repo": "Amitminer/hbd", "private": True,
                    "temp_clone_token": "ATPCSIMULATEDCLONETOKEN1234567"})


# V32/N14 - STATEFUL double-spend. A one-time reward credit must move the balance ONCE; the
# bug (and its control) only exist across a SEQUENCE of two identical claims, so these routes
# carry server-side state rather than returning a canned response.
_WALLET = {"balance": 100}
_WALLET_SAFE = {"balance": 100, "claimed": False}


@app.route("/api/wallet")
def wallet():
    return jsonify({"balance": _WALLET["balance"]})


@app.route("/api/claim-reward", methods=["POST"])
def claim_reward():
    # V32 VULN: no idempotency guard -- the one-time credit is granted on every call, so an
    # identical second request double-spends the reward.
    _WALLET["balance"] += 50
    return jsonify({"ok": True, "balance": _WALLET["balance"]})


@app.route("/api/wallet-safe")
def wallet_safe():
    return jsonify({"balance": _WALLET_SAFE["balance"]})


@app.route("/api/claim-once", methods=["POST"])
def claim_once():
    # N14 CONTROL: the one-time credit is guarded, so the second identical request is refused
    # (409) and the balance does not move again.
    if _WALLET_SAFE["claimed"]:
        return jsonify({"error": "already claimed"}), 409
    _WALLET_SAFE["claimed"] = True
    _WALLET_SAFE["balance"] += 50
    return jsonify({"ok": True, "balance": _WALLET_SAFE["balance"]})


# V33/N15 - CONCURRENT single-use consumption (TOCTOU), judged by the STATE delta. The vulnerable
# route separates the check from the commit with a window and holds no lock across it, so
# concurrent racers all pass the check; the control route does both inside one lock. The app
# serves threaded=True, so the burst is genuinely concurrent.
_RACE_V = {"balance": 0, "armed": True}
_RACE_S = {"balance": 0, "armed": True}
_RACE_LOCK = threading.Lock()


@app.route("/api/race-wallet")
def race_wallet():
    return jsonify({"balance": _RACE_V["balance"]})


@app.route("/api/race-redeem", methods=["POST"])
def race_redeem():
    # V33 VULN: check, then a window, then commit -- the check is NOT under the lock, so every
    # concurrent racer sees the resource armed and each one credits it.
    if _RACE_V["armed"]:
        time.sleep(0.15)
        with _RACE_LOCK:
            _RACE_V["armed"] = False
            _RACE_V["balance"] += 50
        return jsonify({"status": "credited", "amount": 50})
    return jsonify({"error": "already redeemed"}), 409


@app.route("/api/race-wallet-safe")
def race_wallet_safe():
    return jsonify({"balance": _RACE_S["balance"]})


@app.route("/api/race-redeem-safe", methods=["POST"])
def race_redeem_safe():
    # N15 CONTROL: the check and the commit are one locked critical section, so exactly one
    # concurrent racer is credited no matter how many fire.
    with _RACE_LOCK:
        if _RACE_S["armed"]:
            _RACE_S["armed"] = False
            _RACE_S["balance"] += 50
            return jsonify({"status": "credited", "amount": 50})
    return jsonify({"error": "already redeemed"}), 409


@app.route("/fp-demo")
def fp_demo():
    # Deterministic fingerprint fixture: a versioned header, a generator meta, and a versioned
    # JS library, so `ptx fingerprint` detection can be exercised without a live third party.
    resp = make_response(
        '<html><head><meta name="generator" content="DemoCMS 1.2.3">'
        '<script src="/js/jquery-3.6.0.min.js"></script>'
        '<link href="/css/bootstrap-5.3.0.min.css"></head><body>hi</body></html>')
    resp.headers["X-Powered-By"] = "PHP/8.1.2"
    return resp


@app.route("/benchmark/rearm-race", methods=["POST"])
def rearm_race():
    # Re-arm both single-use resources WITHOUT resetting their balances, so the truth burst and
    # the probe's burst each start armed and read their own delta. Mirrors reset-redemption.
    _RACE_V["armed"] = True
    _RACE_S["armed"] = True
    return jsonify({"rearmed": True})


@app.route("/api/safe-config")
def safe_config():
    # N13 SAFE: the token field holds a placeholder, not a real credential.
    return jsonify({"access_token": "your_token_here", "theme": "dark"})


if __name__ == "__main__":
    # debug/use_reloader are forced OFF rather than left to defaults. The Werkzeug
    # reloader watches every .py file in this directory, so editing scorecard.py restarted
    # the target mid-run and wiped its in-memory session store; every later authenticated
    # oracle then got 401 and was recorded as a FALSE NEGATIVE. The score fell from 71/71
    # to 46/71 with zero transport errors anywhere — a silently wrong measurement caused
    # by a text editor. A measurement instrument must not restart itself because a
    # neighbouring file changed.
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False, threaded=True)
