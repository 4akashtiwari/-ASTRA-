#!/usr/bin/env python3
"""
SAFE TARGET — deliberately NOT vulnerable.

Every route here mirrors a vulnerability in the benchmark target, implemented correctly.
The test suite runs the same probes against both targets and asserts:
  * vulnerable target -> VULNERABLE
  * safe target       -> not vulnerable

This is what catches false positives, which the Stanford/CMU/Gray Swan study found to be
the dominant AI failure mode. A probe suite that only tests against a vulnerable target
can never detect a probe that reports everything as vulnerable.
"""
import hashlib, hmac, json, os, re, sqlite3, threading, time, urllib.request
from flask import Flask, request, jsonify, g, make_response

app = Flask(__name__)
DB = "/tmp/safe_target.db"
JWT_SECRET = b"a-real-secret-that-is-never-leaked"
BASE_DIR = os.environ.get("PTX_SAFE_FILES") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "files")
PORT = int(os.environ.get("PTX_SAFE_PORT", "5002"))
_lock = threading.Lock()          # the atomicity the vulnerable target lacks


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close(exc=None):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def seed():
    if os.path.exists(DB):
        os.remove(DB)
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, is_admin INT, credits INT);
    CREATE TABLE invoices(id INTEGER PRIMARY KEY, user_id INT, customer TEXT);
    CREATE TABLE comments(id INTEGER PRIMARY KEY, user_id INT, body TEXT);
    CREATE TABLE redemptions(code TEXT PRIMARY KEY, used INT DEFAULT 0);
    CREATE TABLE products(sku TEXT PRIMARY KEY, name TEXT, price REAL);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, sku TEXT, qty INT,
                        unit_price REAL, total REAL, state TEXT, refunded REAL DEFAULT 0);
    CREATE TABLE order_steps(order_id INT PRIMARY KEY, validated INT DEFAULT 0,
                             paid INT DEFAULT 0);
    INSERT INTO products VALUES ('WIDGET','Blue widget',49.00),('GADGET','Red gadget',199.00);
    INSERT INTO orders VALUES (9001,1,'WIDGET',1,49.00,49.00,'paid',0);
    INSERT INTO users VALUES (1,'alice',0,100),(2,'bob',0,100),(3,'carol',1,100);
    INSERT INTO invoices VALUES (1001,1,'Alice Anderson'),(1003,2,'Bob Bhatti'),(1005,3,'Carol Chawla');
    INSERT INTO redemptions VALUES ('WELCOME50',0);
    """)
    c.commit(); c.close()


_sessions = {}
_counter = [5000]                     # NOT sequential-looking, and opaque
_counter_lock = threading.Lock()


def make_session(uid):
    with _counter_lock:
        _counter[0] += 1
        raw = f"{_counter[0]}:{os.urandom(16).hex()}"
    tok = hashlib.sha256(raw.encode()).hexdigest()
    _sessions[tok] = {"uid": uid}
    return tok


def get_session():
    tok = request.cookies.get("sid")
    return (_sessions.get(tok), tok) if tok in _sessions else (None, None)


@app.after_request
def harden(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    # no Server / X-Powered-By disclosure
    resp.headers.pop("Server", None)
    return resp


# --- SAFE: ownership predicate inside the query itself ------------------------
@app.route("/api/invoices/<int:iid>")
def invoice(iid):
    sess, _ = get_session()
    if not sess:
        return jsonify({"error": "auth required"}), 401
    row = db().execute(
        "SELECT * FROM invoices WHERE id=? AND user_id=?", (iid, sess["uid"])).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404   # 404, not 403: no existence leak
    return jsonify(dict(row))


# --- SAFE: parameterized query ------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db().execute(
        "SELECT id, customer, 0 AS amount FROM invoices WHERE customer LIKE ?",
        (f"%{q}%",)).fetchall()
    return jsonify({"results": [dict(r) for r in rows], "count": len(rows)})


# --- SAFE: output-encoded ----------------------------------------------------
def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


@app.route("/greet")
def greet():
    return f"<html><body><h1>Hello {esc(request.args.get('name', 'stranger'))}!</h1></body></html>"


@app.route("/api/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        sess, _ = get_session()
        if not sess:
            return jsonify({"error": "auth required"}), 401
        db().execute("INSERT INTO comments(user_id, body) VALUES(?,?)",
                     (sess["uid"], request.json.get("body", "")))
        db().commit()
        return jsonify({"ok": True})
    rows = db().execute("SELECT * FROM comments").fetchall()
    return "<html><body>" + "".join(
        f"<div>{esc(r['body'])}</div>" for r in rows) + "</body></html>"


# --- SAFE: argument vector, no shell ------------------------------------------
@app.route("/api/ping")
def ping():
    host = request.args.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", host):
        return jsonify({"error": "invalid host"}), 400
    import subprocess
    try:
        out = subprocess.run(["ping", "-c", "1", host], capture_output=True,
                             text=True, timeout=5, shell=False)
        return jsonify({"stdout": out.stdout, "rc": out.returncode})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- SAFE: no secrets served --------------------------------------------------
@app.route("/.env")
@app.route("/package-lock.json")
@app.route("/.git/config")
def denied():
    return jsonify({"error": "not found"}), 404


# --- SAFE: function-level authorization ---------------------------------------
@app.route("/admin/users")
def admin_users():
    sess, _ = get_session()
    if not sess:
        return jsonify({"error": "auth required"}), 401
    me = db().execute("SELECT is_admin FROM users WHERE id=?", (sess["uid"],)).fetchone()
    if not me or not me["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"users": [dict(r) for r in db().execute("SELECT * FROM users")]})


# --- SAFE: atomic conditional update ------------------------------------------
@app.route("/api/redeem", methods=["POST"])
def redeem():
    sess, _ = get_session()
    if not sess:
        return jsonify({"error": "auth required"}), 401
    code = request.json.get("code", "")
    with _lock:
        cur = db().execute(
            "UPDATE redemptions SET used=1 WHERE code=? AND used=0", (code,))
        db().commit()
        if cur.rowcount == 0:
            return jsonify({"error": "already redeemed"}), 409
    return jsonify({"status": "credited", "amount": 50})


# --- SAFE: outbound allowlist by resolved IP ----------------------------------
@app.route("/api/fetch")
def fetch():
    import ipaddress, socket
    url = request.args.get("url", "")
    try:
        host = urllib.request.urlparse(url).hostname
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return jsonify({"status": "blocked", "reason": "non-public address"}), 403
    except Exception as e:
        return jsonify({"status": "blocked", "reason": str(e)}), 400
    return jsonify({"status": "blocked", "reason": "host not on allowlist"}), 403


# --- SAFE: canonicalised and confined -----------------------------------------
@app.route("/download")
def download():
    name = request.args.get("file", "")
    root = os.path.realpath(BASE_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if not path.startswith(root + os.sep):
        return jsonify({"error": "outside permitted directory"}), 403
    try:
        with open(path) as f:
            return make_response(f.read(), 200, {"Content-Type": "text/plain"})
    except Exception:
        return jsonify({"error": "not found"}), 404


# --- SAFE: algorithm pinned server-side ---------------------------------------
def _b64d(s):
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@app.route("/api/me")
def me():
    tok = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not tok:
        return jsonify({"error": "no token"}), 401
    try:
        h, p, sig = tok.split(".")
        header = json.loads(_b64d(h))
        if header.get("alg") != "HS256":          # pinned; alg:none rejected
            return jsonify({"error": "algorithm not permitted"}), 401
        expect = hmac.new(JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
        import base64
        if not hmac.compare_digest(expect, _b64d(sig)):
            return jsonify({"error": "bad signature"}), 401
        return jsonify({"claims": json.loads(_b64d(p)), "granted": True})
    except Exception:
        return jsonify({"error": "invalid token"}), 401


# --- SAFE: destination allowlist ------------------------------------------------
ALLOWED_REDIRECTS = {"/", "/login", "/help"}


@app.route("/redirect")
def redirect_ep():
    target = request.args.get("next", "/")
    if target not in ALLOWED_REDIRECTS:
        return jsonify({"error": "destination not permitted"}), 400
    resp = make_response("", 302)
    resp.headers["Location"] = target
    return resp


# --- SAFE: explicit allowlist binding ------------------------------------------
ASSIGNABLE = ("bio",)


@app.route("/api/profile", methods=["POST"])
def profile():
    sess, _ = get_session()
    if not sess:
        return jsonify({"error": "auth required"}), 401
    data = request.json or {}
    applied = {k: v for k, v in data.items() if k in ASSIGNABLE}
    for k, v in applied.items():
        db().execute(f"UPDATE users SET {k}=? WHERE id=?", (v, sess["uid"]))
    db().commit()
    return jsonify({"ok": True, "changed": list(applied),
                    "ignored": [k for k in data if k not in ASSIGNABLE]})


# --- SAFE: no method-override header honoured ----------------------------------
@app.route("/api/account/delete", methods=["GET", "POST", "DELETE"])
def account_delete():
    sess, _ = get_session()
    if not sess:
        return jsonify({"error": "auth required"}), 401
    if request.method != "DELETE":
        return jsonify({"error": "use DELETE"}), 405
    return jsonify({"deleted": True, "id": sess["uid"]})


# --- SAFE: user input is data, never a template --------------------------------
@app.route("/api/render", methods=["POST"])
def render():
    tmpl = (request.json or {}).get("template", "")
    ctx = {"user": "alice", "credits": 100}
    known = re.findall(r"\{(\w+)\}", tmpl)
    if any(k not in ctx for k in known):
        return jsonify({"error": "unknown placeholder"}), 400
    for k, v in ctx.items():
        tmpl = tmpl.replace("{" + k + "}", str(v))
    return jsonify({"rendered": tmpl})


@app.route("/login", methods=["POST"])
def login():
    u = (request.json or {}).get("username")
    row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if not row:
        return jsonify({"error": "invalid credentials"}), 401   # same status either way
    tok = make_session(row["id"])
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie("sid", tok, httponly=True, samesite="Lax", secure=False)
    return resp


ALLOWED_ORIGIN = "http://127.0.0.1"


@app.route("/api/email/change", methods=["POST"])
def email_change():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    # Reject any request whose Origin is not our own. This is the control the CSRF probe
    # provokes: if it is present, the cross-site request never reaches the state change.
    origin = request.headers.get("Origin", "")
    if origin and not origin.startswith(ALLOWED_ORIGIN):
        return jsonify({"error": "cross-origin request rejected"}), 403
    d = request.json or {}
    new = d.get("email", "")
    if not new: return jsonify({"error": "email required"}), 400
    db().execute("UPDATE users SET email=? WHERE id=?", (new, sess["uid"]))
    db().commit()
    return jsonify({"ok": True, "email": new})


@app.route("/api/email/current", methods=["GET"])
def email_current():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    row = db().execute("SELECT email FROM users WHERE id=?", (sess["uid"],)).fetchone()
    return jsonify({"email": row["email"]})


def _next_oid():
    """Order ids from the same locked counter the rest of this target uses."""
    with _counter_lock:
        _counter[0] += 1
        return _counter[0]


# --- hardened business logic -------------------------------------------------
# Each mirrors a vulnerable endpoint in the benchmark target and implements the control
# the probe is looking for. If any probe reports VULNERABLE against these, the probe has
# a false positive — which for business logic is the more dangerous error, because a
# tester who has to chase invented logic flaws stops believing the real ones.

@app.route("/api/cart", methods=["POST"])
def cart():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    sku = d.get("sku", "")
    row = db().execute("SELECT price FROM products WHERE sku=?", (sku,)).fetchone()
    if not row: return jsonify({"error": "no such product"}), 404
    qty = d.get("qty", 1)
    # Quantity must be a positive integer. Rejected at the boundary, not clamped, because
    # clamping silently turns a bad request into a different order than the one asked for.
    if not isinstance(qty, int) or isinstance(qty, bool) or qty < 1:
        return jsonify({"error": "quantity must be a positive integer"}), 422
    total = row["price"] * qty
    db().execute("UPDATE users SET credits = credits - ? WHERE id=?", (total, sess["uid"]))
    db().commit()
    return jsonify({"sku": sku, "qty": qty, "total": total,
                    "credits": db().execute("SELECT credits FROM users WHERE id=?",
                                            (sess["uid"],)).fetchone()["credits"]})


@app.route("/api/checkout", methods=["POST"])
def checkout():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    sku = d.get("sku", "")
    row = db().execute("SELECT price FROM products WHERE sku=?", (sku,)).fetchone()
    if not row: return jsonify({"error": "no such product"}), 404
    qty = d.get("qty", 1)
    if not isinstance(qty, int) or isinstance(qty, bool) or qty < 1:
        return jsonify({"error": "quantity must be a positive integer"}), 422
    # The price comes from the catalog. Any client-supplied price is ignored, and the
    # response reports both so the caller can see the substitution did not take effect.
    unit = row["price"]
    total = unit * qty
    oid = _next_oid()
    db().execute("INSERT INTO orders VALUES (?,?,?,?,?,?,'paid',0)",
                 (oid, sess["uid"], sku, qty, unit, total))
    db().execute("UPDATE users SET credits = credits - ? WHERE id=?", (total, sess["uid"]))
    db().commit()
    return jsonify({"order": oid, "sku": sku, "unit_price": unit, "total": total,
                    "catalog_price": unit,
                    "client_price_ignored": d.get("unit_price")})


@app.route("/api/refund", methods=["POST"])
def refund():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    oid = d.get("order_id")
    # The amount is derived from the stored order, never taken from the request.
    row = db().execute(
        "SELECT user_id, total, refunded, state FROM orders WHERE id=?", (oid,)).fetchone()
    if not row:
        return jsonify({"error": "no such order"}), 404
    if row["user_id"] != sess["uid"]:
        # 404 not 403, so the existence of other users' orders is not disclosed either.
        return jsonify({"error": "no such order"}), 404
    if row["state"] != "paid":
        return jsonify({"error": "order is not refundable"}), 409
    remaining = row["total"] - row["refunded"]
    if remaining <= 0:
        return jsonify({"error": "order already fully refunded"}), 409
    db().execute("UPDATE orders SET refunded = total WHERE id=?", (oid,))
    db().execute("UPDATE users SET credits = credits + ? WHERE id=?",
                 (remaining, sess["uid"]))
    db().commit()
    return jsonify({"refunded": remaining, "order": oid,
                    "credits": db().execute("SELECT credits FROM users WHERE id=?",
                                            (sess["uid"],)).fetchone()["credits"]})


@app.route("/api/order/validate", methods=["POST"])
def order_validate():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    oid = _next_oid()
    db().execute("INSERT INTO order_steps VALUES (?,1,0)", (oid,))
    db().commit()
    return jsonify({"order": oid, "validated": True})


@app.route("/api/order/confirm", methods=["POST"])
def order_confirm():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    d = request.json or {}
    oid = d.get("order")
    # The gate is server-side state, so a client assertion cannot satisfy it.
    row = db().execute("SELECT validated, paid FROM order_steps WHERE order_id=?",
                       (oid,)).fetchone()
    if not row or not row["validated"]:
        return jsonify({"error": "validation step not completed"}), 409
    db().execute("INSERT INTO orders VALUES (?,?,?,?,?,?,'confirmed',0)",
                 (oid, sess["uid"], d.get("sku", "WIDGET"), 1, 0.0, 0.0))
    db().commit()
    return jsonify({"order": oid, "state": "confirmed"})


@app.route("/api/credits", methods=["GET"])
def credits():
    sess, _ = get_session()
    if not sess: return jsonify({"error": "auth required"}), 401
    return jsonify({"credits": db().execute(
        "SELECT credits FROM users WHERE id=?", (sess["uid"],)).fetchone()["credits"]})


@app.route("/benchmark/reset", methods=["POST"])
def reset():
    close(); seed(); _sessions.clear()
    return jsonify({"reset": True})


@app.route("/")
def index():
    return "<html><body><h1>Acme Billing (hardened)</h1></body></html>"


class SuppressServer:
    """Flask's after_request cannot delete Werkzeug's own Server header — the server adds
    it after the response is built. A WSGI wrapper can, which is what a hardened
    deployment actually does via its reverse proxy."""

    def __init__(self, wsgi):
        self.wsgi = wsgi

    def __call__(self, environ, start_response):
        def sr(status, headers, exc_info=None):
            headers = [(k, v) for k, v in headers if k.lower() != "server"]
            headers.append(("Server", "redacted"))
            return start_response(status, headers, exc_info)
        return self.wsgi(environ, sr)


seed()
if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple("127.0.0.1", PORT, SuppressServer(app), threaded=True, use_reloader=False)
