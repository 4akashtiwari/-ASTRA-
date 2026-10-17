"""Named identities for an engagement, so a probe can act as a specific user.

Access-control testing is comparative by nature. "Can this user read that object" is
only a question when there are two users and you can act as each of them. Every probe
that needed a session took it as an inline `--cookie`, which meant the credential went
into shell history, had to be retyped for every command, and could not express the one
thing the test actually needs: *do this as A, then check what B can see*.

Cookies are credentials. They are stored 0600 inside the engagement directory and are
never printed in full -- a report or a log that echoes a live session cookie has just
turned a finding into an incident.
"""

import json
import os
import stat
import time

FILENAME = "identities.json"


def _p(engagement):
    return os.path.join(engagement, FILENAME)


def _load(engagement):
    try:
        with open(_p(engagement), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"identities": {}}


def _save(engagement, data):
    p = _p(engagement)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    # Credentials on disk. 0600 before the rename, not after, so there is no window
    # where the file exists world-readable.
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp, p)


def mask(cookie):
    """A cookie rendered for logs: recognisable, not usable."""
    if not cookie:
        return "(none)"
    parts = []
    for chunk in str(cookie).split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            parts.append("%s=%s" % (k.strip(), _mask_value(v)))
        else:
            parts.append(_mask_value(chunk))
    return "; ".join(parts)


def _mask_value(v):
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


def store(engagement, name, cookie, role="", note=""):
    """Record a session under a name. Re-storing replaces the cookie, not the history."""
    data = _load(engagement)
    ids = data.setdefault("identities", {})
    prev = ids.get(name)
    ids[name] = {
        "name": name,
        "cookie": cookie,
        "role": role or (prev or {}).get("role", ""),
        "note": note or (prev or {}).get("note", ""),
        "stored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "replaced_count": (prev or {}).get("replaced_count", 0) + (1 if prev else 0),
    }
    _save(engagement, data)
    return ids[name]


def get(engagement, name):
    """The raw cookie, for the code that has to send it. Never for display."""
    return _load(engagement)["identities"].get(name, {}).get("cookie")


def describe(engagement, name):
    """Everything safe to show: the name, the role, and a masked cookie."""
    rec = _load(engagement)["identities"].get(name)
    if not rec:
        return None
    out = dict(rec)
    out["cookie"] = mask(rec.get("cookie"))
    return out


def all_names(engagement):
    return sorted(_load(engagement)["identities"])


def remove(engagement, name):
    data = _load(engagement)
    existed = data["identities"].pop(name, None) is not None
    if existed:
        _save(engagement, data)
    return existed


def resolve(args, engagement):
    """Turn `--as NAME` into a cookie, with an error that names the available identities.

    Returns (cookie, error). A missing identity is a hard error rather than an anonymous
    request: silently dropping the session turns "test this as the admin" into "test this
    logged out", which reads as a clean result.
    """
    name = getattr(args, "as_identity", None)
    if not name:
        return getattr(args, "cookie", None), None
    cookie = get(engagement, name)
    if cookie is None:
        known = all_names(engagement)
        return None, ("no identity named %r%s" % (
            name, " (stored: %s)" % ", ".join(known) if known else
            " — store one with `ptx session login`"))
    # --cookie still wins if both were given, but that is a contradiction worth flagging
    # rather than resolving silently.
    if getattr(args, "cookie", None) and getattr(args, "cookie", None) != cookie:
        return None, ("both --as %s and --cookie were given and they disagree; "
                      "pass one or the other" % name)
    return cookie, None
