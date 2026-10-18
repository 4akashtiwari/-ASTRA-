# ASTRA web console

A browser front-end for the `ptx` CLI. It does not re-implement anything: every active
command is a subprocess call to `python3 ptx/ptx.py`, so the CLI's scope guard, rate
ceiling, evidence discipline and exit codes apply exactly as they do on the command line.
A web UI is the last place a scope guard should be bypassable, and the surest way to keep
it is never to route around it.

## Run

```
pip install flask          # the sandbox bench target needs it; the backend is stdlib-only
python3 web/app.py         # serves http://0.0.0.0:8080
```

On startup it creates `web/demo-engagement/` scoped to a local sandbox benchmark target
(`bench/target_v2.py`, which it also launches) and points the console at it.

## Design

- **Backend: Python stdlib only** (`http.server`). No web framework, so nothing to install
  for the backend to boot — in an environment that wipes packages between steps, a backend
  that needs an install is a backend that randomly dies.
- **Target is fixed to the owned sandbox bench.** Active scanning is not user-targetable;
  out-of-scope hosts are rejected by the CLI and the rejection is surfaced, not hidden.
- **Panels:** probe runner · variant sweep (incl. `--from-finding`) · retest · fingerprint +
  CVE · surface map · coverage · live findings list (click a finding to sweep its class).

## Endpoints

`GET /api/{health,scope,findings,coverage,meta}` ·
`POST /api/{probe,variants,retest,fingerprint,discover}` — each maps to one `ptx` command
with a fixed shape; user input is passed as argv elements (never a shell string).
