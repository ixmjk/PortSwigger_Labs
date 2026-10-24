# Server-side pause-based request smuggling (EXPERT) — automated solver

Fully automated, reusable solver for the PortSwigger Web Security Academy lab
**"Server-side pause-based request smuggling"** (EXPERT difficulty).

## Run

```bash
uv run python solve.py --url "https://TARGET_URL/"
```

Optional: `--outdir DIR` (default: current directory) — where per-run evidence
and logs are stored (`evidence/run_<ts>/`, `logs/solve_<ts>.log`).

**Exit code 0 iff the lab's status widget reports solved**
(`widgetcontainer-lab-status is-solved`) — the solver verifies genuine lab
completion, not just an HTTP response.

## Requirements

- `uv` (https://astral.sh/uv) — `pyproject.toml` + `uv.lock` included
- Python ≥ 3.10, **stdlib only** (no third-party dependencies)
- Network access to the lab host

## How it works

Pause-based CL.0 server-side desync:

1. **Recon** (parallel): `GET /` (title sanity check + infra-down detection) and
   probe 20 candidate paths for *server-level redirect endpoints*
   (`GET <p> → 3xx, Location: <p>/`).
2. **Harvest**: on one raw TLS/HTTP-1.1 socket send
   `POST <redir>` headers with `Content-Length = L`, **pause ~62 s**
   (back-end read timeout ≈60 s; front-end ≈120 s), then send `L` bytes =
   `GET /admin/` with `Host: localhost`, then a **sacrificial `GET /`**.
   The timed-out back-end parses the smuggled bytes as a new request; the
   front-end pairs back-end responses with client requests in order, so the
   admin panel HTML (containing the per-instance CSRF token) arrives as the
   sacrificial request's response.
3. **Delete**: same pattern with
   `POST /admin/delete/` (`Host: localhost`, `csrf=<harvested>&username=carlos`).
4. **Verify**: re-fetch `/` and require the solved widget.

Adaptive fallbacks: pause sweeps `[62] → [45,55,70,80,95] → [30,38,50,60,100,110,115]`
(parallel within a sweep), redirect candidates cycled, back-end host
`localhost → 127.0.0.1`, one CSRF re-harvest + delete retry, and **fail-fast
on 502/504** (lab infrastructure down / instance reclaimed).

Nothing instance-specific is hardcoded: host comes from `--url`; redirect
endpoint, CSRF token, and working pause are discovered at runtime.

## Layout

| Path | Contents |
|---|---|
| `solve.py` | the solver |
| `pyproject.toml`, `uv.lock`, `.venv/` | uv project (zero deps) |
| `scripts/` | historical raw-socket drivers (probe/battery/exploit) from the manual phase |
| `experiments/` | historical probe & battery raw evidence (manual phase) |
| `evidence/` | research paper + walkthrough (text), manual-phase exploit evidence, `run_<ts>/` per solver run (recon, raw sends, verify page, `report.json`) |
| `requests/` | exact bytes on the wire (manual phase) |
| `responses/` | saved lab pages, status checks, polls |
| `screenshots/` | browser screenshots of lab state |
| `logs/` | tee'd run logs |
| `README.md` / `REPORT.md` / `RESUME.md` / `LESSONS_LEARNED.md` / `SOURCES.md` | docs |
