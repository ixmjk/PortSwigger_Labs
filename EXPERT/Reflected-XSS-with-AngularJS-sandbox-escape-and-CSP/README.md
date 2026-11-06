# README — Reflected XSS with AngularJS sandbox escape and CSP

Automated solver for the PortSwigger Web Security Academy **EXPERT** lab
"Reflected XSS with AngularJS sandbox escape and CSP".

## What the lab teaches

* Reflected HTML injection inside an AngularJS application is client-side
  template injection: the injected markup is compiled by Angular, not merely
  parsed by the browser.
* A strict CSP (`script-src 'self'`, no `unsafe-inline`/`unsafe-eval`) does not
  stop Angular expression evaluation, because the expression is evaluated by
  Angular's own interpreter rather than by an inline script.
* The AngularJS ≤ 1.5 sandbox is escapable through filter arguments:
  `orderBy` evaluates its predicate per element of `$event.composedPath()`, and
  the last element is `window`, so `alert` can be called in window scope
  without an explicit `window` reference.

## Quick start

```bash
uv sync
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

Options: `--wait SECONDS` (default 300, victim queue), `--timeout SECONDS`
(default 25), `--verbose` (log every request), `--skip-access-log`.

Exit codes: `0` verified solved, `1` exploit sent but lab not solved, `2`
usage/environment, `3` lab unreachable or expired.

## How the solver works

1. `identify()` — fetches `/`, checks the `<title>` against the expected lab
   name, reads the CSP header, discovers the AngularJS bundle **and version**
   from the page, verifies `<body ng-app>`, and reads the exploit-server URL
   from `#exploit-link`.
2. `baseline()` — records the authoritative `widgetcontainer-lab-status`
   state and saves the page under `evidence/`.
3. `control()` — sends the payload through `?search=`, asserts the payload is
   reflected verbatim in the `<h1>`, and reports the effective `script-src`
   (no `unsafe-inline`/`unsafe-eval` ⇒ inline script is blocked, which is what
   makes the Angular path the bypass).
4. `discover_exploit_form()` — fetches the exploit server root, reads the
   form `action` and field names, so nothing about that server is hardcoded.
5. `store()` — POSTs the redirector `<script>location='<lab>/?search=<enc>#x'</script>`
   and fetches `/exploit` back to confirm the body was stored as written.
6. `deliver()` — POSTs `formAction=DELIVER_TO_VICTIM`.
7. `wait_solved()` — polls `/` until the widget reports `is-solved` /
   `<p>Solved</p>`; saves the solved page.
8. `access_log()` — after the flip, fetches the exploit-server access log
   (with the same body, because `ACCESS_LOG` re-stores it) and keeps the lines
   mentioning the victim, for proof of delivery.

All instance-specific values (host, exploit-server host, form action, field
names, AngularJS version, CSP) are discovered at runtime; the payload is the
only constant, and it is the lab's own vector.

## Files

| Path | Purpose |
|---|---|
| `solve.py` | The solver (single file, `httpx`). |
| `SOLUTION.md` | Concise manual + automated reproduction. |
| `REPORT.md` | Case study: recon, mechanism, verification, timings. |
| `RESUME.md` | Checkpoint and continuation notes. |
| `LESSONS_LEARNED.md` | Generalisable lessons. |
| `SOURCES.md` | Sources consulted. |
| `evidence/`, `logs/` | Local run artefacts (git-ignored). |
