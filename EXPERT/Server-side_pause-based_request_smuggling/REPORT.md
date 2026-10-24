# REPORT — Server-side pause-based request smuggling (EXPERT)

## Objective
Solve the PortSwigger lab by identifying a pause-based CL.0 desync vector,
smuggling a request to the back-end admin panel (`/admin`), and deleting the
user `carlos`. Rebuild the manual solution into a reusable automated solver
(`uv run python solve.py --url ...`) and verify on a fresh instance.

## Instances
| Instance | URL | Result |
|---|---|---|
| #1 (manual) | `https://0a33006004e7508b87be6c9a00f200dd.web-security-academy.net/` | **SOLVED** (2026-10-23, session 1); later reclaimed by PortSwigger (504) |
| #2 (solver) | `https://0af7008604440ca0805d3a480001004f.web-security-academy.net/` | **SOLVED** by `solve.py` (2026-10-24), then reclaimed (504) |

## Verified completion (instance #2)
- Solver run 1 (`evidence/run_<ts>/report.json`, `logs/solve_new_instance.log`):
  - title matched: "Server-side pause-based request smuggling"
  - redirect endpoints discovered (19, incl. `/my-account`, `/resources`, …)
  - CSRF harvested live: `tD2ug…` (pause=62 s, redir=`/my-account`)
  - DELETE attempt → `[302 (timeout redirect), 302 (Location: /)]`, delete confirmed
  - VERIFY: `solved=true`, widget `Solved`
  - **elapsed 193.5 s, 23 HTTP requests, 2803 bytes** (run-1 bookkeeping; later
    fixed to also count harvest-phase requests)
- **Independent verification** (separate `curl`, not the solver):
  `responses/new_instance_status_check.html` → `widgetcontainer-lab-status is-solved`,
  `<p>Solved</p>`.
- Instance #1 (manual phase) was likewise verified: `responses/status_final.html`
  → `is-solved` / `Solved` (CSRF `vIGaa2…`,
  delete → 302, lab flipped to Solved).

Note: after solving, PortSwigger reclaims lab instances (both now return
`504 Gateway Timeout`). This is expected infrastructure behavior, not a
failure of the solution; the solver now fail-fasts on it in <1 s.

## Reusability
- `solve.py` hardcodes no URLs, hostnames, cookies, CSRF tokens, or session IDs.
  Host ← `--url`; redirect endpoint, CSRF token, and working pause discovered at
  runtime; only lab-definition constants remain (`/admin`, `/admin/delete/`,
  `carlos`, status-widget markers).
- Tested successfully on a fresh instance (run 1 above).
- Re-run on the reclaimed instance #1 correctly detected "lab infrastructure
  down" and aborted with a clean report (see
  `logs/solve_old_instance_rerun.log`) — expected, since the instance was gone.
- Re-running on instance #2 after solve fails fast on 504 (instance already
  reclaimed) — `logs/solve_new_instance_run2.log`.

## Command
```bash
uv run python solve.py --url "https://TARGET_URL/"
```
(run from this directory; uv 0.13.5, CPython 3.14.8, zero dependencies)

## Timeline (investigation)
1. Manual phase (session 1): endpoint probing → parallel timeout probes →
   behavior batteries (A–G, H1–H7) → mechanism model → manual exploit
   (harvest + delete) → verified Solved.
2. Solver phase (session 2): dir reorg to `PortSwigger_Labs/`, solver written,
   tested on fresh instance → Solved in 193.5 s → independent curl verification
   → stats bookkeeping + infra fail-fast fixes → docs.

## Artifacts
Everything under this directory: `evidence/` (incl. `run_<ts>/report.json` per
solver run), `logs/`, `responses/`, `requests/`, `experiments/`, `scripts/`,
plus `README.md`, `RESUME.md`, `LESSONS_LEARNED.md`, `SOURCES.md`, `SOLUTION.md`
(manual-phase write-up).
