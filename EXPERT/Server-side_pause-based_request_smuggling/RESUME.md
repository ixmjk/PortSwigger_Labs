# RESUME — Server-side pause-based request smuggling (EXPERT)

## STATUS: ✅ SOLVED — automated solver built, tested, verified. NO OUTSTANDING WORK.

- **Instance #2** (solver target) `https://0af7008604440ca0805d3a480001004f.web-security-academy.net/`
  → solved by `solve.py` run 1: `evidence/run_*/report.json` (`solved: true`, elapsed 193.5 s,
  23 HTTP requests) + **independent curl verification** (`responses/new_instance_status_check.html`
  → `is-solved` / `Solved`).
- **Instance #1** (manual phase) `https://0a33006004e7508b87be6c9a00f200dd.web-security-academy.net/`
  → solved 2026-10-23 (verified: `responses/status_final.html`).
- Both instances were subsequently **reclaimed by PortSwigger** (504 → connection refused;
  screenshot: `screenshots/new_instance_after_reclaim.png`) — expected ephemeral-lab behavior;
  solved state was already captured as evidence.
- `solve.py` final version includes: dynamic discovery (host/endpoint/CSRF/pause), adaptive
  pause sweeps, redirect-candidate cycling, CSRF re-harvest + delete retry, request/byte
  counters, per-run `report.json`, and **fail-fast on 502/504** (lab down).

## 2026-10-24 — wrong-lab run triage + fail-fast guard added
- A **different lab's** instance (`0aa300140445b81982b5dd7f00be0007`, "Combining web cache
  poisoning") was run through this (pause-based) solver by mistake (terminal autocompleted
  the wrong `solve.py`). It swept pauses for ~5.5 min / 48 requests, then failed at CSRF
  harvest ("could not harvest CSRF from admin panel") — expected for the wrong lab, **not**
  a solver bug.
- **Fix**: fail-fast title-mismatch guard added (abort in ~0.4 s unless `--allow-mismatch`).
  Verified against that live instance: default aborts in 0.4 s; `--allow-mismatch` continues.
  Test evidence: `evidence/run_20261024_015252/`, `evidence/run_20261024_015320/`,
  `logs/solve_20261024_0153*.log`.
- That combining instance is now `is-solved` (resolved by a separate/correct run). Both labs
  remain intact under `/root/Desktop/PortSwigger_Labs/EXPERT/`.

## Re-run on a FRESH target URL
```bash
cd /root/Desktop/PortSwigger_Labs/EXPERT/Server-side_pause-based_request_smuggling
uv run python solve.py --url "https://NEW_TARGET_URL/"
```
- Happy path ≈ 195 s wall (recon ~2 s + harvest 62 s + delete 62 s + verify).
- Exit 0 only if the lab widget reports solved. Artifacts → `evidence/run_<ts>/`, `logs/solve_<ts>.log`.
- If it reports "lab infrastructure down": the instance is dead; wait and retry, or use a fresh URL.
- If a fresh instance behaves differently (unsolved after delete): check the harvest diag in the
  log (pause window / redir endpoint) and the delete response body (`Invalid CSRF token` →
  re-harvest path exists).

## Verified behavior model (this lab family)
| Fact | Value / evidence |
|---|---|
| Front-end read timeout | ≈120 s → `400 {"error":"Read timeout"}` + close (experiments/battery_F…) |
| Back-end read timeout | ≈60 s; timeout response = self-generated 302 (no X-Frame-Options) on redirect endpoints; connection kept open (experiments/resp_probe_p65 vs p30) |
| Front-end `/admin` block | per request, any Host → 403 JSON (experiments/battery_A/B/G) — smuggle bytes must stay "body" in front-end bookkeeping (nonzero CL) |
| Front-end streaming | bytes sent after back-end timeout still forwarded to back-end (experiments/b2_H1…) |
| Response pairing | back-end responses pair with client requests in order → sacrificial follow-up needed to read smuggled responses in-band (experiments/b2_H1 vs b2_H7) |
| Admin panel | `Host: localhost` required (else "only accessible to local users"); form `action=/admin/delete`, hidden `name="csrf"`, `username`; CSRF per-instance (manual: `vIGaa2…`, solver: `tD2ug…`); invalid → `400 "Invalid CSRF token"` |
| Delete success | 302 (Location `/` or `/admin/`); lab widget flips to `is-solved` |
| Infra | instances reclaimed post-solve (504 then conn-refused) — verify early, fail fast |

## Files
- `solve.py` + `pyproject.toml` + `uv.lock` (+`.venv/`) — the automated solver (stdlib only, zero deps)
- `README.md`, `REPORT.md`, `LESSONS_LEARNED.md`, `SOURCES.md`, `SOLUTION.md` (manual-phase write-up)
- `scripts/` — historical manual-phase drivers (smuggle.py, battery.py, battery2.py, exploit.py)
- `experiments/` — manual-phase probe/battery raw evidence (probe_results.json, raw_probe_*.bin, resp_probe_*.bin, battery_*.txt, b2_*.txt)
- `evidence/` — research paper + walkthrough (html/txt), manual exploit raw (exploit_*.txt), `run_<ts>/` per solver run (recon_home.html, recon_redirects.json, harvest_*.txt, delete_raw.txt, verify_final.html, report.json)
- `requests/` — exact bytes on the wire (manual phase, attack1/attack2)
- `responses/` — home page, status checks (before/after), new-instance status check, reclaim polls
- `screenshots/` — browser capture of reclaimed instance state
- `logs/` — all tee'd run logs (probe1, battery1, battery2, exploit1, solve_new_instance, solve_new_instance_run2, solve_old_instance_rerun)
