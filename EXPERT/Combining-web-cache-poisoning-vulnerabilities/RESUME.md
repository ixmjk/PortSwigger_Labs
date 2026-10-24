# RESUME — Combining web cache poisoning vulnerabilities (EXPERT)

## STATUS: ✅ COMPLETE / SOLVED & VERIFIED (multiple fresh instances)
- Instance `0a9a0059033608fe80ed030b00a40091`: reached **`is-solved`**; exploit chain
  reproduced in a real browser (`alert(document.cookie)` × 20).
- Fresh instance `0a3900d404cee1638046629e005a0021` (2026-10-24): **SOLVED** by the
  corrected solver in 110.7 s / 268 requests (`poison_verified=True`, `lab_confirmed=True`);
  both the exploit server and a cache-busted lab fetch report `is-solved`.
`solve.py` runs end-to-end on fresh instances. All artifacts saved.

**Nothing left to do** on these instances. If an instance has since been reclaimed
(504 / connection refused), it is still solved & documented here; to redo on a fresh
instance, use the steps below.

## 2026-10-24 — detection-timing + loop-resilience fixes
Two bugs found while verifying on a fresh instance and fixed in `solve.py`:
1. **Detection lag** — solved-detection was gated on the lab's `/?localized=1`, a 30s-cached
   poisoned page, so the solver kept logging "still not solved" up to ~30s after the visitor
   actually solved the lab. Fix: gate on the exploit server's status widget (separate,
   non-cached host, flips promptly); confirm on the lab with a cache-busted fetch
   (`/?cb=<ms>`) reported as `lab_confirmed`. Verified: fresh run SOLVED with
   `lab_confirmed=True` at detection. (log: `logs/solve_fresh_verify2_*.log`)
2. **Transient-error crash** — a single `ReadTimeout` (read timeout=20) killed the whole run
   ~48s in. Fix: wrap every poison-loop sub-step + the final confirmation in
   `try/except requests.exceptions.RequestException` (log `[warn]`, continue; final check is
   non-destructive). Verified: `scripts/test_resilience.py` — 53 simulated ReadTimeouts, no
   crash. (crash evidence: `logs/solve_fresh_verify_*.log`)
Backup of the pre-fix solver: `solve.py.bak_20261024_020320`.

## Verified facts (empirically, on the live lab)
| Fact | Evidence |
|---|---|
| Cache key = request-line path + query only (headers unkeyed) | 3× identical `GET /` → miss,hit,hit |
| `GET /?localized=1` + `X-Forwarded-Host: H` → page `data.host = H` | T3/T4 |
| `GET /` + `X-Original-URL: /setlang\es` (backslash) → **302 → /setlang/es**, `cache-control: max-age=30`, `x-cache: miss` | T1/T2 |
| Forward-slash `/setlang/es` → `cache-control: private` + `Set-Cookie` (NOT cacheable) | recon |
| `translations.js`: non-English `lang` → `el.innerHTML = dict[k]` (DOM XSS sink); English never runs it | read of JS |
| Exploit server: POST form `responseFile/responseHead/responseBody/formAction=STORE`; serves at `responseFile` path; needs `Access-Control-Allow-Origin: *` for cross-origin `fetch().json()` | form + config test |
| Solved-state: lab header widget `is-solved` + `<p>Solved</p>`; "Go to exploit server" link removed when solved | solved HTML |

## Exact resume steps (fresh lab URL)
1. `cd "/root/Desktop/PortSwigger_Labs/EXPERT/Combining-web-cache-poisoning-vulnerabilities"`
2. `uv sync`
3. `uv run python solve.py --url "https://<FRESH_ID>.web-security-academy.net" --timeout 240`
   (fresh instance auto-discovers the exploit server; no `--exploit` needed).
4. Watch for `*** LAB SOLVED ***` + summary JSON `{"solved": true, ...}`.
5. Confirm: `curl -s <lab>/?localized=1 | grep -oE 'widgetcontainer-lab-status[^>]*|<p>(Solved|Not solved)</p>'`

### Manual / manual-debug notes
- To poison `/` you need a **cache MISS**: wait ~30s for TTL expiry (the lab visitor
  keeps `/` repopulated clean). Keep the poison loop running continuously.
- Use `allow_redirects=False` for the X-Original-URL poison (requests otherwise
  re-sends the header on follow-ups and loops the 302 → TooManyRedirects).
- To capture the alert in a browser: poison both caches, then a fresh tab `goto /`
  with a `Page.addScriptToEvaluateOnNewDocument` hook that overrides `window.alert`.
- Malicious JSON payload (value must match an element's innerHTML key, e.g.
  "View details" which appears in all home-page product tiles):
  `"View details": "<img src=x onerror=alert(document.cookie)>"`.

## Files
- `solve.py`, `pyproject.toml`, `uv.lock` — the solver + uv project.
- `evidence/browser_alert_capture.json` — definitive XSS-in-browser capture.
- `evidence/solved_state_*.html` — authoritative solved widget.
- `evidence/writeup_*.html` — reference walkthroughs (pasindu, siunam321).
- `requests/*.request` — exact poison + config requests.
- `logs/solve_repro_FINAL.log` — final clean solver run (SOLVED, poison_verified=True).
