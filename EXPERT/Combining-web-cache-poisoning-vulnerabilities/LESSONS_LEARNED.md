# LESSONS LEARNED

## Techniques that worked
- **Verify the cache key empirically first**: N identical requests → miss,hit,hit
  with `age` incrementing confirms key = path+query and the TTL (`cache-control: max-age=30`).
- **Identify every unkeyed header by reflection**: probe headers and diff the response
  body. `X-Forwarded-Host` → reflected into `data.host`; `X-Original-URL` → changes
  the back-end route. These are the "levers" for cache poisoning.
- **Exploit the *client-side* resource origin**: reflecting the host in `data.host`
  makes the victim's *browser* fetch our JSON — no need to reflect into the page body
  itself. Combining "server-side cache poisoning" + "client-side DOM XSS" is the crux.
- **Match the DOM-sink key**: `translate()` does `el.innerHTML = dict[k]` only when
  `el.innerHTML === k`. Read the actual page to find a key present on the target page
  ("View details" appears in every home-page product tile → 20 injections).
- **Force the non-English path**: the DOM sink only runs for `lang != en`, so poison a
  cacheable redirect to `/setlang/es` to flip the English visitor's language.
- **CORS for cross-origin `fetch().json()`**: the exploit server JSON needs
  `Access-Control-Allow-Origin: *` or the `fetch().then(r=>r.json())` is blocked.
- **Capture `alert()` in a headless browser** with CDP
  `Page.addScriptToEvaluateOnNewDocument` overriding `window.alert` to a recorder —
  gives non-blocking, script-readable proof (count + message).

## Mistakes / pitfalls (avoid repeating)
- **`requests` re-sends custom headers on redirect follow-ups.** Sending
  `GET /` with `X-Original-URL` and letting requests follow the 302 re-applies the
  header to `/setlang/es`, looping the 302 → `TooManyRedirects`. Fix: `allow_redirects=False`.
- **Poisoning needs a cache MISS.** If the cache is warm (clean), a poison request is a
  no-op HIT. The lab's own visitor keeps `/` repopulated clean, so you must poison
  **continuously** (re-poison at every 30s TTL expiry) and wait for the visitor to land
  on a poisoned window. A single "wait 30s then poison" can still hit a warm cache.
- **The exploit-server link vanishes when solved.** The lab header removes "Go to
  exploit server" once solved, so exploit-server discovery only works on an unsolved
  instance. Provide an `--exploit` fallback for re-runs.
- **`<script>` via `innerHTML` does not execute** — use an event-handler tag
  (`<img src=x onerror=…>`) for DOM-injected XSS.
- **Absolute vs relative timer bug**: `if time.time() >= 3.0` is always true
  (compare against `time.time()+3.0`).
- **Setting cookies on `about:blank` throws SecurityError** — navigate to the real
  origin first (or rely on the redirect to set the cookie).

## Tool behavior / environment
- `web_extract` backend here is search-only (ddgs) → cannot fetch URL bodies; use
  `curl`/browser for walkthroughs.
- Browser harness `capture_screenshot` can time out (60s) when the daemon is busy after
  a heavy JS page; rely on `js()` DOM reads for verification.
- PortSwigger lab instances are **ephemeral** — verify solved state immediately and save
  the HTML as evidence.
- uv project: `uv add requests` → `pyproject.toml` + `uv.lock`; run with
  `uv run python solve.py --url …`.

## Speed/reliability improvements for next time
- Reuse the "poison-until-`GET /` returns 302" loop (poll the poisoned state) instead of
  guessing TTL timing.
- Keep exploit-server config idempotent (re-POST each run; it's cheap).
- Poll solved status on the **exploit server** (separate host) so the poll doesn't
  disturb the lab cache you're poisoning.
- Run the solver for a generous window (≥200s) to catch ~3–4 visitor visits.

## Detection timing & loop resilience (2026-10-24, fresh-instance fix)
- **Gate solved-detection on the EXPLOIT SERVER status, not the lab page.** The lab home
  page / `/?localized=1` are the very pages we continuously poison, cached for
  `max-age=30`. Their status widget is STALE for up to ~30s after the visitor solves the
  lab (it only re-flips after the origin is solved AND the cache entry is re-fetched).
  The exploit server's status widget is on a separate, non-lab-cached host and flips
  promptly → gate detection on it. Bug symptom: "still not solved" keeps logging ~30s after
  the lab is actually solved.
- **Cache-bust the on-lab-host confirmation.** To confirm on the lab itself, fetch with a
  unique query (`/?cb=<ms>`) → origin fetch that bypasses the 30s poisoned cache, so it
  reflects the CURRENT state. Report it as evidence (`lab_confirmed`), never as the gate.
- **A single transient network error must not kill the run.** The pre-fix solver died on
  one `ReadTimeout` (read timeout=20) ~48s in. Wrap each poison-loop sub-step
  (`_poison`, `_verify_poisoned`, `_check_solved`) and the final confirmation in
  `try/except requests.exceptions.RequestException` → log a `[warn]` and continue (the
  solved-state is sticky, so retry). Verified: 53 simulated ReadTimeouts did not crash the
  loop (`scripts/test_resilience.py`).
- **Keep the final confirmation non-destructive.** If the loop already detected solved
  (exploit server is-solved, sticky), a transient error in the final re-check must not
  un-solve it — only a *successful* re-check that reports not-solved downgrades.
