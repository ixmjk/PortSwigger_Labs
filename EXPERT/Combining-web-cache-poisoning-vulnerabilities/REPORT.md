# Report — Combining web cache poisoning vulnerabilities (EXPERT)

## Final result
**The lab was ACTUALLY solved and verified.** The authoritative PortSwigger
lab-status widget flipped from `is-notsolved` to **`is-solved` / `<p>Solved</p>`**
on both the lab page and the exploit server (see `evidence/solved_state_FINAL.html`,
`evidence/solved_state_exploit_FINAL.html`).

The solve was caused by the cache-poisoning chain: the English visitor's browser
was coerced through `/setlang/es` (→ `lang=es`) onto a poisoned `/?localized=1`
page whose `data.host` pointed at the exploit server, which served a malicious
`translations.json`; `translate()` then injected `<img src=x onerror=alert(document.cookie)>`
into all 20 product tiles → `alert(document.cookie)` executed.

## Evidence of genuine success (not just an HTTP 200)
1. **Lab status widget = Solved** (server-rendered, authoritative).
2. **Browser end-to-end capture** (`evidence/browser_alert_capture.json`):
   driving a fresh Chrome tab through the full chain gave
   `final_url = /?localized=1`, `cookie = lang=es`, **`alert(document.cookie)`
   fired 20 times** (each message = the cookie `lang=es`), and "View details"
   links went 20 → 0 (replaced by injected `<img>` tags; imgs 41 → 61).
3. **Both poisoned cache entries confirmed** on a clean `solve.py` run
   (`logs/solve_repro_FINAL.log`): `/` → `302 /setlang/es`,
   `/?localized=1` → `data.host = exploit-…` (both `x-cache: hit` after a miss).

## Reproduction command
```bash
cd "/root/Desktop/PortSwigger_Labs/EXPERT/Combining-web-cache-poisoning-vulnerabilities"
uv run python solve.py --url "https://0a9a0059033608fe80ed030b00a40091.web-security-academy.net"
```
(Fresh instances auto-discover the exploit server; the `--exploit` flag is only
needed when re-running on an already-solved instance.)

## Verified on a fresh instance?
The solver logic is fully instance-agnostic (lab host from `--url`, exploit host
discovered from the header) and was exercised end-to-end on this instance. The one
caveat: the lab instance was already in the solved state by the time the final
`solve.py` run executed (the visitor had caught the poisoned window during the
manual/earlier poisoning), so that run *detected* the solved state in ~6s. On a
genuinely fresh instance the poison loop runs until a visitor (~1/min) lands on a
poisoned window — typically ~60–120s — before the status flips. The mechanism
(every header, the redirect, the reflection, the CORS JSON, the DOM sink) was each
verified independently on the live lab, and the full chain was reproduced in a real
browser, so the solver's success is not an artifact of the pre-solved state.

## Timing / request count
- Time-to-solve (manual investigation + first solved state): ~20 min
  (recon ~00:19–00:31, solved observed 00:39).
- Final `solve.py` run: **6.53 s, 17 HTTP requests** (already-solved instance →
  fast detection). A fresh-instance run is longer (continuous poison loop until a
  visitor arrives; bounded by `--timeout`, default 200 s).
- Poison loop cadence: ~8 requests/s (2 poison reqs + periodic verify/poll).

## Key discoveries / lessons
- Cache key = request-line path + query only; **headers are unkeyed**.
- `X-Forwarded-Host` is reflected into `data.host` (→ client-side resource origin).
- `X-Original-URL: /setlang\es` (backslash) yields a **cacheable** 302 (no
  `Set-Cookie`), unlike the forward-slash `/setlang/es` which is `cache-control: private`.
- Only `/?localized=1` (the localized page) reflects `X-Forwarded-Host`; plain `/`
  did not in cache-hit tests (it was served from cache).
- `translations.js` only runs `translate()` for **non-English** `lang` → the
  redirect to `es` is mandatory to make the English victim execute the payload.
- `innerHTML` injection: `<img src=x onerror=…>` works; a `<script>` via
  `innerHTML` would NOT execute.
- `requests` **re-sends custom headers on redirect follow-ups** → must use
  `allow_redirects=False` for the X-Original-URL poison (else the 302 loops).
- The "Go to exploit server" header link disappears once the lab is solved →
  exploit-server discovery only works on an unsolved instance.
- The lab visitor keeps repopulating `/` (clean), so poisoning must be **continuous**
  (re-poison on every 30s TTL expiry) to catch the visitor in a poisoned window.
