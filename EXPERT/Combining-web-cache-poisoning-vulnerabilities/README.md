# PortSwigger Lab: Combining web cache poisoning vulnerabilities (EXPERT)

**Status: ✅ SOLVED & VERIFIED** (lab status widget → `is-solved` / `Solved`)

Autonomous solver for the PortSwigger Web Security Academy lab
*"Combining web cache poisoning vulnerabilities"*.

Target instance used (ephemeral):
`https://0a9a0059033608fe80ed030b00a40091.web-security-academy.net/`
Exploit server: `https://exploit-0a3b00cc030c083f8029022601f300a9.exploit-server.net`

## What the lab requires
Poison the shared CDN cache so the English-speaking visitor (who hits the home
page ~once a minute) receives a response that executes `alert(document.cookie)`
in their browser.

## The exploit chain (three combined design flaws)
The CDN cache key is **request-line path + query string only**. Two **unkeyed**
request headers let us change the *body* the back-end returns for a given key:

1. **`X-Original-URL: /setlang\es`** (backslash) → back-end routes on the header;
   the backslash path is an unknown route so it answers a **cacheable 302 → `/setlang/es`**
   (no `Set-Cookie`). Stored under key `/`.
2. **`X-Forwarded-Host: <exploit-host>`** → reflected into the page's
   `data = {"host": "..."}`; `translations.js` then fetches
   `//<host>/resources/json/translations.json` → our exploit-server JSON.
3. **DOM XSS sink** in `translations.js`: for **non-English** languages it does
   `el.innerHTML = dict[k]` over the page, so a translation *value* containing
   `<img src=x onerror=alert(document.cookie)>` executes. English never runs this,
   so we force `lang=es` via the redirect.

Victim flow:
`GET /` (302) → `GET /setlang/es` (sets `lang=es`, 302) → `GET /?localized=1`
(poisoned, `data.host=exploit`) → fetch exploit JSON (CORS `*`) → `translate()`
rewrites the 20 "View details" tiles → **20 × `alert(document.cookie)`**.

## How to run
```bash
cd "Combining web cache poisoning vulnerabilities"
uv sync                                   # or: uv add requests (already locked)
uv run python solve.py --url "https://<LAB_ID>.web-security-academy.net"
```
- On a **fresh (unsolved)** instance the exploit-server URL is auto-discovered
  from the lab header.
- On a **re-run of an already-solved** instance pass `--exploit <url>` (the header
  no longer exposes the link once solved).
- `--timeout` (default 200s) is the window to wait for the visitor; `--quiet` for less noise.

The script: (1) recon → (2) configure exploit server with the malicious JSON →
(3) continuous poison loop (keeps both cache entries poisoned through their 30s
TTL) while polling the status widget → (4) reports SOLVED + elapsed time + request count.

## Project layout
```
solve.py                  # the solver
pyproject.toml / uv.lock  # uv-managed deps (requests)
README.md / REPORT.md     # this + full write-up
RESUME.md                 # status, verified facts, resume steps (fresh URL)
LESSONS_LEARNED.md        # reusable techniques & mistakes
SOURCES.md                # walkthroughs / references / search queries
requests/                 # exact poison + config requests
evidence/                 # solved-state HTML, browser alert capture, writeups
logs/                     # timestamped solver run logs
```
