# RESUME — Reflected XSS protected by CSP, with CSP bypass

**Status: COMPLETE / SOLVED.**

## Checkpoint

* Lab: `Reflected XSS protected by CSP, with CSP bypass` — Expert, XSS / CSP.
* Instance used: `0a1000fd031ddb3b82b08ee000e400c1.web-security-academy.net`
  (likely expired by now). A fresh instance needs no code changes — only `--url`.
* Solved: yes. Lab widget `is-solved` / `<p>Solved</p>` after the exploit request.
* Exploit: `GET /?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'`.
* Detection: lab marks itself solved server-side; no browser or exploit server needed.
* Verified: solver run on the live instance → 5 requests, 2.0 s, exit 0
  (reported "already solved" because recon had already flipped it).

## Done

| item | state |
|---|---|
| Reflection confirmed unencoded in `<h1>` | done |
| CSP header map (`script-src 'self'`, `report-uri …?token=`) | done |
| `token` parameter confirmed reflected into the header | done |
| Bypass payload (`script-src-elem 'unsafe-inline'`) verified in echoed CSP | done |
| Solve confirmed via lab status widget | done |
| `solve.py` (control + exploit + poll + verification) | done, exit 0 |
| `uv` project (`pyproject.toml`, `uv.lock`, `uv add httpx[http2]`) | done |
| Universal launcher match (`exact folder-name match`) | done |
| Docs (README / SOLUTION / REPORT / LESSONS / SOURCES) | done |

## Open item

A **fresh-instance** run was not possible: launching another instance requires a
logged-in PortSwigger account and the available browser session is signed out.
With a fresh URL this is the whole procedure:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "<FRESH_LAB_URL>"
```

Expect exit 0, "caused by solver: yes", and the widget flipping to solved within
a couple of seconds.

## Gotchas if reopened

1. The `token` value must start with `;` and must **not** contain `&` — it lives
   in a header, so a stray separator truncates the directive.
2. Use `script-src-elem`, not `script-src`: some instances/tools already define
   `script-src`, and the `-elem` variant is the one that overrides it for
   `<script>` elements (Chrome-only, per PortSwigger).
3. Do not treat the CSP echo alone as success — always read the lab widget.
4. `/exploit` is 404 on this lab; there is nothing to deliver to a victim.

## Exact continuation commands

```bash
cd "/root/Desktop/PortSwigger_Labs/EXPERT/Reflected-XSS-protected-by-CSP-with-CSP-bypass"
uv run python solve.py --url "<LAB_URL>" --verbose
cd /root/Desktop/PortSwigger_Labs && uv run python solve.py --url "<LAB_URL>"
```
