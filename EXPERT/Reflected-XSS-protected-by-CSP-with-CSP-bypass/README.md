# Reflected XSS protected by CSP, with CSP bypass — Expert

Automated solver for the PortSwigger Web Security Academy lab
[Reflected XSS protected by CSP, with CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass).

## The bug in one paragraph

The blog search page reflects `search` into `<h1>… search results for
'<PAYLOAD>'</h1>` with no HTML encoding, so `<script>alert(1)</script>` lands
in the page verbatim. A `Content-Security-Policy` header stops it from running
(`script-src 'self'`). The same header ends with
`report-uri /csp-report?token=<token>` — the `token` query parameter is copied
into the policy untrusted, so a second parameter injects a fresh directive:
`;script-src-elem 'unsafe-inline'`. `script-src-elem` wins over `script-src`
for `<script>` elements, so the inline payload executes and `alert(1)` fires.

## Run it

```bash
cd "EXPERT/Reflected-XSS-protected-by-CSP-with-CSP-bypass"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

From the repository root the universal launcher finds this solver by page title:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

Options: `--timeout S` (per request, default 20), `--wait S` (polling window
after the exploit, default 20), `--verbose` (print each request URL).

Exit codes: `0` verified solved, `1` exploit sent but lab not marked solved,
`2` usage problem, `3` lab unreachable/expired.

## What the solver proves

1. Page title identifies this lab (refuses to run against anything else).
2. Baseline status is read from the lab's own header widget
   (`widgetcontainer-lab-status`).
3. Control request: the payload is reflected **verbatim** while
   `script-src 'self'` still forbids inline script.
4. Exploit request (`search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'`):
   the echoed policy now contains the injected `script-src-elem 'unsafe-inline'`.
5. The lab root is polled until the widget reports `is-solved` / `Solved`.

Success is the lab's own solved state — not a 200, not a redirect.

## Verified result

| instance | baseline | after exploit | requests | solver time |
|---|---|---|---|---|
| `0a1000fd031ddb3b82b08ee000e400c1` | not solved | **SOLVED** | 5 | 2.0 s |

The lab flipped to solved when the exploit request was first sent during recon
(see `evidence/`), before the solver existed; the shipped solver then re-verified
the same instance end-to-end and reported it already solved. See `RESUME.md`
for why no second fresh instance was used.

## Files

```
solve.py        the solver (httpx, no browser needed)
RESUME.md       checkpoint, state, continuation commands
SOLUTION.md     minimal reproducible recipe
REPORT.md       investigation notes and evidence chain
LESSONS_LEARNED.md  generalisable CSP-bypass lessons
SOURCES.md      references
evidence/       before/after lab widget HTML + exploit response headers (local, git-ignored)
logs/           solver and launcher runs (local, git-ignored)
```
