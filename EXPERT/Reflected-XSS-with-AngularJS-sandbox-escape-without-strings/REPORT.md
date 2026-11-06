# Report — Reflected XSS with AngularJS sandbox escape without strings

**Lab:** Reflected XSS with AngularJS sandbox escape without strings
**Difficulty:** EXPERT (rendered badge, Academy description page)
**Instance:** `0a4b007b042c8475835b4be200ca003c.web-security-academy.net`
**Date:** 2026-11-06 (UTC)
**Result:** solved — `widgetcontainer-lab-status is-solved` / `<p>Solved</p>`
**Caused by solver run:** no (the instance was flipped by the recon request and
stays solved; the solver re-proved the mechanism and returned exit 0)

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:24:17 | `GET /` — baseline `is-notsolved`; title, AngularJS 1.4.4, `ng-app` recorded |
| 22:24:27 | `GET /?search=zzzq123` — reflection found: `$scope.query[key] = 'zzzq123'` inside `<script>` |
| 22:24:4x | Character probes: `' " < \` are HTML-entity-encoded, so the JS string cannot be broken |
| 22:24:5x | Two-parameter probe shows **one statement per parameter** and the `$parse(key)` sink |
| 22:25:0x | Key-as-expression control `?search=1&7*7=x` — key is reflected into `var key = '7*7'` |
| 22:25:50 | Exploit request (official vector) — response body still `is-notsolved` |
| 22:25:56 | Poll: `is-solved` / `Solved` |
| 22:29 | Browser proof: exploit URL alerts `1`; controls `7*7` and no-`charAt`-break stay silent |
| 22:27 | `solve.py` run: exit 0, 6 requests, 2.4 s (baseline already solved) |
| 22:27 | Root launcher: exact folder-name match, exit 0, 2.8 s total |

## Request inventory (solver)

1. `GET /` — identity, Angular version, `ng-app`
2. `GET /?search=1&probe=sink` — confirm the `$parse(key)` controller sink
3. `GET /exploit` — 404, no exploit server (server-side check)
4. `GET /` — baseline status (authoritative widget)
5. `GET /?search=1&7*7=x` — control: parameter names are compiled
6. `GET /?search=1&toString()…fromCharCode(…)=1` — exploit vector, reflected verbatim

## Findings

* **Injection channel is the parameter _name_, not the value.** The lab
  interpolates each parameter into `var key = '<name>'; $scope.query[key] = '<value>';`
  and then calls `$parse(key)`, so the name is compiled as an Angular expression.
  Entity-encoding of `'`/`"`/`<` inside `<script>` makes JS-string breakout
  impossible; the expression channel is the intended path.
* **`=` handling is the fiddly part.** The app splits a parameter on the first
  literal `=` and decodes afterwards. `%3d` is therefore required for the internal
  `charAt=[].join` assignment; a raw `=` would truncate the expression.
* **The sandbox break is load-bearing.** Without
  `toString().constructor.prototype.charAt=[].join;`, the same `orderBy` string
  predicate is rejected by AngularJS 1.4 and no alert fires (browser control B).
* **No exploit server.** `/exploit` returns 404 and the header has no
  `#exploit-link`; the lab is checked server-side and flips ~6 s after the crafted
  request. The first response still reports *Not solved*, so polling the widget is
  mandatory — a single-response check produces a false negative.
* **Instance state is sticky.** With no fresh instance available (Academy account
  needed), the solver reports `caused by solver: no (was already solved)` rather
  than claiming the flip.

## Artefacts

* `evidence/20261106T222417Z-lab-baseline-manual.html` — pre-exploit page, `is-notsolved`
* `evidence/20261106T222550Z-exploit-response-manual.html` — response to the vector, still `is-notsolved`
* `evidence/20261106T222700Z-lab-solved-manual.html` — `is-solved` / `Solved`
* `evidence/browser-alert-proof.txt` — Chromium: exploit alerts `["1"]`, controls `[]`
* `evidence/<stamp>-sink-controller.html`, `-control-expression.html`, `-exploit-response.html`, `-lab-baseline.html`, `-lab-solved.html` — solver run
* `requests/exploit-request.txt`, `responses/exploit-response-key.txt`
* `logs/<stamp>-solve.log`
