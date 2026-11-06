# SOURCES — Reflected XSS with AngularJS sandbox escape and CSP

## Primary

* PortSwigger Academy — lab page and official solution
  <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp>
  Used for: objective wording, the `orderBy` + `composedPath()` vector, and the
  note that `path` is Chrome-specific (the official explanation still describes
  the `path` mechanic while the shipped payload calls `composedPath()`).
* PortSwigger Academy — "AngularJS sandbox escape" and
  "Bypassing a CSP with an AngularJS sandbox escape" topic pages
  <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
  Used for: the sandbox model (blocked `window`/`constructor`) and why filters
  are the escape surface.

## Live instance (authoritative for this run)

* `GET /` of the lab: `<title>`, CSP header, `angular_1-4-4.js` script tag,
  `<body ng-app ng-csp>`, `<h1>0 search results for '...'</h1>` reflection.
* `GET /?search=<payload>`: control request proving verbatim reflection.
* Exploit server: `GET /` (form action `/`, fields `urlIsHttps`,
  `responseFile`, `responseHead`, `responseBody`), `GET /exploit` (stored body),
  `POST /` with `formAction=STORE|DELIVER_TO_VICTIM|ACCESS_LOG`.
* Lab header widget: `widgetcontainer-lab-status is-notsolved|is-solved` plus
  `<p>Not solved</p>`/`<p>Solved</p>` — the only accepted success oracle.

## Secondary / background

* AngularJS 1.4.x source (`$parse` sandbox, `orderByFilter`,
  `ensureSafeMemberName`, `ensureSafeObject`) — read for the mechanism, not
  copied into the solver.
* Repository prior art: `EXPERT/Reflected-XSS-with-event-handlers-and-href-attributes-blocked`
  and `EXPERT/Reflected-XSS-protected-by-CSP-with-CSP-bypass` — reused solver
  structure (identify → baseline → control → exploit → poll → evidence).

## Not used

* Third-party write-ups: not needed, the official solution plus the live
  instance were sufficient. The vector was verified against the instance rather
  than trusted from any prose description.
