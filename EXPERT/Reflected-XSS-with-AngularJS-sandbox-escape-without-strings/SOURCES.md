# SOURCES — Reflected XSS with AngularJS sandbox escape without strings

## Primary

* PortSwigger Academy — lab page and official solution
  <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings>
  Used for: objective wording, the quote-free `toString().constructor` +
  `fromCharCode` vector, and the `%3d` encoding of the internal assignment.
  Difficulty badge (`EXPERT`) read from the rendered page
  (`widget-container-labelevel`), not from static HTML.
* PortSwigger Academy — client-side template injection topic
  <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
  Used for: the AngularJS sandbox model (blocked `window`, `constructor` chain)
  and the general "expression sink" framing.

## Live instance (authoritative for this run)

* `GET /` — `<title>`, `/resources/js/angular_1-4-4.js`, `<body ng-app=labApp>`,
  status widget `widgetcontainer-lab-status is-notsolved|is-solved`.
* `GET /?search=1&foo=bar&baz=qux` — one `var key`/`$scope.query[key]`/
  `$parse(key)` triple per parameter: the name is the expression sink.
* `GET /?search=1&7*7=x` — control: the name `7*7` is reflected and, in a
  browser, evaluated to `49`.
* `GET /?search=1&toString()…fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`
  — the exploit request; the response still reports *Not solved*.
* `GET /exploit` → **404** and no `#exploit-link` in the header: no exploit
  server, the lab is checked server-side.

## Secondary / background

* AngularJS 1.4.4 source (`/resources/js/angular_1-4-4.js`): `$parse` sandbox
  (`ensureSafeObject`, `ensureSafeMemberName`), `orderByFilter` compiling a
  string predicate with `$parse` — read for the mechanism; the solver only uses
  the shipped behaviour, verified in a browser.
* Repository prior art:
  `EXPERT/Reflected-XSS-with-AngularJS-sandbox-escape-and-CSP` (solver layout,
  Angular version gating), `EXPERT/Reflected-XSS-in-a-JavaScript-URL-with-some-characters-blocked`
  (no-exploit-server, server-side flip pattern).

## Not used

* Third-party write-ups: not needed. The vector was taken from the official
  solution and then verified step by step against the live instance, including a
  browser control without the sandbox break.
