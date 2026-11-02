# SOLUTION — Reflected XSS protected by CSP, with CSP bypass

Lab: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass>
Difficulty: Expert

## Payload

Send this request (search string and `token` both URL-encoded):

```
GET /?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=%3Bscript-src-elem%20%27unsafe-inline%27
```

Decoded:

```
/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

## Why it works

1. `search` is reflected into the results heading without HTML encoding.
2. The response CSP is
   `default-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; report-uri /csp-report?token=<token>`
   and `<token>` is taken from the request's `token` parameter — attacker controlled.
3. Starting the value with `;` terminates the `report-uri` directive, and
   `script-src-elem 'unsafe-inline'` is parsed as a new policy directive.
4. `script-src-elem` overrides `script-src` for `<script>` elements, so the
   reflected inline script is allowed and `alert(1)` runs.

## Automated

```bash
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

The solver checks the reflection, checks that the injected directive appears in
the returned CSP header, then confirms the lab widget reports `Solved`.

## Notes

* Intended browser is Chrome (per PortSwigger), because of `script-src-elem`
  support; the HTTP-level exploit is browser-independent.
* No exploit server is needed; the lab marks itself solved once the bypassing
  request is received (`/exploit` returns 404 on this lab).
