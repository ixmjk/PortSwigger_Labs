# LESSONS LEARNED — CSP bypass via policy-parameter injection

Generalisable points, not instance trivia.

## 1. Treat every reflected response header as an injection sink

A parameter echoed into `Content-Security-Policy`, `Location`, or any other
header is a *parser* target, not a string. Here `token` was concatenated into
`report-uri /csp-report?token=…`; terminating the directive with `;` and
appending a new one rewrote the policy. Always diff the full header between two
requests with distinct values for each parameter — reflection into a header is
easy to miss when only the body is inspected.

## 2. Know the CSP override hierarchy

`script-src-elem` governs `<script>` elements and **overrides** `script-src` for
them; `script-src-attr` does the same for inline event handlers. So appending
`script-src-elem 'unsafe-inline'` defeats a hardened `script-src 'self'`
without touching it. The directive only exists in Chromium browsers, which is
why Academy marks some of these labs Chrome-only — but a server-side detector
does not care.

## 3. Check whether the lab's solve detection is server-side before automating a browser

The first hypothesis was "needs a headless Chrome so `alert()` fires". A single
plain GET flipped the widget, so the detector simply validates the bypassing
request. A cheap rule: send the crafted request with a bare HTTP client and
re-read the status widget before adding any browser dependency. Pure-httpx
solvers are far more portable (no Chromium download, works on ARM).

## 4. The lab status widget is the authoritative oracle

Success = `widgetcontainer-lab-status is-solved` and `<p>Solved</p>` in the
returned HTML (the header WebSocket pushes the same markup). A 200, a reflected
payload, or an injected directive are *preconditions*, not proof — assert them
separately and then poll the widget.

## 5. Handle the "already solved" case explicitly

Once the exploit has been sent during recon, the instance stays solved. The
solver must not claim it caused the flip: it records the baseline state first
and reports `caused by solver: no (was already solved)`. For a clean end-to-end
proof you need a fresh instance, which requires an authenticated Academy
session — plan for that before burning the only URL you were given.
