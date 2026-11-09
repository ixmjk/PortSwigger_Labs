# Report — Bypassing access controls via HTTP/2 request tunnelling

* **Lab:** Bypassing access controls via HTTP/2 request tunnelling
* **Category:** HTTP request smuggling → request tunnelling (HTTP/2 downgrade)
* **Difficulty:** EXPERT (read from `widget-container-labelevel` on the Academy
  description page)
* **Objective:** access `/admin` as `administrator` and delete `carlos`
* **Result:** **solved**, caused by this solver. Serialized attack:
  **12.0 s / 21 HTTP requests / exit 0**.
* **Evidence of record:** `evidence/baseline.raw` (`is-notsolved`),
  `evidence/control_GET_admin.raw` (401), `evidence/leak_cl_120_body_100_a1.raw`
  (leaked auth headers), `evidence/measure_tunnelled-admin.raw`
  (`Received only 3712 of expected 8691`), `evidence/tunnel_admin_via_login.raw`
  (tunnelled admin panel with `carlos`), `evidence/tunnel_admin_delete_carlos.raw`,
  `evidence/verify_admin_attempt_1.raw` (admin panel without `carlos`, widget
  `is-solved`), `evidence/after-solved.html` (solved page),
  `evidence/requests.jsonl`, `evidence/events.jsonl`.

## Timeline

| step | finding |
|---|---|
| Recon (plain `curl`) | Title identifies the lab; widget `is-notsolved`; `/my-account` → 302 `/login`; no exploit server involved. |
| Header-name probe | `foo: bar\r\nHost: abc` produced `Gateway Timeout (3) connecting to abc` — header-name CRLF injection confirmed on the first attempt. |
| Leak probe | `POST /?search=…` with injected `Content-Length` returned `X-SSL-VERIFIED: 0`, `X-SSL-CLIENT-CN: null`, `X-FRONTEND-KEY: …` immediately. |
| Size catalogue | `/login` 3351 B, `/admin` (401) 2776 B, `/` 8691 B, `/post?postId=n` 6472–9186 B. |
| Tunnel proof | Outer `HEAD /login` + tunnelled `GET /admin` returned a nested `HTTP/1.1 200 OK` admin panel in a 3351-byte body; the `carlos` delete link was present. |
| Delete + verify | Tunnelled `/admin/delete?username=carlos`; a fresh tunnelled `/admin` returned 200 with only `wiener`; widget `is-solved`. |

## What went wrong on the first packaged run

The first end-to-end run (11.1 s, exit 1) failed on one regex, not on the
technique: the leak parser captured the reflection's trailing `'</h1>` as part of
`X-FRONTEND-KEY`, so the forged tunnelled request sent
`X-FRONTEND-KEY: <key>'</h1>` and received a **401** instead of the admin panel.
The measured tunnelled length was correspondingly short (3180 instead of 3712
bytes), the size heuristic picked the 2776-byte `/admin` error page as the outer
path, and the subsequent tunnels exposed nothing readable. Fix: constrain the key
regex to digits (`[0-9]{4,}`). The next run solved on the first attempt.
Lesson recorded in `LESSONS_LEARNED.md`.

## Interesting observations

* **The lab does not advertise h2 over ALPN.** Negotiating `http/1.1` (or no
  ALPN) and then sending the h2 preface works; this is exactly Burp's
  *Allow HTTP/2 ALPN override* setting.
* **h2's own validation must be relaxed in two places.** Outbound: header names
  containing CRLF are rejected unless `validate_outbound_headers=False` and
  `normalize_outbound_headers=False`. Inbound: HEAD responses must carry no body,
  but the front-end delivers the tunnelled bytes as a DATA frame on the HEAD
  stream, so `H2Stream._track_content_length` is bypassed for this client or the
  exploit response cannot be parsed at all.
* **The front-end reports its own mis-framing precisely**, which turns the
  "not enough bytes" error into a measurement oracle: `Received only 3712 of
  expected 8691` gives the exact tunnelled response size in one request.
* **The delete answers a byte-count error even though it worked.** `302` is much
  shorter than the 3351-byte outer page, so the front-end errors after the
  back-end has already deleted the user. Success must be verified by re-reading
  `/admin` and by the widget, never by the delete response.
* **The post-delete verification capture also contained the next failure
  string** (`HTTP/1.1 400 Bad Request`) after the complete admin page. After the
  user list shrinks the front-end's over-read runs past the end of the tunnelled
  response into the back-end's response to a stray request; the admin page itself
  is intact and ends at `</html>`.

## Non-findings / dead ends avoided

* No classic desync was attempted: the description states the front-end does not
  reuse back-end connections, and that was confirmed by the self-contained
  tunnelling exchange.
* No need to log in as `wiener:peter` (unlike the cache-deception lab): the
  back-end trusts the front-end's certificate headers, so the forged tunnel needs
  no session of its own.
