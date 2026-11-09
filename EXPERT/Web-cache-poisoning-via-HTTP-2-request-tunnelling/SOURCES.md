# Sources

## Primary

* PortSwigger — *Lab: Web cache poisoning via HTTP/2 request tunnelling*
  <https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling>
  — objective, difficulty badge (`EXPERT`) and the official solution steps
  (`:path` injection, `HEAD`, tunnel `GET /post?postId=N`, then
  `GET /resources?<script>alert(1)</script>` padded past the outer
  `Content-Length`, remove the cachebuster, resend every ~5 s).
* PortSwigger — *Request tunnelling* topic
  <https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling>
  — blind vs non-blind tunnelling, why a non-reusing front-end is still
  vulnerable, and the `HEAD`/`Content-Length` over-read.

## Secondary (community write-ups, used as cross-checks)

* siunam — *Web cache poisoning via HTTP/2 request tunnelling*
  <https://siunam321.github.io/ctf/portswigger-labs/HTTP-Request-Smuggling/smuggling-19/>
  — confirms the padding trick and that the reflected `/resources` redirect is
  the XSS gadget.
* k0z1l — *Lab 19: Web Cache Poisoning via HTTP/2 Request Tunnelling*
  <https://k0z1l.github.io/writeups/portswigger-http-request-smuggling/lab-19-http-request-smuggling-web-cache-poisoning-via-h2-request-tunnelling/>
  — cache-key framing (the tunnelled response is stored under the outer URL).
* logicbreaker — *Web cache poisoning via HTTP/2 request tunnelling*
  <https://logicbreaker.sh/writeup/web-cache-poisoning-via-http-2-request-tunnelling>

## Local prior art

* `EXPERT/Bypassing-access-controls-via-HTTP-2-request-tunnelling/` — the
  sibling lab in this repository; its HTTP/2 client (ALPN override,
  `validate_outbound_headers=False`, relaxed `_track_content_length`) is reused
  here.
