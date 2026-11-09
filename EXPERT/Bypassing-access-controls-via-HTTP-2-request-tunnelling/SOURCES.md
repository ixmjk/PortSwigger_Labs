# Sources

## Official

* Lab description, objective, hint, and official solution:
  <https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling>
  (the `widget-container-labelevel` badge reads **EXPERT**).
* Request tunnelling topic page (blind vs non-blind tunnelling, the HEAD
  over-read trick, response-length balancing):
  <https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling>
* HTTP/2 request smuggling background:
  <https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors>

## Community write-ups consulted for cross-checks

* logicbreaker — *Bypassing access controls via HTTP/2 request tunnelling*
  (step-by-step reasoning for each header-name injection):
  <https://logicbreaker.sh/writeup/bypassing-access-controls-via-http-2-request-tunnelling>
* Juan E. Grateron — same lab, including measured page sizes and the note that
  `/login` (3351 B) fits the tunnelled admin response while `/admin` (2776 B)
  truncates it:
  <https://juangrate.cc/writeups/smuggling/bypassing-access-controls-via-http2-request-tunnelling/>
* siunam — lab 18 in the HTTP request smuggling series, shows the leaked
  `X-FRONTEND-KEY` values and the "Received only … of expected …" errors:
  <https://siunam321.github.io/ctf/portswigger-labs/HTTP-Request-Smuggling/smuggling-18/>

## Tooling

* `hyper-h2` (Python HTTP/2 state machine; used for frame generation and HPACK):
  <https://hyper-h2.readthedocs.io/>
* `h2.config.H2Configuration` header validation flags:
  <https://hyper-h2.readthedocs.io/en/stable/api.html#h2.config.H2Configuration>
