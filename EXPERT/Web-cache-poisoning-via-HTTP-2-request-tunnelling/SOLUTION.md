# Solution — Web cache poisoning via HTTP/2 request tunnelling

One command:

```bash
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

## 1. Confirm the front-end is an HTTP/2 → HTTP/1.1 downgrade

The lab does not advertise `h2` via ALPN. Complete TLS as `http/1.1`, then send
the HTTP/2 preface and a normal request: it answers `200` with
`x-cache`/`age`/`cache-control: max-age=30`, so there is a cache in front of the
back-end.

## 2. Confirm CRLF injection in `:path`

Send an ordinary `GET` with

```
:path: /?cb=1 HTTP/1.1\r\nFoo: bar
```

The response is a normal home page — the front-end wrote the injected CRLF
straight into the HTTP/1.1 request line.

## 3. Tunnel a second request and read its response

Switch to `HEAD` and place a complete request after the outer one:

```
:path: /?cb=2 HTTP/1.1\r\nHost: <lab-id>\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nFoo: bar
```

The front-end over-reads `Content-Length` "body" bytes for the `HEAD`, and those
bytes are the smuggled `GET /post?postId=1` response. That response comes back
as the body of the HTTP/2 stream — non-blind tunnelling.

## 4. Pick the XSS gadget

`GET /resources?<script>alert(1)</script>` answers

```
HTTP/1.1 302 Found
Location: /resources/?<script>alert(1)</script>
```

The query is reflected into `Location` unescaped, and the value is not
HTML-escaped, so a cached copy of those bytes contains a live `<script>` tag.

## 5. Fill the over-read

The front-end caches exactly as many bytes as the outer `Content-Length`. A
single small `302` response ends before that, so the front-end blocks on a short
read (HTTP 500/timeout). Two options:

* pad the reflected query until the tunnelled header block is long enough
  (works while the home page is small — the unsolved page measured 8345 bytes —
  but the front-end rejects a `:path` over ~10 000 bytes with `400`);
* pipeline filler requests so the *following* responses supply the bytes. This
  is robust for any `content-length` and needs no padding:

```
:path: / HTTP/1.1\r\nHost: <lab-id>\r\n\r\n
       GET /resources?<script>alert(1)</script> HTTP/1.1\r\nHost: <lab-id>\r\n\r\n
       GET /post?postId=1 HTTP/1.1\r\nHost: <lab-id>\r\n\r\n
       GET /post?postId=2 HTTP/1.1\r\n
       Foo: bar
```

## 6. Poison `/`

The cache key is the URL on the outer request line, so keep `:path` starting
with `/` — the injected CRLF does not change the key. Send the tunnelled `HEAD /`
and then fetch `/`: the response is `x-cache: hit` with body

```
HTTP/1.1 302 Found
Location: /resources/?<script>alert(1)</script>
…
```

The victim visits `/` every 15 s; the entry has `max-age=30`, and a request
served from a fresh entry never reaches the back-end, so re-send the tunnel
every few seconds to re-arm the key after each expiry.

## 7. Verify

Only the lab's own widget counts: read a cache-busted page such as
`/post?postId=1&cb=<random>` and require
`widgetcontainer-lab-status is-solved` / `<p>Solved</p>` (`/` itself is serving
the poison, so it cannot be used to read the widget).

The solver then waits for the poison to expire and re-fetches `/` so the
instance serves its real home page again.
