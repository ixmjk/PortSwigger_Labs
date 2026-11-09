# Lessons learned — Web cache poisoning via HTTP/2 request tunnelling

* **This lab's injection point is `:path`, not just header names.** The sibling
  access-control lab injects through a header *name*; here the front-end also
  copies `:path` into the HTTP/1.1 request line unsanitised. That matters
  because the cache key is the URL on the request line: injecting through
  `:path` still lets you keep the key as `/` (start the value with `/`), while a
  `?cachebuster=` run only poisons that cachebuster key.
* **A single small smuggled response never fills the over-read.** The front-end
  reads exactly the outer `Content-Length`; if the tunnelled response ends
  first, you get `500`/timeout and nothing is cached. Two fixes: pad the
  reflected query (the official solution) or pipeline filler pages. Prefer
  filler pages.
* **Pad length is bounded by the front-end's `:path` limit.** Measured on this
  instance: 9 500 bytes accepted, 10 077 → `400`. Once the lab is solved the
  home page is 11 590 bytes (congratulations banner) — larger than the limit —
  so padding is not a general solution.
* **Filler pages make the tunnel `content-length`-agnostic.** Pipelining
  `GET /post?postId=N` behind the payload request supplies plain response bytes
  the front-end happily caches; the payload only has to sit in the first
  response. Measure page sizes live and add pages until the total exceeds the
  outer `Content-Length`.
* **The last injected request line must end without its own blank line.** The
  front-end appends ` HTTP/1.1` plus its own headers, so finish with
  `… HTTP/1.1\r\n` followed by a `Foo: bar` line: the suffix lands on `Foo` and
  the appended headers become that request's headers.
* **`x-cache: hit` means the poison did not reach the back-end.** A fresh entry
  (max-age 30) is served without touching the origin, so a "re-poison" during
  the TTL is a no-op — but the key is still poisoned, which is all the victim
  needs. Loop every few seconds and let the expiry re-arm it.
* **Never read the widget from `/` while it is poisoned.** The cached body has
  no lab header. Use any other page with a unique query parameter
  (`/post?postId=1&cb=<random>`) to bypass the 30 s cache and get a fresh
  widget.
* **Restore the home-page entry before handing off.** The repo launcher reads
  the lab title with a plain `GET /`; a poisoned entry returns the raw tunnelled
  bytes, which has no `<title>` and makes the launcher report "no readable
  title". Waiting for the TTL and re-fetching `/` fixes it.
* **The victim/checker is fast on this lab** — the flip happened within minutes
  of the first poison, unlike the stored-comment labs where minutes to tens of
  minutes are normal.
* **A solved instance has a different `content-length`.** Hardcoding the number
  from a write-up (8512, 8345, …) breaks the poison. Always measure.
