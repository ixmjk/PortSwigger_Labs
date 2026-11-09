# Web cache poisoning via HTTP/2 request tunnelling — Expert

Automated solver for the PortSwigger Web Security Academy lab
[Web cache poisoning via HTTP/2 request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling).

Objective: poison the home-page cache so the victim, who visits `/` every 15
seconds, executes `alert(1)` in their browser.

## The bug in one paragraph

The front-end terminates HTTP/2 and rewrites each request as HTTP/1.1 for the
back-end, but it does not sanitise the `:path` pseudo-header before writing it
into the request line. A CRLF inside `:path` therefore ends the outer request
and appends attacker-chosen requests to it. The front-end does not reuse
back-end connections, so classic smuggling is useless — but *request tunnelling*
works: for a `HEAD` request it trusts the back-end's `Content-Length` and keeps
reading that many "body" bytes from the socket. Those bytes are actually the
responses to the smuggled requests, and the front-end caches them under the
cache key of the outer request. Because the outer request line stays valid
(`HEAD /`), the poisoned key is `/`. The first smuggled request is
`GET /resources?<script>alert(1)</script>`, which answers `302` with an
unescaped `Location` header echoing the query — so the cached body starts with a
live `<script>` tag.

## Run it

```bash
cd "EXPERT/Web-cache-poisoning-via-HTTP-2-request-tunnelling"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"

# from the repository root, through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

| flag | meaning |
|---|---|
| `--wait S` | how long to keep `/` poisoned while the victim visits (default 180 s) |
| `--interval S` | seconds between poison attempts (default 3 s) |
| `--timeout S` | per-request socket timeout (default 20 s) |

Nothing instance-specific is hardcoded: the host comes from `--url`, the outer
`Content-Length` and the filler-page sizes are measured live, the cache-busting
tokens are random, and success is read from the lab's own solved widget.

## What it does

0. **Baseline** — `GET /?cb=<random>` reads the title, the
   `widgetcontainer-lab-status` widget and the home page `content-length` (the
   number of bytes the front-end will over-read on a tunnelled `HEAD`).
1. **Size the filler** — fetches `/post?postId=N` pages and keeps the smallest
   set whose bodies exceed that `content-length`.
2. **Control tunnel** — repeats the attack through a cache-busted outer URL
   (`/?cb=<random>`), then reads that key back and requires the tunnelled bytes
   (payload included) to be there. This proves CRLF injection, tunnelling and
   cache write on a throwaway key without touching `/`.
3. **Already solved?** — if the widget already says `is-solved`, stop here and
   report `caused by solver: no` instead of claiming the flip.
4. **Poison `/`** — `HEAD /` with the following injected after the request
   line, repeated every `--interval` seconds:

   ```http
   GET /resources?<script>alert(1)</script> HTTP/1.1
   Host: <lab-id>.web-security-academy.net

   GET /post?postId=1 HTTP/1.1
   Host: <lab-id>.web-security-academy.net

   GET /post?postId=2 HTTP/1.1
   Foo: bar
   ```

   The last-line `Foo: bar` absorbs the ` HTTP/1.1` suffix the front-end appends
   while rewriting. A request served from a fresh cache entry never reaches the
   back-end, so the loop simply re-arms `/` as soon as the 30 s TTL expires.
5. **Watch it land** — repeatedly `GET /` and require the payload bytes to come
   back from the cache (`x-cache: hit`), then poll the widget from a
   cache-busted content page until it reads `is-solved`.
6. **Restore** — wait for the poisoned entry to expire, then re-fetch `/` so the
   instance serves its real home page again (this also keeps the repo launcher's
   title lookup working).

## Verified behaviour (this instance)

* Baseline: `is-notsolved`, home `content-length` **8345** (unsolved page).
* First exploratory tunnel (single smuggle, 9 000 bytes of padding after the
  payload) poisoned `/`: the next `GET /` answered `x-cache: hit` with
  `HTTP/1.1 302 Found` + `Location: /resources/?<script>alert(1)</script>…` as
  the body. The lab widget flipped to `is-solved` before a verification read
  ~3 minutes later — the victim visits every 15 s.
* After the flip the home page grows to `content-length` **11590** (the
  "Congratulations" banner), which is above the front-end's `:path` limit
  (~10 000 bytes), so pure padding can no longer fill the over-read. The
  multi-request tunnel (payload response + two `/post` pages) works for both
  sizes and is what the solver ships.
* Solver re-run on the solved instance: baseline `is-solved`, control tunnel
  captures **11590 bytes** with the payload reflected and the cache-buster key
  serving `x-cache: hit` — **5 requests, 2.7 s, exit 0**.
* `smoke_paths.py` on the same instance drives the phases the solved path skips:
  poison `/` on a cache miss, verify `GET /` serves the payload from cache, then
  restore a clean entry — **18 requests, 39.7 s, exit 0**.
* Root launcher: exact folder-name match, exit 0, 2.9 s total.

Local artifacts (git-ignored): `evidence/` — the pre-flip home page, the poisoned
home body, the post-flip solved page, plus `requests.jsonl`/`events.jsonl` and
raw responses; `logs/` — the verification runs; `scripts/` — the three
exploratory probes that established the mechanics.

## Implementation notes

* The lab speaks HTTP/2 but **does not advertise it via ALPN**. The client
  negotiates `http/1.1` and then sends the HTTP/2 connection preface anyway
  (the Python equivalent of Burp's *Allow HTTP/2 ALPN override*).
* `h2` validates outbound pseudo-headers, so the connection uses
  `validate_outbound_headers=False` and `normalize_outbound_headers=False`.
* `h2` also enforces `content-length: 0` on inbound `HEAD` responses; the
  front-end returns the tunnelled bytes as DATA on those streams, so
  `H2Stream._track_content_length` is relaxed for this client.
* Filler pages are ordinary `GET /post?postId=N` responses pipelined behind the
  payload request: the front-end stops reading at the outer `Content-Length`,
  so only the first bytes need to matter and the rest is filler.

## Exit codes

0 verified solved (or already solved), 1 exploit ran but not verified, 2 usage or
unreachable/expired instance.
