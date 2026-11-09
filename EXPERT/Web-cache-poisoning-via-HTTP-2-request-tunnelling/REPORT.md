# Report — Web cache poisoning via HTTP/2 request tunnelling

## Target

| | |
|---|---|
| Lab | Web cache poisoning via HTTP/2 request tunnelling |
| Difficulty | **EXPERT** (read from `widget-container-labelevel` on the Academy page) |
| Topic | HTTP request smuggling → request tunnelling |
| Objective | Poison the home-page cache so the victim's browser executes `alert(1)` |
| Victim | Visits `/` every 15 seconds |

## Result

**Solved.** The lab's own widget reads `widgetcontainer-lab-status is-solved`
(`<p>Solved</p>`) and the home-page cache was observed serving the tunnelled
`302` whose `Location` header carries `<script>alert(1)</script>`.

The flip was caused by the first exploratory tunnel in this session: the
baseline fetch at the start of the investigation read `is-notsolved` on the
8345-byte home page, the tunnelled `HEAD /` was sent immediately afterwards, and
the next independent read of a content page showed `is-solved`. The instance is
one-shot, so `solve.py` — written after the flip — re-runs in its
"already solved" mode and proves the mechanism with a control tunnel instead of
claiming a second flip.

## Evidence

| artifact | what it shows |
|---|---|
| `evidence/01-baseline-home-is-notsolved.html` | pre-exploit home page, `widgetcontainer-lab-status is-notsolved`, content-length 8345 |
| `evidence/02-home-served-poisoned-body.html` | `GET /` after the tunnelled `HEAD`: body is `HTTP/1.1 302 Found` + `Location: /resources/?<script>alert(1)</script>` |
| `evidence/03-post-page-is-solved.html` | independent content page reading `is-solved` (the widget cannot be read from `/` while it is poisoned) |
| `evidence/04-home-after-flip.html` | solved home page (content-length 11590 — the congratulations banner) |
| `evidence/requests.jsonl`, `evidence/events.jsonl` | per-request log (cookies redacted) and solver events |
| `evidence/*.raw` | raw tunnelled/cached bodies from the verification runs |
| `logs/run-lab-folder.log`, `logs/run-launcher.log`, `logs/smoke-solved-instance.log` | the three verification runs |

## Measurements

| what | value |
|---|---|
| home `content-length`, unsolved | 8345 bytes |
| home `content-length`, solved | 11590 bytes |
| cache TTL | `cache-control: max-age=30` |
| front-end `:path` limit | ~10 000 bytes (`400` above it; 9 500 tested OK, 10 077 → `400`) |
| minimum padding for the single-smuggle variant | ≥ outer content-length (9 000 bytes of padding worked at 8345) |
| tunnelled bytes cached per poison | exactly the outer `content-length` |
| time from first poison to `is-solved` | under ~3 minutes (victim visits every 15 s) |
| solver on the solved instance | 5 requests, 2.7 s, exit 0 |
| `smoke_paths.py` (poison + verify + restore) | 18 requests, 39.7 s, exit 0 |
| root launcher end-to-end | 2.9 s, exact folder-name match, exit 0 |

## Why the mechanism works

1. The front-end downgrades HTTP/2 to HTTP/1.1 and copies `:path` into the
   request line without sanitising CRLF.
2. A `HEAD` outer request makes the front-end trust the back-end's
   `Content-Length` and read that many bytes as the response body.
3. Those bytes are the pipelined responses to the smuggled requests; the
   front-end caches them under the outer URL's key (`/`).
4. `/resources?<payload>` reflects the query unescaped into `Location`, so the
   cached bytes contain a live `<script>` tag and the victim executes it.

## Defensive notes

* Never build an HTTP/1.1 request line or header block from unvalidated
  protocol metadata; re-serialise and validate on the HTTP/2 → HTTP/1.1
  boundary (or keep the connection HTTP/2 end to end).
* Reject `\r`, `\n` and other control characters in `:path`, `:method` and
  header names/values at the edge.
* Do not cache responses to `HEAD` requests, and never let a cache store more
  bytes than the response it is attributed to.
* Encode reflected values in `Location` and other headers.
