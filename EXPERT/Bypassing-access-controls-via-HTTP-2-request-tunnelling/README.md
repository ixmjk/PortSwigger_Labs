# Bypassing access controls via HTTP/2 request tunnelling — Expert

Automated solver for the PortSwigger Web Security Academy lab
[Bypassing access controls via HTTP/2 request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling).

Objective: reach `/admin` as the `administrator` and delete the user `carlos`.

## The bug in one paragraph

The front-end terminates HTTP/2 and rewrites each request as HTTP/1.1 for the
back-end, but it copies header **names** through without sanitising them. In
HTTP/2 a header name is an opaque byte string, so it can contain `\r\n`; when the
front-end writes that name into the HTTP/1.1 header block the CRLF becomes a real
line break. A single name field can therefore close the header block and inject
complete headers — or a complete second request. The front-end does not reuse
back-end connections, so classic (cross-user) smuggling is impossible here, but
*request tunnelling* still works: the injected request is answered by the
back-end on our own connection, and because the front-end over-reads HEAD
responses by their `content-length`, the tunnelled response is delivered to us
inside the body of our own HTTP/2 response. The back-end trusts three
front-end-appended headers (`X-SSL-VERIFIED`, `X-SSL-CLIENT-CN`,
`X-FRONTEND-KEY`) for client authentication; they are leaked first, then forged.

## Run it

```bash
cd "EXPERT/Bypassing-access-controls-via-HTTP-2-request-tunnelling"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"

# from the repository root, through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

| flag | meaning |
|---|---|
| `--wait S` | how long to poll the solved widget after the delete (default 180 s) |
| `--timeout S` | per-request socket timeout (default 25 s) |

Nothing instance-specific is hardcoded: the host comes from `--url`, the
`X-FRONTEND-KEY` is leaked at runtime, the tunnelled response length is measured
from the front-end's own error, the outer path is picked from content-lengths
probed on the live instance, and the delete URL is read from the tunnelled admin
page (with `/admin/delete?username=carlos` only as a fallback constant from the
lab's objective).

## What it does

0. **Baseline** — `GET /` (HTTP/2) reads the title and the
   `widgetcontainer-lab-status` widget; a control `GET /admin` must return
   **401**, proving the access control is in place. If the instance already says
   solved, the solver says so and exits 0 without claiming the flip.
1. **Leak the auth headers** — `POST /?search=…` with an injected header name
   `x-leak: probe\r\nContent-Length: 120\r\n\r\nsearch=tunnelprobe` and a body
   longer than 120 bytes. The back-end over-reads past its body and pulls the
   front-end's appended headers into the reflected search value, yielding
   `X-SSL-VERIFIED: 0`, `X-SSL-CLIENT-CN: null` and the per-instance
   `X-FRONTEND-KEY`.
2. **Measure the tunnelled response** — tunnel `GET /admin` behind an oversized
   outer `HEAD /`; the front-end answers
   `Server Error: Received only <N> of expected <M> bytes of data`. `N` is the
   exact byte count of the tunnelled HTTP/1.1 response.
3. **Choose the outer path** — HEAD-probe the home page's links (`/login`,
   `/admin`, `/post?postId=…`, `/`) and take the **largest** page whose
   `content-length` is ≤ `N`. That maximises how many tunnelled bytes the
   over-read exposes.
4. **Read `/admin`** — tunnel `GET /admin` with forged auth headers
   (`X-SSL-VERIFIED: 1`, `X-SSL-CLIENT-CN: administrator`, the leaked key) behind
   `HEAD <best path>`. The captured body contains the nested `HTTP/1.1 200 OK`
   admin page with the `carlos` delete link.
5. **Delete `carlos`** — retunnel with
   `GET /admin/delete?username=carlos`. A front-end byte-count error at this
   point is expected: the delete answers `302`, which is shorter than the outer
   page.
6. **Verify** — re-tunnel `/admin` and require an HTTP/1.1 200 page from which
   `carlos` is gone, then poll `GET /` until the widget reads
   `widgetcontainer-lab-status is-solved`. Only that widget (plus the gone user)
   is treated as success.

## Verified behaviour (this instance)

* Baseline widget `is-notsolved`; control `GET /admin` → **401**.
* Leaked `X-FRONTEND-KEY`, `X-SSL-VERIFIED: 0`, `X-SSL-CLIENT-CN: null`.
* Measured tunnelled `/admin`: **3712 bytes**; best outer path `/login`
  (**3351 bytes**), which exposes the whole user table.
* Tunnelled `/admin` → nested `HTTP/1.1 200 OK` with
  `wiener` and `carlos` and `/admin/delete?username=carlos`.
* Tunnelled delete → front-end reports a short read (302 vs 3351), as expected.
* Verification tunnel: admin page returns 200 **without** `carlos`; `GET /` then
  reads `widgetcontainer-lab-status is-solved` / `<p>Solved</p>`.
* End-to-end run: **12.0 s, 21 HTTP requests, exit 0**.
* Re-run through the root launcher: exact folder-name match, exit 0 (already-
  solved path, 1.0 s / 2 requests).

Local artifacts (git-ignored): `evidence/` — baseline page, the 401 control,
the leaked-header reflection, the "Received only N of expected M" measurement,
the tunnelled admin page, the delete attempt, the post-delete admin page, the
solved page, plus `requests.jsonl` and `events.jsonl`.

## Implementation notes

* The lab speaks HTTP/2 but **does not advertise it via ALPN**. The solver
  negotiates `http/1.1` (or nothing) and then sends the HTTP/2 connection preface
  anyway. This is what Burp's *Allow HTTP/2 ALPN override* option exists for.
* Python's `h2` validates outbound header names/values, so the client is built
  with `validate_outbound_headers=False` and `normalize_outbound_headers=False`;
  otherwise the `\r\n` in the name is rejected or the name is lowercased.
* `h2` also enforces `content-length: 0` on inbound HEAD responses. The
  front-end returns the tunnelled bytes as a DATA frame on those streams, so
  `H2Stream._track_content_length` is relaxed for this client — otherwise parsing
  dies with `InvalidBodyLengthError` right when the exploit succeeds.
* Every request uses a fresh TLS connection: the front-end does not reuse
  back-end connections, and tunnelling is a self-contained one-shot exchange.

## Exit codes

0 verified solved (or already solved), 1 exploit ran but not verified, 2 usage or
unreachable/expired instance.
