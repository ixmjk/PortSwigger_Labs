# Report — 0.CL request smuggling

## Lab

* Title: **0.CL request smuggling**
* Difficulty: **EXPERT** (live Academy description page, `lablevel` badge)
* Topic: HTTP request smuggling — advanced, 0.CL desync (HTTP/1.1 Must Die research)
* Objective: Carlos visits `/` every five seconds — execute `alert()` in his browser.

## Instance

* A temporary `*.web-security-academy.net` instance; the host is deliberately not
  recorded in the docs (it is passed with `--url`).
* Baseline captured before any exploit request: `is-notsolved` /
  `<p>Not solved</p>` (`evidence/lab-baseline-notsolved.html`, 8,380 bytes).
* No exploit server on this lab (`GET /exploit` → 404), and `/admin` is 404 from
  the outside; the whole attack is unauthenticated.
* After the double-desync campaign the same URL answered `is-solved` /
  `<p>Solved</p>` plus the congratulations banner
  (`evidence/lab-after-attack-solved.html`).

## Timeline (this session)

| step | what | outcome |
|---|---|---|
| 0 | fresh instance (owner relaunched) run with the packaged solver | widget flipped at ~50-55 s of attack; the then-current status poller missed it and kept attacking until Ctrl-C |
| 1 | `GET /` over HTTP/1.1 | `is-notsolved`, blog homepage, no `Server` header |
| 2 | `/exploit`, `/admin` probes | 404 → no exploit server, no direct admin route |
| 3 | UA reflection on `/post?postId=6` | `<script>` reflected unescaped into a hidden input |
| 4 | `Content-Length : 7` with no body | no response for 5 s → 0.CL deadlock |
| 5 | 20-byte split PoC on one connection | `200` + `400 Bad Request` → desync confirmed |
| 6 | double-desync campaign, 8 threads, separate connections | **widget flipped to solved** (~350 pairs in 45 s) |
| 7 | mechanism experiments on the solved instance | persistent pipelining served the smuggled page back to the attacker (150 pairs/s, ~0.6 hits/s) |
| 8 | `solve.py` written, diagnose-only + full runs | exit 0, primitives re-proven |
| 9 | root launcher run | exit 0, exact folder-name match, 56.2 s total |

## Mechanism

1. `Content-Length : N` (space before colon) is invisible to the front-end parser
   but forwarded verbatim; the back-end parses it. An H-V discrepancy.
2. A body-less request with that header is forwarded immediately while the
   back-end waits for N bytes → upstream deadlock.
3. A server-level redirect answers before the body, breaking the deadlock and
   leaving the connection open (early-response gadget: `/resources/css/<name>`).
4. Stage 2's header block supplies exactly the N bytes the back-end is waiting
   for; the bytes appended after it become pipelined requests from the back-end's
   point of view, so a full `GET /post?postId=N` with the XSS `User-Agent` is
   produced on the shared upstream connection.
5. The front-end's response-to-request pairing is now off by one: whoever is next
   on that connection — Carlos, polling `/` every five seconds — is answered with
   the blog post page (self-XSS becomes real XSS) and `alert(1)` runs.

## Result

| item | value |
|---|---|
| Status | solved (lab's own widget: `is-solved`) |
| Caused by the solver's technique on this instance | yes — baseline unsolved, flipped during the double-desync campaign |
| Campaign that flipped it | queue variant: 8 threads, stage 1 and stage 2 on separate connections, ~350 pairs / ~700 requests / 45 s (first instance) and ~50-55 s (fresh instance) |
| Packaged solver re-run (already-solved instance, demo window) | exit 0 — 345 pairs, 708 requests, 55.8 s, 6 responses carried the smuggled page |
| Requests / time for a normal `--wait 480` run | bounded by the widget poll; typical solve seen in <60 s of attack |
| Launcher from repo root | exit 0, `[EXPERT] 0.CL-request-smuggling` exact match, 4.0 s overhead |
| `tests/test_launcher.py` | 27/27 pass |

## Detection had to be fixed

The first run against a fresh instance flipped the lab at ~50-55 s but the solver
kept attacking to 130 s: its status poller ran *during* the storm, and a
desynchronised front-end answers `GET /` with queued/stale responses — a page
rendered before the flip says `is-notsolved`, and stray 302/400/500 bodies carry
no widget at all. The solver now attacks in ~8 s bursts, pauses, lets the pool
drain ~0.8 s and only then reads the widget (3 attempts, 1.2 s apart). Measured
after the fix on the same (now solved) instance with `--force`: `widget=SOLVED`
at the first cycle boundary, 16-18 s wall clock, exit 0. Ctrl-C is also handled: it
stops the workers, verifies the widget and reports instead of raising.

## Why the solver has several variants

* `queue` (default) — stage 1 / stage 2 on separate client connections. This is
  the configuration that flipped the instance: the front-end's shared upstream
  pool lets a queued/smuggled response be paired with *another* client's request.
* `pipe` — persistent pipelined connections. Not the delivery vector by itself
  (the smuggled page comes back to the attacker) but ~20× faster at poisoning
  connections and the only variant that shows the smuggled page in-band on our
  own requests; used as an evidence channel.
* `absorb` — smuggled request cut mid-header so the victim's own request bytes
  complete it (the whitepaper's absorption shape).
* `sameconn` — all three frames on one connection, useful to observe the
  response-queue shift (`302`, `404`, `200`) deterministically.

## Limitations / honest notes

* Academy instances stay solved once flipped, and a fresh instance can only be
  launched from the owner's logged-in dashboard — so the flip could not be
  repeated from a cold baseline in this session. The packaged `queue` variant is
  byte-for-byte the request pair that flipped this instance; the solve is
  probabilistic (the poisoned connection has to be the one Carlos's poll lands
  on), which is why the default window is 480 s.
* The attack leaves the front-end answering oddly for ~10 s afterwards (stray
  responses, the odd 400/500); the solver therefore retries baseline, gadget and
  final status reads instead of trusting a single request.
* `HEAD /` returns 404 on these instances while `GET /` works — not an expiry.
