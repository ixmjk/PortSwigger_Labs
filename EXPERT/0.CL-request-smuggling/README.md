# 0.CL request smuggling — Expert

Automated solver for the PortSwigger Web Security Academy lab
[0.CL request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling).

## The bug in one paragraph

The front-end does not recognise `Content-Length` when it is obfuscated with a
space before the colon (`Content-Length : N`) and forwards the header verbatim,
while the back-end parses it. That Hidden-Visible discrepancy is a **0.CL
desync**. A request carrying only the obfuscated header leaves the upstream
connection deadlocked (the back-end waits for N body bytes); a server-level
redirect (`/resources/css/<anything>` → 302) answers before the body arrives and
breaks the deadlock while keeping the connection open. A second request whose
header block is exactly N bytes is then eaten as stage 1's body, and the bytes
appended after it are parsed by the back-end as a pipelined request — a blog post
page whose `User-Agent` carries `x"><script>alert(1)</script>`. The post page
reflects `User-Agent` unescaped into a hidden input, so the script runs in the
browser that receives the poisoned response. Carlos polls `/` every five
seconds; he is served the smuggled page and the lab's widget flips.

## Run it

```bash
cd "EXPERT/0.CL-request-smuggling"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"

# from the repository root, through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

Options

| flag | meaning |
|---|---|
| `--wait S` | attack window while unsolved (default 480 s; Carlos polls every 5 s) |
| `--threads N` | attacker threads (default 8) |
| `--variants a,b` | subset of `queue` (default), `pipe`, `absorb`, `sameconn` |
| `--diagnose-only` | prove the 0.CL primitives and stop without attacking |
| `--force` | attack even when the baseline widget already says solved (re-verification) |
| `--demo S` | attack seconds when the instance is already solved (default 20) |
| `--evidence DIR` | evidence directory (default `evidence/`) |

Nothing instance-specific is hardcoded: host and port come from `--url`, the
post id is scraped from the homepage, the early-response gadget is probed, and
no session cookie, CSRF token or exploit-server URL is needed.

## What it does

1. **Baseline** — `GET /`, reads `widgetcontainer-lab-status` from the lab's own
   header (retried: a desynced front-end can answer with a stray response).
2. **Discovery** — scrapes a `/post?postId=N` id from the homepage and confirms
   the `User-Agent` reflection is unescaped (`<script>` survives in the HTML).
3. **Gadget** — probes `/resources/css/anything`, `/resources/images/blog.svg`,
   `/resources/js/anything` for a server-level 3xx (early-response gadget).
4. **Proof** — shows the 0.CL deadlock (`Content-Length : 20`, no body → no
   response at all) and the pipelined-bytes anomaly.
5. **Attack** — the double-desync pair, replayed concurrently until the widget
   reports solved, or `--wait` expires.
6. **Verify** — the lab's own status widget is the only success oracle; HTTP
   200/302/404 never counts. Exit code 0 only on a solved widget.

## Verification recorded for this lab

| check | result |
|---|---|
| Baseline on the first instance | `is-notsolved` / `<p>Not solved</p>` |
| After the double-desync campaign (8 threads, ~350 pairs in 45 s) | `is-solved` / `<p>Solved</p>` |
| Fresh instance, packaged solver | widget flipped after ~50-55 s of attack (browser check) |
| Detection after the burst/pause fix (`--force` on the then-solved instance) | `widget=SOLVED` at the first cycle boundary (16-18 s), exit 0 |
| Packaged solver on a solved instance | exit 0, `caused by solver: no (was already solved)` |
| Launcher from repo root | exit 0, `exact folder-name match` (`[EXPERT] 0.CL-request-smuggling`) |
| Launcher test suite | 27/27 pass |

The first fresh-instance run exposed a detection bug, not an attack bug: with
traffic running continuously the front-end's pool is full of stale/queued
responses, so `GET /` frequently returned a page rendered *before* the flip and
the solver kept attacking after the lab was already solved. The solver now
attacks in ~8 s bursts and reads the widget in the pause; the flip is picked up
within one cycle (measured: 16-18 s from process start).

## Files

* `solve.py` — the solver (raw TLS HTTP/1.1, threads, no third-party deps).
* `SOLUTION.md` — reproducible request-by-request walkthrough.
* `REPORT.md` — case study: instance, timeline, mechanism, results, limits.
* `RESUME.md` — checkpoint and continuation notes.
* `LESSONS_LEARNED.md` — generalisable lessons.
* `SOURCES.md` — lab, whitepaper and write-up references.
* `evidence/`, `logs/` — local artefacts (git-ignored).
