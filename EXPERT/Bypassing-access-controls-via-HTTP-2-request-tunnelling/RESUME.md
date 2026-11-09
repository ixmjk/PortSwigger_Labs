# Resume / checkpoint

## State: SOLVED end-to-end by the packaged solver

* Lab: **Bypassing access controls via HTTP/2 request tunnelling** (EXPERT, live
  badge read from the Academy description page).
* Instance started `is-notsolved`; the solver leaked the front-end key, tunnelled
  `GET /admin`, deleted `carlos`, and the widget flipped to `is-solved`.
  * Serialized run: **12.0 s, 21 requests, exit 0**, `caused by solver: yes`.
  * Verification: tunnelled `/admin` returns `HTTP/1.1 200` with only `wiener`;
    `evidence/after-solved.html` carries
    `widgetcontainer-lab-status is-solved` / `<p>Solved</p>`.
* Root launcher (`uv run python solve.py --url <lab>`) matched the folder
  **exactly** and exited 0 on the now-solved instance (1.0 s / 2 requests,
  "already reports the lab as solved"). `tests/test_launcher.py`: 27/27 pass.
* Root README badges, coverage sentence, and table row updated (22 / 274).

## Re-running

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

A fresh instance shows the full chain: baseline → 401 control → leak → length
measurement → outer-path selection → tunnelled `/admin` → tunnelled delete →
verification + widget poll. On an already-solved instance the solver stops after
the baseline/control pair (2 requests) and reports that the instance was already
solved, without claiming the flip.

## If resuming / debugging

1. Liveness: `curl -sS -o /dev/null -w '%{http_code}' "$LAB/"` → 200.
   (`HEAD /` over plain HTTP returns 404 on these instances — use GET.)
2. Header-name injection sanity check: one `GET /` with the header name
   `foo: bar\r\nHost: abc` must answer
   `Server Error: Gateway Timeout (3) connecting to abc`.
3. Leak sanity check: `POST /?search=x` with the injected
   `Content-Length: 120` plus a 100-byte body must reflect
   `X-FRONTEND-KEY: <digits>`.
4. If the tunnelled `/admin` read returns no `HTTP/1.1 200`, the outer
   `content-length` is larger than the tunnelled response: read the
   `Received only N of expected M` error first and pick a path whose
   content-length is ≤ N.
5. If the lab is already solved, `GET /` answers
   `widgetcontainer-lab-status is-solved`; relaunch a fresh instance from the
   Academy account for a true end-to-end flip.

## Local, git-ignored artifacts

* `evidence/` — baseline, 401 control, leaked headers, length measurement,
  tunnelled admin page, delete attempt, post-delete admin page, solved page,
  `requests.jsonl`, `events.jsonl`.
* `evidence/events.jsonl` contains both runs: the failed first packaged run (bad
  key regex) and the successful second run.
* `logs/` — reserved for future run transcripts (none required; terminal output
  of the verified run is quoted in `REPORT.md`).
* No `experiments/` or `scripts/` files were needed: the two probes were run from
  the session scratch directory, and their results are reproduced in
  `SOLUTION.md` and `REPORT.md`.
