# Resume / checkpoint

## State: COMPLETE (fresh-instance run done)

* Lab: **0.CL request smuggling** (EXPERT, live badge).
* Instance: unsolved at baseline → **flipped to solved** by the double-desync
  campaign documented here (`evidence/lab-baseline-notsolved.html` →
  `evidence/lab-after-attack-solved.html`).
* `solve.py` written and run: `--diagnose-only` (primitives proven) and full runs
  (exit 0 on the solved instance, 345 pairs / 708 requests / 55.8 s).
* Root launcher: exit 0, exact folder-name match `[EXPERT] 0.CL-request-smuggling`,
  56.2 s total including launch overhead. `tests/test_launcher.py` 27/27.
* Docs: README, SOLUTION, REPORT, RESUME, LESSONS_LEARNED, SOURCES.
* Evidence (local, git-ignored): `evidence/`, `logs/run-*.json`.

## Fresh-instance run (done)

A relaunched instance was attacked with the packaged solver: the widget flipped
after ~50-55 s. The run also exposed a *detection* bug — the old poller read the
widget while the front-end was saturated with queued/stale responses and never
saw `is-solved`, so it kept attacking until Ctrl-C. Fixed by burst/pause
polling; re-tested with `--force` on the then-solved instance (widget=SOLVED at
the first cycle boundary, 18 s, exit 0).

## If resuming

1. Check the URL is alive: `curl -s -o /dev/null -w '%{http_code}' "$LAB/"`.
   `HEAD /` answers 404 on these instances; use `GET`.
2. `uv run python solve.py --url "$LAB" --diagnose-only` — must print
   `deadlock=True` and `UA reflection: confirmed`.
3. `uv run python solve.py --url "$LAB"` — on a fresh instance this attacks until
   the widget reports solved (exit 0).
4. If it does not flip in 480 s, raise `--threads 12` and retry; keep the
   `queue` variant first. The failure mode to watch for is the whole front-end
   answering stray responses — back off 15 s and re-run so the pool recovers.

## Recorded failures / dead ends

* `Content-Length : 7` with no body and no gadget → silence (deadlock). Expected;
  do not read it as a broken instance.
* A *complete* smuggled request inside the OPTIONS body is produced immediately
  and consumed by the attacker's own next request (persistent variant), so it
  does not reliably reach the victim — that is why the default uses separate
  connections and many repetitions.
* Truncating the smuggled request mid-header (`absorb`) never showed an in-band
  hit on the tested instance; kept as a fallback only.
* Closing an attack socket immediately after `sendall` (RST with unread data)
  kills the desync; the solver drains ~180 ms before closing.
* `/resources/images/blog.svg` started answering 400 while the instance was
  heavily desynced. The gadget prober therefore retries and accepts any of
  `/resources/{css,js}/<anything>`.
