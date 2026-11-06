# RESUME — Reflected XSS with AngularJS sandbox escape and CSP

## Checkpoint (2026-11-06)

**State: SOLVED and verified.** All work is complete; nothing is pending
except the user's independent test and commit approval.

* Lab instance used for the verified run: expired/finished, instance-specific
  host intentionally not recorded here (relaunch from the Academy account to
  re-test).
* Solver: `EXPERT/Reflected-XSS-with-AngularJS-sandbox-escape-and-CSP/solve.py`
* Verified twice: from the lab folder (exit 0, 9 requests, 4.2 s, fresh
  instance, baseline `not solved` → `is-solved`) and from the repo root through
  `solve.py` (launcher reported `exact folder-name match`, exit 0).
* `uv run python tests/test_launcher.py`: 27 passed, 0 failed.

## What was tried and what worked

| Attempt | Result |
|---|---|
| Static recon with `curl` — headers, title, reflection context | Found AngularJS 1.4.4, `ng-app ng-csp`, CSP `script-src 'self'`, reflection in `<h1>` |
| Vector requiring an inline handler (`<img onerror>`) | Rejected on paper: CSP `script-src 'self'` has no `unsafe-inline`, handlers never run |
| Angular filter-argument sandbox escape (`$event.composedPath()|orderBy:'(z=alert)(document.cookie)'`) with `#x` fragment focus | Solved (this is the delivered vector) |
| Access-log POST after solving | Works, but re-stores the body; the solver re-sends the identical body so the stored exploit is unchanged |

## Continuation steps (only needed if re-testing on a new instance)

1. Launch the lab again from the logged-in Academy account (anonymous visitors
   cannot spawn instances).
2. Run:
   `cd /root/Desktop/PortSwigger_Labs && uv run python solve.py --url "<fresh URL>"`
3. Confirm exit 0 and the widget text `Solved`; if the new instance ships
   AngularJS ≥ 1.6 the solver exits 2 by design (no sandbox → wrong vector).
4. If a URL expires mid-run: the solver returns 3 and keeps its artefacts under
   `evidence/`; request a fresh URL for the same lab, do not switch targets.

## Known limits

* `$event.composedPath()` is Chrome-only; the lab's victim bot is Chrome, so
  this is the intended vector. A Firefox victim would need `$event.path`
  (deprecated) and this solver would not flip the widget.
* The victim queue can delay delivery by minutes; the default `--wait 300` is
  generous for that reason, although this instance flipped in < 1 s.
