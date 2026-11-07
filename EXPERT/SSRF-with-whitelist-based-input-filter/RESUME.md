# Resume / checkpoint

## State: COMPLETE

* Lab: SSRF with whitelist-based input filter (EXPERT, per live Academy badge).
* Instance: unsolved at baseline → solved by the delete request documented in
  `evidence/00_baseline_transcript.txt`.
* `solve.py` written, run from the lab folder (exit 0) and through the repo-root
  launcher (exit 0, exact folder-name match).
* Docs written: README, SOLUTION, REPORT, RESUME, LESSONS_LEARNED, SOURCES.
* Evidence: `evidence/` (local, git-ignored), `responses/admin_via_ssrf.html`,
  `requests/`.

## If resuming

1. Confirm the URL still resolves; expired instances answer 404/503 —
   `curl -s -o /dev/null -w '%{http_code}' "$LAB/"`.
2. Run `uv run python solve.py --url "$LAB"`. A fresh instance is unsolved, so
   the run must flip the widget; a solved instance re-proves the mechanism.
3. Nothing is left to implement. Known next step only if PortSwigger tightens the
   filter: add vectors after `bypass_candidates()` (e.g. `%2523` with an explicit
   `..` path, or `localhost%25%32%33`).

## Recorded failures (historical)

* Control POST failed with `"Missing parameter"` when the form body kept literal
  `&` / `=` inside the `stockApi` value and `%` was preserved. Fixed by encoding
  `&`/`=` while keeping `%` literal (`encode_form_value`).
