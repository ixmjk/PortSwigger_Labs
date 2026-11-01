# RESUME — 2FA bypass using a brute-force attack

**Status: COMPLETE / SOLVED.** Kept for continuity if the work is ever reopened.

## Checkpoint

* Lab title: `2FA bypass using a brute-force attack` (Expert, Authentication / multi-factor)
* Instance used: whatever `--url` points at. The host used during the solved run has
  expired; a fresh instance needs no solver changes — only `--url`.
* Solved: yes. Recovered code `1434`. Lab widget `is-solved`; `/my-account` showed
  `Your username is: carlos`.
* Verified independently with curl, not only through the solver.

## What is done

| item | state |
|---|---|
| flow mapped (`/login` → 302 `/login2` → 2 guesses) | done |
| throttle characterised (2 failures per session, then 500/400) | done |
| bypass attempts (1FA session, csrf tricks, array param, 20x concurrent POSTs) | done, all rejected |
| capacity measured (12 vs 24 workers) | done |
| `solve.py` (parallel sweep, re-queue, verification) | done, exit 0 verified |
| global launcher match (`exact folder-name match`) + run | done, exit 0 |
| docs: README / SOLUTION / REPORT / LESSONS / SOURCES | done |
| root README lab list + badges | pending update in this session |

## Gotchas to remember if this is re-run

1. Success is `302` **with `/my-account` in `Location`**. Any other 302 (notably `→ /login`
   when a session dies) is a false positive. This cost one wasted 170-second run.
2. Verify inside the winning session (`GET /my-account`). The code is **single use** —
   re-logging in with it returns "Incorrect security code".
3. Clear per-pass state (`self.found`, `solved` event) at the start of every pass, or
   passes 3+ "succeed" instantly with a stale value.
4. The code rotates during a sweep: a full 10,000-code pass with no hit is normal; the
   solver repeats passes automatically (`--max-passes`).
5. ~50% of cycles lose their second guess to the shared account-level attempt counter.
   Re-queue that code instead of counting it as tested.

## Exact continuation commands

```bash
cd "/root/Desktop/PortSwigger_Labs/EXPERT/2FA-bypass-using-a-brute-force-attack"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net" --workers 24

# through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

If the instance has expired the launcher prints `lab unavailable (HTTP 4xx/5xx)` and the
solver exits `3`. Ask for a fresh URL; do not restart the investigation.

## Artifacts

* `solve.py` — solver (also the reusable artifact)
* `experiments/probe_cycle.py` — single-cycle latency probe
* `experiments/probe_conc.py` — worker-count / failure-mode probe
* `logs/run1.log`, `logs/run2.log`, `logs/run3.log` — all attack runs, including failures
* `responses/` — raw throttle-mapping responses; `requests/curl_flow.sh` — exact requests
* `evidence/my-account.html`, `evidence/lab-home-solved.html` — proof
