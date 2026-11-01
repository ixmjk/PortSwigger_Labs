# LESSONS LEARNED — 2FA bypass using a brute-force attack

Rules distilled from this lab. Generalizable ones also live in the
`portswigger-weblabs` Hermes skill.

## Success criteria

1. **Only `302 → /my-account` is success.** A dying session answers `302 → /login`. Accepting
   "any 302 that isn't /login2" produced a false positive that burned a 170 s run.
   Generalise: never define success as "not the failure page"; define it as the *positive*
   terminal state.
2. **Verify in the session that succeeded.** For 2FA labs the code is typically single use:
   re-logging in with the recovered code returns "Incorrect security code". The proof of
   access is `GET /my-account` on the authenticated session — which is also what the lab
   scores. A "verify by logging in again" helper is a trap for one-shot credentials.

## Parallel brute-force engineering

3. **Reset per-pass state.** `self.found`/`solved` events persisting across passes made
   passes 3-5 "succeed" in 2 s with a stale code. Clear them at the start of each pass, and
   have workers exit on the event rather than looping.
4. **Re-queue only codes the server never evaluated.** A `500 "No user logged in"` (or a
   `400` csrf error) means that guess never ran, so the code must be retried; a `200
   "Incorrect"` means it ran. Counting a dead-session guess as tested silently skips
   codes — with a 10k space and ~50% cycle loss, that is a guaranteed miss.
5. **The attempt budget can be account-scoped, not session-scoped.** With N parallel
   sessions on one account, roughly half of second guesses die at `500` because another
   worker consumed the shared budget between our login and our POST. Budget accordingly:
   ~1.4-1.5 usable guesses per 5-request cycle, not 2.
6. **Measure per-request cost before choosing worker counts.** One 5-request cycle was
   ~0.72 s sequential; 12 workers gave 88 req/s with zero anomalies, 24 gave 133 req/s with
   occasional ConnectError/ReadTimeout. Pick concurrency from measurement, and keep a
   shared adaptive circuit breaker (3 s → 45 s) so one degraded worker cannot stall the run.
7. **`curl` per request is a bad load generator here** (~350 ms TLS/process overhead per
   call, 1.9 s per cycle vs 0.72 s with a keep-alive HTTP/2 client). Use one client per
   worker with connection reuse.
8. **Concurrency cannot beat an atomic counter.** 20 simultaneous POSTs with one valid csrf
   yielded exactly 2 processed responses: the "2 attempts per session" limit is enforced
   atomically server-side. Do not design around that race.

## Reconnaissance

9. **Dump the real form.** The field was `mfa-code` (not `verificationCode`), and each page
   render issues a *new* csrf that only that page's endpoint accepts — reusing the `/login`
   token on `/login2` gives `400`.
10. **Cheap bypasses first.** OneFA-session `/my-account`, csrf omission, array-typed
    parameters — 12 requests total to rule out the shortcuts before committing to a
    36,000-request sweep.
11. **Code rotation is part of the lab, not a bug.** A complete 10,000-code pass with no
    hit happened here; the very next pass hit within 8 s. Always wrap the sweep in a
    pass loop before concluding anything is wrong.
12. **Report throughput, not progress counters.** `remaining≈N` drifts upward when codes
    are re-queued; the honest metrics are distinct guesses, requests, cycles and elapsed
    time.
