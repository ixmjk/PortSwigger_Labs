# LESSONS LEARNED

## Technique (pause-based CL.0 desync)
1. **Mechanism**: send request headers promising a body (`Content-Length: L`),
   pause longer than the back-end's read timeout (~60 s) but shorter than the
   front-end's (~120 s). The back-end treats the partial request as complete
   (CL.0-like), self-generates a response on server-level-redirect endpoints
   (e.g. `/resources` → 302), and keeps the connection open. The bytes sent
   after the pause are "body" to the front-end (its per-request path blocks
   never fire) but a **new request** to the back-end.
2. **Front-end response pairing**: back-end responses are paired with client
   requests in order. A smuggled request's response is delivered in the slot of
   the *next* client request → always queue a **sacrificial follow-up request**
   to observe smuggled responses in-band (without it they are held undelivered).
3. **Don't trust walkthroughs blindly**: the 2023 walkthrough's CL.0 variant
   403s on the current lab front-end (the `/admin` block is now applied per
   request). Nonzero-CL body smuggle is required. Verify behavior empirically.
4. **Per-instance CSRF**: admin token is random per instance — harvest it
   (smuggled `GET /admin/` with `Host: localhost`), never reuse a published token
   (invalid token → `400 "Invalid CSRF token"`).
5. **Fingerprints**: `X-Frame-Options: SAMEORIGIN` present = app-generated
   response; absent = Apache error-path/self-generated (timeout redirect) — a
   clean desync indicator. Front-end 400 `{"error":"Read timeout"}` + close =
   pause exceeded front-end timeout.
6. **Timeout window**: measure empirically with parallel connections at several
   pause values; the response fingerprint (XFO presence) reveals which side
   timed out.

## Tooling
7. **Raw-socket Python == Turbo Intruder**: `ssl` socket with
   `set_alpn_protocols(["http/1.1"])`, exact `sendall` sequencing + `time.sleep`
   gives full pause-mid-request control with zero dependencies.
8. **Parallel pause sweeps** keep wall-time ≈ the longest pause in the sweep;
   run recon probes in parallel threads too.
9. **uv workflow**: zero-dep `pyproject.toml` → `uv lock` →
   `uv run python solve.py ...` works offline and is fully reproducible.
10. **Count what you send**: track logical HTTP requests and bytes per
    connection; make sure every phase (recon, harvest, delete, verify) feeds
    the counters — harvest stats were initially missed (fixed).

## Lab infrastructure realities
11. **Lab instances are ephemeral**: PortSwigger reclaims them (often shortly
    after solving) → `504 Gateway Timeout`. Consequences:
    - verify immediately after the state change and save the evidence page;
    - fail fast on 502/504 (don't burn minutes on pause sweeps of a dead lab);
    - don't rely on re-running against an old URL later.
12. The first `GET /` on a cold connection can take ~10 s (DNS+TLS) — not an
    error; don't set recon timeouts below that.
13. The front-end 302-redirects essentially any path to `path/` (mod_dir-style),
    so redirect-endpoint discovery returns many candidates; any of them works
    as the desync anchor.
14. Occasional `ConnectionRefusedError` on individual recon probes is transient
    and harmless (log and continue).

## Process
15. Map behavior before exploiting: cheap parallel probe batteries (several
    connections × different pauses) beat long single-shot experiments.
16. Preserve everything continuously (raw bytes of every request/response,
    per-run `report.json`, tee'd logs) — the solver run itself is the evidence.
17. Keep `RESUME.md` current with exact redo commands for fresh URLs; keep
    instance-specific details out of reusable skills (portswigger-weblabs skill
    holds only generalizable technique).

## Robustness / wrong-lab guard
18. **Fail-fast on wrong-lab**: the solver now aborts (~0.4 s, 1 request) when the page
    title doesn't match the lab it targets — e.g. running the pause-based solver against a
    "Combining web cache poisoning" instance. Previously it only warned and burned
    ~5.5 min / 48 requests sweeping pauses on a lab with no pause-based setup before
    failing at CSRF harvest. Guard: `if "pause-based" not in title: report_fail(); return 1`,
    overridable with `--allow-mismatch`. Verified against a live wrong-lab instance —
    default aborts in 0.4 s; `--allow-mismatch` continues. Evidence: `evidence/run_20261024_015320/`.
19. **Match solver to lab**: before running a lab, confirm the page `<title>` is the lab the
    solver targets. A wrong-lab run is the most common silent time-waster; a title check at
    recon (before any expensive sweep) catches it for ~1 request.
