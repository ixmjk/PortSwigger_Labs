# Stealing OAuth access tokens via a proxy page

**Difficulty:** Expert
**Status:** Verified solved on a live Academy instance (administrator API key accepted, `LAB Solved` widget).
**Objective:** Steal the administrator's OAuth access token, read their API key from the OAuth server, and submit it.

Run from this directory:

```bash
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"
```

The solver verifies the page title, discovers the exploit server, the OAuth server, `client_id` and
`scope` from `/social-login`, proves that the `redirect_uri` path-traversal is accepted, stores a
freshly-generated payload (new `nonce` each run) on the exploit server, delivers it to the victim,
harvests the leaked token from the exploit server's access log, resolves it against the OAuth
server's `/me`, and only exits `0` after `POST /submitSolution` returns `{"correct":true}` **and**
the lab page reports `widgetcontainer-lab-status is-solved`.

Useful flags:

| Flag | Purpose |
|---|---|
| `--force` | Re-run the exploit even if the lab already reports solved. |
| `--exploit-url URL` | Supply the exploit-server URL explicitly (a solved lab hides its banner link). |
| `--attempts N` | Delivery attempts (default 3, each with a fresh nonce). |
| `--self-test` | Offline checks of the access-log parser; no network access. |
| `--no-evidence` | Do not persist request/response dumps. |

Nothing instance-specific is hardcoded: hosts, `client_id`, nonce, token, API key and sessions are
all discovered at runtime. Per-run request/response dumps, the leaked access log, timings and the
summary live under `requests/`, `responses/`, `evidence/` and `logs/` — private, instance-specific
material that stays out of Git.

See [SOLUTION.md](SOLUTION.md) for the short reproduction path, [REPORT.md](REPORT.md) for the
investigation, [RESUME.md](RESUME.md) for checkpoints, and
[LESSONS_LEARNED.md](LESSONS_LEARNED.md) for reusable findings.
