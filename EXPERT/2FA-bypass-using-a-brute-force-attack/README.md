# 2FA bypass using a brute-force attack — automated solver (Expert)

PortSwigger Web Security Academy → **Authentication** → *2FA bypass using a brute-force attack*.

The MFA check at `POST /login2` validates a 4-digit code with no rate limit and no
account lockout. The only throttle is **session scoped**: after two wrong codes the
session is destroyed, so an attacker gets **two guesses per authenticated session**.
Sweeping 0000–9999 with a pool of throw-away sessions recovers the code and lands on
Carlos's account page.

## Quick start

```bash
cd "/root/Desktop/PortSwigger_Labs/EXPERT/2FA-bypass-using-a-brute-force-attack"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"

# or through the universal launcher, from the repo root
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

Nothing instance-specific is baked in: the base URL comes from `--url`, CSRF tokens and
cookies are read from live responses, and every run starts from an empty cookie jar.

## Result on the reference run

| metric | value |
|---|---|
| outcome | **solved** (lab widget `is-solved` *and* `/my-account` returning `Your username is: carlos`) |
| recovered code | `1434` |
| guesses | 10,966 (10,000 distinct + re-queued ones) |
| HTTP requests | 36,390 |
| login cycles | 7,280 |
| wall clock | **289.6 s** (~4 min 50 s) |
| throughput | ~38 guesses/s, ~126 req/s at 24 workers |

Pass 1 covered all 9,992 code slots without a hit — the server rotated the code mid-sweep,
exactly as the lab brief warns. Pass 2 hit at `1434`.

## How it works

One worker cycle = 5 requests = 2 guesses:

```
GET  /login                 -> csrf
POST /login                 -> 302 /login2       (username+password accepted)
GET  /login2                -> csrf2
POST /login2  code A        -> 200 "Incorrect security code" + fresh csrf
POST /login2  code B        -> 302 /my-account   <- success
```

* Codes come from a lock-protected shared queue (`0000`–`9999`, shuffled each pass), so
  parallel workers never test the same code twice.
* A `500 "No user logged in"` / `400 invalid csrf` on a guess means the session's two
  attempts were already spent (often by *another* worker, because the account-level
  counter is shared). That code was never evaluated, so it is pushed back onto the queue.
* Success requires `302` whose `Location` contains `/my-account`. **Any other 302**
  (e.g. `→ /login` after a session died) must not be treated as a win — that mistake
  produced two false positives during development.
* The winning worker immediately reads `/my-account` **on the same session**. That is the
  lab's real completion condition. Re-logging-in to "verify" fails: the code is single
  use and rotates on success.
* Failures of the lab instance itself (connect errors, read timeouts, 502/503/504) feed a
  shared adaptive circuit breaker: escalating pauses (3 s → 45 s) for all workers instead
  of hammering a degrading instance.

## Options

| flag | default | meaning |
|---|---|---|
| `--url` | – | lab base URL (required) |
| `--workers` | 20 | parallel login sessions |
| `--max-passes` | 8 | full 0000–9999 sweeps (the code rotates mid-attack) |
| `--timeout` | 20 | per-request timeout, seconds |
| `--verbose` | off | log rejected redirects and cycle errors |
| `--force` | off | re-run even when the lab already shows solved |

## Exit codes

| code | meaning |
|---|---|
| `0` | verified solved (status widget flipped **and** Carlos's account page read) |
| `1` | sweeps finished without a verified hit |
| `2` | usage / environment problem |
| `3` | lab unreachable or expired |

## Evidence

`evidence/my-account.html` (Carlos's page from the winning session) and
`evidence/lab-home-solved.html` (status widget `is-solved`) are produced by the solver
and the manual check respectively. Both are git-ignored research artifacts.
