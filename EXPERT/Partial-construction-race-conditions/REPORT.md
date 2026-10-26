# REPORT — Partial construction race conditions (EXPERT)

## Objective

Solve the PortSwigger lab by abusing a race condition in the user-registration
flow to obtain an account with an unverified `@ginandjuice.shop` address, then
log in, reach the admin panel and delete `carlos`. Rebuild the manual exploit
into a reusable automated solver (`uv run python solve.py --url ...`).

## Instance

| Instance | URL | Result |
|---|---|---|
| #1 | `https://0a20006e045183128050ad0100900007.web-security-academy.net/` | **SOLVED** 2026-10-26 (manual race + solver re-runs) |

Lab title from the page: `Partial construction race conditions`; the app is PHP
(`phpsessionid` cookie).

## Recon findings

- `POST /register` takes `csrf`, `username`, `email`, `password`.
  Non-`@ginandjuice.shop` addresses are rejected; a valid one returns
  `200` + *"Please check your emails for your account registration link"*.
- `GET /resources/static/users.js` shows the confirmation flow is a
  `POST` to `/confirm?<query>` built from the URL, i.e. the token travels in the
  **query string**.
- Unconfirmed accounts cannot log in (`Invalid username or password`), which is
  what makes the confirmation step the gate to bypass.
- `/confirm` token parsing (probe `experiments/probe_01.py`, raw output in
  `responses/confirm_token_variants.txt`):

  | Request | Status | Body |
  |---|---|---|
  | `/confirm` | 400 | `Missing parameter: token` |
  | `/confirm?token=` | 403 | `Forbidden` |
  | `/confirm?token=bogus` | 400 | `Incorrect token: bogus` |
  | `/confirm?token[]=` | 400 | `Incorrect token: Array` |

  The array form is *processed*, not rejected — the prerequisite for the
  type-juggling half of the exploit.

## Exploitation

Mechanism: the registration handler inserts the user row first and writes the
confirmation token afterwards. In that gap the stored token is `NULL`, and
PHP's loose `==` makes `[] == null` true, so `POST /confirm?token[]=` confirms
the half-constructed row.

First prototype (`experiments/race_01.py`): 15 attempts, one confirm thread of
40 requests per attempt, 5 attempts in parallel, flood started 50 ms before the
registration. Result: **2 confirmations returned `200`** (HTTP `200` on the
`/confirm` endpoint) and accounts `rc2`/`rc3` logged in with `302 → /my-account`.
Deleting `carlos` flipped the lab to solved (`experiments/followup_01.py`).

Throughput measurement (`experiments/bench_latency.py`): a single `/confirm`
costs **~440 ms** server-side, so throughput is entirely concurrency-bound —
16 client threads yielded ~35 req/s, 4 threads only ~7 req/s. That is why the
first prototype needed 24 s per batch.

Final solver design: 6 confirm-flood threads per attempt, 8 attempts per batch,
and an early-exit event that abandons the rest of the flood as soon as any
confirmation succeeds.

## Verified completion

`logs/solve_final_verified.log` (run with `--force` on the already-solved
instance, to exercise the full exploit path):

```
[   0.9s] prepared 16 registration sessions
[   2.1s]   [+] /confirm returned 200 (race hit)
   ... (5 hits)
[  11.6s] batch 0: 5 confirmed of 8 (total requests 146)
[  11.6s] confirmed account: rcgtymwg1
[  12.1s] logged in as rcgtymwg1: HTTP 200, admin=True
[  12.5s] GET /admin/delete?username=carlos -> HTTP 302
[  12.9s] admin user list no longer contains carlos: True
[  13.4s] lab status check: solved=True
```

Run summary: **solved=true, requests=150, elapsed=13.37 s, confirm hits=5**.

Independent verification (`responses/status_final.html`, plain `curl`):

```
widgetcontainer-lab-status is-solved
<p>Solved</p>
```

Earlier runs on the same instance (same code path, `--force`):

| Run | Hits | Confirmed accounts | Requests | Elapsed |
|---|---|---|---|---|
| 1 (initial params `--attempts 15 --confirms 40 --parallel 5`) | 2 | rc2, rc3 | 645 | 75.4 s |
| 2 (`--attempts 14 --confirms 40 --parallel 4`) | 1 | 1 | 535 | 68.9 s |
| 3 (defaults, early exit) | 2 | 2 | 140 | 13.1 s |
| 4 (defaults, final verified run) | 5 | 5 | 150 | 13.4 s |

## Reusability

- No hardcoded host, session id, CSRF token or username: host ← `--url`, CSRF
  and cookies fetched per attempt, usernames carry a random 6-char nonce per
  run.
- Only lab-definition constants remain (`/register`, `/confirm?token[]=`,
  `/admin/delete`, `carlos`, `@ginandjuice.shop`, status-widget markers).
- Global launcher verified: title `Partial construction race conditions` maps
  to the folder `EXPERT/Partial-construction-race-conditions` as an **exact
  folder-name match**; launcher exit code `0`.

## Notes / limits

- The exploit is stochastic: each attempt has roughly a 10–60 % chance of
  landing, so the solver retries up to `--max-batches` runs with fresh nonces.
- Accounts created during a successful run stay behind on the instance; they
  are harmless (`rc<nonce><n>@ginandjuice.shop`).
- The instance is left solved; subsequent runs short-circuit at
  "lab already shows as solved" unless `--force` is given.
