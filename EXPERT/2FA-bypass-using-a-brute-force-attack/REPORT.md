# REPORT — 2FA bypass using a brute-force attack (Expert)

**Target:** `https://<lab-id>.web-security-academy.net` (2FA bypass using a brute-force attack)
**Credentials issued:** `carlos:montoya`
**Result:** solved — lab widget `is-solved`, `/my-account` served `Your username is: carlos`.
**Recovered code:** `1434`
**Cost:** 10,966 guesses · 36,390 HTTP requests · 7,280 login cycles · **289.6 s** (~38 guesses/s, ~126 req/s, 24 workers).

---

## 1. Objective

Reach Carlos's account page without access to his 2FA code by brute-forcing it.

## 2. Reconnaissance

### 2.1 Login flow

```
GET  /login     -> 200, <form action="/login"> with hidden csrf
POST /login     -> 302 Location: /login2   (credentials accepted, 1FA complete)
GET  /login2    -> 200, <form method=POST> hidden csrf + <input name=mfa-code>
POST /login2    -> 302 /my-account on the correct code
```

Field name confirmed by dumping the form: **`mfa-code`**, plus a per-page `csrf`.
The `/login2` page's token is distinct from the `/login` page's token, and a token from
one page is *not* accepted by the other (`400 "Invalid CSRF token (session does not
contain a CSRF token)"`).

### 2.2 Throttle mapping (the key discovery)

Single session, four consecutive guesses:

| attempt | response |
|---|---|
| 1 (`1111`) | `200` + "Incorrect security code" + fresh csrf |
| 2 (`1112`) | `200` + "Incorrect security code" + fresh csrf |
| 3 (`1113`) | **`500` "No user logged in"** |
| 4 (`1114`) | `400` (session and its csrf are gone) |

So: **two code guesses per authenticated session**, no rate limit, no lockout, no delay.
Re-login restores two more guesses. Nothing about IP address matters (verified indirectly —
all traffic came from one IP and the only failure mode was the per-account/per-session
attempt budget, never a throttle status).

### 2.3 Cheap bypasses rejected

* `GET /my-account` with a 1FA-only session → `302 /login` (must complete 2FA).
* `POST /login` without csrf, or with a foreign csrf → `400 invalid CSRF token`.
* `mfa-code[]=1` (array) → `400`.
* Parallel guesses on one session: 20 simultaneous POSTs with a single valid csrf →
  exactly **2** processed (`200`), 17 `400`, 1 dropped. The attempt counter is enforced
  atomically; concurrency does not multiply the budget.

### 2.4 Capacity measurement

`experiments/probe_cycle.py` (single sequential client, HTTP/2 keep-alive):

```
GET /login 0.08-0.49s | POST /login 0.19s | GET /login2 0.08s | POST /login2 0.19s
=> one 5-request cycle ≈ 0.72 s ≈ 2.7 codes/s per worker
```

`experiments/probe_conc.py` (N workers, 25-30 s):

| workers | cycles/s | guesses/s | requests/s | anomalies |
|---|---|---|---|---|
| 12 | 16.2 | ~32 | ~88 | none |
| 24 | 25.6 | ~51 | ~133 | 17 ConnectError, 5 ReadTimeout |

Roughly **half of all cycles lose their second guess** because the attempt counter appears
to be account-scoped: another worker's failure consumes the shared budget between our
login and our second POST. Those codes are re-queued, which is why the final run needed
10,966 guesses for 10,000 codes.

## 3. Exploitation

```
[ 15.x s] pass 1/5: sweeping 0000-9999 (24 workers, 2 guesses per login cycle)
...
[167.5 s] *** code 0740 ACCEPTED (pass 1) ***        <- FALSE POSITIVE (302 -> /login)
```

### 3.1 Failure 1 — accepting any 302

First run treated any `302` whose `Location` did not contain `/login2` as success. A dying
session answers `302 /login`, so code `0740` was flagged; verification immediately showed
the code was rejected. **Fix:** success is `302` **and** `"/my-account" in Location`;
everything else re-queues the code.

### 3.2 Failure 2 — verifying with a fresh login

Second run hit a real `302 → /my-account` at code `0332` and then "verified" by logging in
again with `0332` — which failed with `200 "Incorrect security code"`. The lab's code is
**single use**: it rotates the instant it is accepted. Also, `--max-passes` reuse left
`self.found` stale, so passes 3-5 "found" the same code within 2 seconds. **Fix:** stop
re-queueing/verifying with a new login; read `/my-account` **in the winning session**,
which is also the lab's actual completion condition, and clear per-pass state.

### 3.3 Successful run (`logs/run3.log`)

```
[260.6 s] guesses=9992 ... remaining≈0
[262.6 s] pass 1 exhausted with no hit (server rotating the code?)
[263.1 s] pass 2/4: sweeping 0000-9999
[287.9 s] code 1434: /my-account -> HTTP 200
[289.1 s] *** code 1434 ACCEPTED (pass 2) ***
[289.6 s] verification: account page=OK, lab widget=SOLVED
```

Pass 1 exhausted the entire space without a hit — the server had rotated the code during
the sweep, exactly as the lab brief warns ("you may need to repeat this attack several
times"). Pass 2 found `1434` after 8 s.

## 4. Verification (independent of the solver)

```bash
curl -s "$B/" | grep -o 'widgetcontainer-lab-status [a-z-]*'
# widgetcontainer-lab-status is-solved
grep "Your username is" evidence/my-account.html
# Your username is: carlos
```

Evidence saved: `evidence/lab-home-solved.html`, `evidence/my-account.html`.

## 5. Performance

| run | workers | outcome | guesses | requests | time |
|---|---|---|---|---|---|
| run1 | 16 | aborted early (breaker storm + false 302 at `0740`) | 946 | 2,366 | 291 s (killed) |
| run2 | 24 | 2 sweeps, false positive `0332`, verify-by-relogin failed | 14,900 | 49,585 | 398.9 s |
| run3 | 24 | **solved**, code `1434` | 10,966 | 36,390 | **289.6 s** |

## 6. Observations / limitations

* The code rotates mid-attack; multiple passes are part of the design, not a bug.
* ~33% of requests are spent on login overhead (3 of every 5 requests per cycle). Cutting
  that would require a way to obtain a valid login csrf without a page fetch — none exists.
* With 24 workers the instance showed occasional `ConnectError` / `ReadTimeout`; the
  shared circuit breaker (3 s → 45 s escalating pauses) kept the run alive without
  collapsing throughput (it stayed at ~38 guesses/s overall).
* A 2-guess cycle remains the cheapest unit of work: 2.5 requests/guess, versus 3
  requests/guess if every guess gets its own freshly logged-in session.
