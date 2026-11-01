# SOURCES — 2FA bypass using a brute-force attack

## Primary

* PortSwigger Web Security Academy — lab page (brief, note on code rotation, hint):
  https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack
  Key excerpts used:
  * "As the verification code will reset while you're running your attack, you may need to
    repeat this attack several times before you succeed."
  * "You will need to use Burp macros in conjunction with Burp Intruder to solve this lab
    … Users proficient in Python might prefer to use the Turbo Intruder extension."
* PortSwigger — official solution (fetched from the lab page):
  "log in as carlos and investigate the 2FA verification process. Notice that if you enter
  the wrong code twice, you will be logged out again. You need to use Burp's session
  handling features to log back in automatically before sending each request."
  → i.e. one guess per freshly logged-in session in Burp; this solver instead extracts
  **two** guesses per session (the maximum the server allows) to halve login overhead.
* PortSwigger topic: Authentication → Multi-factor authentication:
  https://portswigger.net/web-security/authentication/multi-factor
* Burp Suite documentation — session handling macros (the technique the lab points at):
  https://portswigger.net/burp/documentation/desktop/settings/sessions

## Used for verification/behaviour checks (no third-party solutions copied)

* Live lab instance responses (`responses/`, `logs/`) — the authoritative source for the
  2-attempt limit, csrf behaviour, redirect targets and code rotation.
* `experiments/probe_cycle.py`, `experiments/probe_conc.py` — self-written probes for
  per-cycle latency and worker-count/failure-mode measurement.

## Notes on external writeups

No community walkthrough was required: the lab page's own solution outline (macro +
Intruder, 2 wrong codes → logout) fully specifies the primitive. The parallel-sweep
implementation, success-signal choice, re-queue semantics and circuit breaker are original
to this repository.
