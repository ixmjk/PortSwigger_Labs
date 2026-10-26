# SOURCES

## Lab & research
- Lab page: https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction
- Topic page: https://portswigger.net/web-security/race-conditions
  (sections: *Partial construction race conditions*, *Session-based locking
  mechanisms*, *PHP parameter array syntax* `param[]=`)
- PortSwigger Research — "Smashing the state machine: the true potential of web
  race conditions" — https://portswigger.net/research/smashing-the-state-machine

## Walkthroughs consulted (saved locally under `evidence/`)
- siunam321, *Partial construction race conditions* (2023)
  https://siunam321.github.io/ctf/portswigger-labs/race-conditions/race-conditions-5/
  → `evidence/writeup_siunam321.html`; source of the Turbo Intruder
  1-register + 50-confirm-per-attempt pattern.
- draftzz, *Partial Construction Race Conditions* (2026)
  https://draftzz.github.io/writeups/race-condition-partial-construction/
  → `evidence/writeup_draftzz.html`; documented the `/confirm?token[]=` probe
  matrix and the `[] == null` loose-comparison explanation.

## Tooling
- uv (Python project manager): https://astral.sh/uv
- httpx: https://www.python-httpx.org/
- Burp Suite / Turbo Intruder (manual equivalent of the threaded flood):
  https://github.com/PortSwigger/turbo-intruder

## Search queries used
- `PortSwigger lab Partial construction race conditions solution registration
  email verification`
- Follow-ups opened directly from the result list (no further query needed).

## Target instance (ephemeral)
- `https://0a20006e045183128050ad0100900007.web-security-academy.net/`
  solved 2026-10-26.
