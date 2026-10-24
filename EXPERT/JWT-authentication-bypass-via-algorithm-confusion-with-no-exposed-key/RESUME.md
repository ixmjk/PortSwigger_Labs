# RESUME — state & continuation

## Status: SOLVED AND VERIFIED (2026-10-24)

- Lab: `JWT authentication bypass via algorithm confusion with no exposed key`
  (EXPERT).
- Original instance `0a06001203d5c2d98118026a002300c9.web-security-academy.net`
  **expired** mid-investigation (user provided replacement).
- Replacement instance `0a2b00c50343858684c16490003d0026.web-security-academy.net`
  **solved**: run5 direct (10 req / 32.6 s / exit 0) and launcher run L2
  (idempotent re-verify, exit 0). Widget `is-solved`, carlos deleted.
- Solver: `EXPERT/JWT-authentication-bypass-via-algorithm-confusion-with-no-exposed-key/solve.py`
  (uv project, `requests` dep; bignum backends: gmpy2 → ctypes libgmp →
  pure-Python fallback).
- Global launcher: verified — exact title match, runs from solver dir,
  propagates exit code.

## If you need to re-verify or the instance is asked for again

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://0a2b00c50343858684c16490003d0026.web-security-academy.net/"
```

Works on fresh and already-solved instances (idempotent: verifies state when
carlos is already gone). If the instance has expired (HTTP 502/504/connection
refused), ask the user for a new lab URL and run the same command with it —
the solver needs nothing else (no hardcoded instance values).

## Verified facts (this lab, stable across instances)

- Login: `wiener:peter`, POST `/login` with form `csrf`; 302 + `session=<RS256 JWT>`.
- JWT: header `{"kid":"<uuid>","alg":"RS256"}` (compact), payload
  `{"iss":"portswigger","exp":<+4h>,"sub":"<user>"}`, 256-byte sig, `e=65537`.
- Key file on server: X.509 PEM, 64-col base64, trailing newline (byte-exact
  HMAC key for HS256 mode).
- Admin: `sub: "administrator"` → `GET /admin` 200; delete link
  `/admin/delete?username=carlos` (plain GET, no CSRF); success 302.
- Oracle for forged keys: `/my-account` → 200 accepted / 302 rejected.
- Solved state: header widget `is-solved` + carlos absent from `/admin`.

## Pending (only user actions)

- Manual test of the new solver + global launcher (user runs the command above).
- Explicit approval to commit (all repo changes are currently uncommitted).

## Open risks / notes

- GMP availability: this box has libgmp.so.10 (ctypes path, ~25 s derivation).
  macOS without Homebrew GMP falls back to pure Python (~3 min derivation) —
  still exits 0, just slower. gmpy2, if importable, is fastest.
- Cofactor enumeration cap is 100000; probability the true cofactor exceeds
  this is negligible (gcd of two random ~2048-bit integers).
- Lab instances are ephemeral; keep re-running early if a new URL is supplied.
