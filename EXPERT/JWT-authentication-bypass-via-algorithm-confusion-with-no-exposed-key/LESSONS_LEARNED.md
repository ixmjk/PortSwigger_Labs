# Lessons Learned

## Technique (generalizable)

1. **Sign2n without Docker/gmpy2.** RSA modulus recovery from two
   (message, signature) pairs needs only `gcd(s1^e − m1, s2^e − m2)` and a
   small-cofactor enumeration. The RSA message for RS256 is *fully
   reconstructible* from the signing input (fixed SHA-256 DigestInfo prefix
   `3031300d060960864801650304020105000420`), so no key knowledge is needed.
   Candidate check: `s^e ≡ m (mod n)` for both tokens. Always enumerate the
   cofactor `c` (don't assume `G == n`) — observed c values across runs:
   1, 2, 6, 7, 62.
2. **Algorithm-confusion HMAC keys are byte-exact file contents.** When the
   server uses a key *file* as the HMAC secret, every byte matters (format,
   line width, trailing newline). Strategy: reconstruct the documented format
   first (lab hint: X.509 PEM), keep a small set of variants as fallback, and
   test against a cheap oracle endpoint (200 vs 302). The 200/302 split on
   `/my-account` made this a 1-request win.
3. **Header tampering by byte replacement** (`RS256`→`HS256` on the raw
   header JSON) preserves `kid` and exact formatting — matches what Burp's
   JWT Editor "don't modify header" produces, and avoids JSON re-serialization
   surprises.
4. **Use a stateless-forge for one-shot cookies, a jar for sequences.** The
   delete endpoint needed the *same session* as the admin page; passing the
   forged JWT per-request (`cookies=`) left the jar empty for the follow-up →
   401 + server-side session clear (`Set-Cookie: session=`). Put the token in
   `session.cookies` when the flow continues.
5. **Idempotent solvers.** On re-run, the target state may already hold
   (carlos already gone). Verify-state-instead-of-act: if the objective is
   already true, skip the action and verify the authoritative state. This also
   makes "re-run after solving" a valid manual test.
6. **Layered bignum backends.** gmpy2 (fastest, if installed) → ctypes
   libgmp (fast, needs libgmp) → pure Python (portable, ~3 min for this
   workload). Keeps the dependency list minimal (`requests` only) and the
   solver runnable on a clean Mac.

## Pitfalls (specific)

- **CPython bignums are painfully slow at 134M-bit scale**: `pow(s, 65537)`
  on a 2048-bit int ≈ 40 s, and the GCD adds more — minutes total. GMP via
  ctypes does it in ~25 s for the whole derivation.
- **ctypes + GMP gotchas** (all hit this session):
  - Real symbols are `__gmpz_*`; `mpz_init` is a macro (no symbol) and
    `mpz_mod_ui` is a macro over `__gmpz_tdiv_r_ui`.
  - `mpz_t` in the C API is `__mpz_struct*` (16-byte struct: `int _mp_alloc,
    int _mp_size, limb *_mp_d`), caller-allocated; functions take pointers to
    it. Treat it as an opaque 8-byte pointer and you segfault on the next use.
  - GMP 6.3.0 changed `__gmpz_get_str` to write into a **caller-provided
    buffer** (`char *`, not `char **` as in older GMP/headers you may find
    online). Version-portable alternative: `__gmpz_export` (stable API).
  - Python name mangling: `self.lib.__gmpz_init` inside a class body becomes
    `self.lib._GMP__gmpz_init`. Use `getattr(lib, "__gmpz_init")` strings.
- **Variable shadowing across a function** (loop var `c` clobbering the
  client object named `c`) — cost one full run. Use distinct names in long
  procedural solvers.
- **Absolute URLs from scraped links**: if a helper concatenates
  `base + path`, detect `http(s)://` prefixes first.
- **Lab instances are ephemeral AND flaky**: the first URL expired mid-work;
  the second threw transient ConnectTimeouts mid-run. Always retry read-only
  calls with backoff and save state after every phase (the solver saves
  evidence per request, so a mid-run death loses nothing).
- **`requests` per-request `cookies=` does not update the jar** — see above.
- **Title-URL mismatch after PortSwigger doc reorg**: old doc URLs
  (`/web-security/jwt/attacking/lab-...`) 404; the lab moved to
  `/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-
  algorithm-confusion-with-no-exposed-key`. The page title is still the stable
  identity — guard on it.

## Performance

- Fresh solve: 10 requests / 32.6 s (GMP path). Keytest requests: 1 when
  cofactor=1, else ≤ number of candidates before the winner (ascending c).
- Pure-Python fallback derivation: ~3 min (2×40 s pows + gcd).
