# JWT Authentication Bypass via Algorithm Confusion (No Exposed Key)

**Difficulty:** EXPERT
**PortSwigger:** [Lab page](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key)

## Objective

The lab's sessions are RS256-signed JWTs (a robust RSA key pair, `kid` header
identifies the key). The key is **not exposed** anywhere, but the server has an
algorithm-confusion flaw: when a token's `alg` is `HS256`, it verifies the
signature as HMAC-SHA256 using **the bytes of the key file** as the secret.

To win:
1. Obtain the server's RSA public key — by *deriving the modulus* from two
   server-signed JWTs (the [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n)
   technique) and reconstructing the X.509 PEM.
2. Forge a JWT with `alg: HS256`, `sub: "administrator"`, signed with the PEM
   bytes as the HMAC secret.
3. Use it to enter `/admin` and delete the user `carlos`.

## How this solver works

`solve.py` is fully self-contained (only `requests` is required):

1. **Identity guard** — fetches the page, checks the `<title>` matches this lab
   (refuses to run on the wrong lab; `--allow-mismatch` overrides).
2. **Two logins** (`wiener:peter`) with fresh sessions → two distinct RS256
   signatures over distinct messages (different `exp`).
3. **Modulus recovery** — reconstructs the EMSA-PKCS1-v1_5 message `m` from
   `header.payload` (SHA-256 digest-info prefix is fixed), then
   `G = gcd(s1^e − m1, s2^e − m2)` for `e ∈ {65537, 3}`. Every divisor `G/c`
   (small `c`) that satisfies `s^e ≡ m (mod n)` is a candidate modulus.
   Fast path uses GMP via `gmpy2` (if installed) or `libgmp.so` through ctypes;
   a pure-Python fallback always works (slower: ~3 min).
4. **Key format search** — for each candidate modulus, rebuilds the public key
   as X.509 / PKCS1 PEM in five byte-exact variants and forges an HS256 token
   with each; the first one the server accepts (200 on `/my-account`) wins.
   The lab stores the key as X.509 PEM, so the documented variant is tried
   first (1 request on the common path).
5. **Admin + delete** — forges `sub: "administrator"` (keeping `iss`, with a
   future `exp`), enters `/admin`, discovers carlos' delete link from the HTML,
   and clicks it (in the session jar — the delete follow-up needs the same
   session).
6. **Verification** — the lab's status widget must read *Solved* **and** carlos
   must be gone from `/admin`. Exit code 0 only then.

Nothing instance-specific is hardcoded: URL, `kid`, payload claims, PEM format
selection, and the delete URL are all discovered at runtime. Re-running on an
already-solved instance is idempotent (it verifies state instead of deleting
again).

## Usage

```bash
cd EXPERT/JWT-authentication-bypass-via-algorithm-confusion-with-no-exposed-key
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"

# or through the universal launcher (identifies the lab from the page title)
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"
```

## Verified results

| Run | Path | Outcome | Requests | Time |
|---|---|---|---:|---:|
| fresh instance | direct `solve.py` | **solved + verified** (widget `is-solved`, carlos gone) | 10 | 32.6 s |
| same (solved) instance | global launcher | idempotent verify, exit 0 | 10 | 29.2 s |

Derived modulus: 2048-bit RSA, `e=65537`; observed small cofactors across runs:
1, 2, 6, 7, 31, 62 (`n = G/c`). Winning key format on every run: **X.509 PEM,
64-char base64 lines, trailing newline** (the lab hint's assumption).

## Files

- `solve.py` — the solver (uv project; `requests` dependency).
- `SOLUTION.md` — direct, no-fluff solution.
- `REPORT.md` — full investigation report.
- `RESUME.md` — state + continuation instructions.
- `LESSONS_LEARNED.md` — techniques and pitfalls.
- `SOURCES.md` — references.
- `evidence/` — per-run request/response captures, derived moduli, winning key
  (git-ignored; kept locally).
- `logs/` — full run logs (git-ignored; kept locally).
