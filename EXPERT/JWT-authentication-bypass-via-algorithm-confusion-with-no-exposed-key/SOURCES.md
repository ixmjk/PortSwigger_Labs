# Sources

## PortSwigger (official)

- Lab page (current location after doc reorg):
  <https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key>
  — includes the walkthrough: collect two JWTs → `docker run --rm -it
  portswigger/sig2n <tok1> <tok2>` → test tampered JWTs on `/my-account`
  (200 = correct key) → forge `sub: "administrator"` with the X.509 key as a
  symmetric key → `/admin` → `/admin/delete?username=carlos`. Hint: "You can
  assume that the server stores its public key as an X.509 PEM file."
- Topic: Algorithm confusion attacks —
  <https://portswigger.net/web-security/jwt/algorithm-confusion>
  (incl. "Deriving public keys from existing tokens": use two JWTs to compute
  potential `n` values; the server-accepted forged JWT identifies the key; the
  HMAC key must be byte-identical to the server's stored key file, format and
  all).
- Companion lab (key exposed via JWKS):
  <https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion>
- JWT header parameters (`kid`, `jku`, `jwk`) background:
  <https://portswigger.net/web-security/jwt>

## rsa_sign2n (the underlying technique)

- <https://github.com/silentsignal/rsa_sign2n> — "Deriving RSA public keys
  from message-signature pairs".
  - `sig2n.py`: core math — `gcd(pow(s1,e)-m1, pow(s2,e)-m2)`, then
    `my_n = gcd_res/my_gcd` for small `my_gcd`, verified by
    `pow(s1,e,my_n)==m1`.
  - `standalone/jwt_forgery.py` (the tool PortSwigger wraps in Docker):
    EMSA-PKCS1-v1_5 message reconstruction via PyCryptodome's
    `_EMSA_PKCS1_V1_5_ENCODE`, asn1tools PKCS#1/X.509 DER encoding,
    `der2pem` (64-col, trailing newline), `forge_mac` (RS256→HS256 byte
    replace in header, `exp = now+86400`, HMAC-SHA256 keyed with PEM bytes).
  - Background: <https://blog.silentsignal.eu/2021-02-08/abusing-jwt-public-keys-without-the-public-key/>
- Technique origin:
  <https://crypto.stackexchange.com/questions/30289/is-it-possible-to-recover-an-rsa-modulus-from-its-signatures/30301#30301>

## GMP (bignum layer)

- GMP manual / headers (Debian `libgmp-dev`, `gmp.h`): `__mpz_*` symbol names,
  `mpz_t = __mpz_struct*` ABI, and the GMP 6.3.0 `mpz_get_str` API change
  (caller buffer) — motivated using the stable `__gmpz_export` instead.
  <https://gmplib.org/manual/Integer-Conversion.html>

## Walkthroughs consulted (cross-checks)

- <https://siunam321.github.io/ctf/portswigger-labs/JWT/jwt-8/>
- <https://pasindu-sd.github.io/writeups-blog/PortSwigger---Labs/JWT/JWT-authentication-bypass-via-algorithm-confusion-with-no-exposed-key>
- <https://yashfren.net/blogs/jwt-attacks-portswiggerlabs-walkthrough/>
- <https://github.com/themayursinha/portswigger-web-security-academy-labs/blob/main/jwt/lab-08-jwt-algorithm-confusion-no-exposed-key.md>

## Live lab evidence (this instance set)

- `evidence/` — per-request captures, derived moduli (`derived_n.txt`),
  winning key PEM, forged tokens, admin panel HTML before/after, final status
  page (git-ignored, kept locally).
- `logs/` — full run output for runs 1–5 and both launcher runs.
