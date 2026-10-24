# Investigation Report — JWT algorithm confusion (no exposed key)

## Summary

EXPERT lab: forge an admin session by exploiting JWT algorithm confusion when
the RSA public key is not exposed. The key insight (from PortSwigger's own
walkthrough and the [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n)
project) is that **two server-signed RS256 JWTs are enough to recover the RSA
modulus**: for PKCS#1 v1.5 signatures, `n | s^e − m` for every
(message, signature) pair, so `n | gcd(s1^e − m1, s2^e − m2)`. Once `n` (and
`e=65537`) are known, the public key can be rebuilt as X.509 PEM and used as
the HS256 HMAC secret — the algorithm-confusion primitive — letting us sign
`sub: "administrator"` tokens.

## Target app (as observed)

- Blog app ("Protect Your Smart Home Gadgets From Cyber Attacks").
- `GET /login` — form with `csrf`, `username`, `password`; POST → 302 to
  `/my-account?id=wiener`, `Set-Cookie: session=<RS256 JWT>`.
- Session JWT: header `{"kid":"<uuid>","alg":"RS256"}` (compact JSON), payload
  `{"iss":"portswigger","exp":<login+4h>,"sub":"<user>"}`, 256-byte signature.
- `GET /my-account` — 200 for a valid session, 302→`/login` (+ `session=`
  cleared) for an invalid one. This 200-vs-302 split is a perfect oracle for
  testing forged keys.
- `GET /admin` — 401 for non-admins; 200 for `sub: "administrator"`, listing
  users with delete links: `<a href="/admin/delete?username=carlos">carlos -
  Delete</a>` (plain GET link, no CSRF).
- `GET /admin/delete?username=carlos` — deletes the user; lab completes.
- Lab status: page header widget `widgetcontainer-lab-status is-solved|is-notsolved`.

## Exploit mechanics

1. **Two signatures.** Fresh login sessions yield distinct JWTs (different
   `exp` ⇒ different messages, same key).
2. **Message reconstruction.** For RS256 the signed EMSA-PKCS1-v1_5 block is
   fully determined by the signing input:
   `EM = 00 01 FF…FF 00 <3031300d060960864801650304020105000420> <SHA256>`
   (19-byte SHA-256 DigestInfo prefix + 32-byte digest), 256 bytes total.
3. **GCD.** `G = gcd(s1^65537 − m1, s2^65537 − m2)` — a 134-million-bit
   integer pair; GMP (via gmpy2 or ctypes libgmp) computes both pows + gcd in
   ~20–30 s. `G = n · c` where `c = gcd` of the two unknown RSA cofactors
   (random ~2048-bit integers), so `c` is almost always tiny.
4. **Candidate filtering.** For each `c` (1…100000) dividing `G`, accept
   `n = G/c` iff `s_i^e ≡ m_i (mod n)` for both tokens and `n` is a plausible
   modulus size (512–8192 bits). Observed winners across five runs:
   `c ∈ {1, 2, 6, 7, 62}` — always a single 2048-bit candidate.
5. **Key format oracle.** The server compares the HMAC key to the **exact
   bytes of its key file** (lab hint: X.509 PEM). The solver rebuilds five
   variants (X.509 64-col ± trailing NL, X.509 60-col, PKCS#1 ± trailing NL)
   and tests each via `/my-account` (200 = match). Pass 1 tries only the
   documented X.509-64-col-with-NL form per candidate; it won on **every** run
   (1–4 requests).
6. **Forge + act.** HS256 token = original header bytes with `RS256`→`HS256`
   replaced in place, payload with `sub: "administrator"` and future `exp`,
   HMAC-SHA256 keyed with the winning PEM bytes. `GET /admin` → 200 →
   `GET /admin/delete?username=carlos` → 302.
7. **Verify.** Status widget `is-solved` + carlos absent from `/admin`.

## Runs and findings (all captured in logs/ + evidence/)

| # | Outcome | Notes |
|---|---|---|
| 1 | failed (bug) | derivation OK (G = 2049 bits → candidates c=1: 2049b, c=2: 2048b); crash: loop variable `c` shadowed the HTTP client |
| 2 | failed (network) | derivation OK (28.7 s); transient ConnectTimeout on first keytest; instance recovered |
| 3 | partial | winner c=62 (G = n·62), x509_nl64; `/admin` 200; delete failed — absolute delete URL was re-prefixed with the base URL |
| 4 | partial | winner c=2, x509_nl64; `/admin` 200; delete 401 — forged cookie passed per-request, absent from the session jar the follow-up used |
| 5 | **SUCCESS** | winner c=1 (G = n) on first keytest; delete 302; widget solved; carlos gone; 10 requests, 32.6 s, exit 0 |
| L1 | launcher, solved instance | idempotency gap exposed: old code failed when carlos already absent (exit 1) — then fixed |
| L2 | **SUCCESS (launcher)** | winner c=7, x509_nl64; delete skipped (already done); widget solved; 10 requests, 29.2 s; launcher identified solver by exact title match |

Cross-run observations:

- The RSA key is **per-instance** (kid and modulus differ between instances).
- The cofactor `c` is random per run (two fresh logins each time) — the solver
  must enumerate, not assume `c=1`.
- `e=65537` confirmed; `e=3` gcd was 1–3 bits (no candidates, as expected).
- Transient connection blips occur on these lab hosts; retry-with-backoff is
  required (4 attempts, 2/4/6/8 s).

## Performance

- Fresh solve: **~10 HTTP requests, ~33 s wall** (dominated by the 20–29 s
  GMP derivation). Keytest cost: 1 request when `c=1`, else one per candidate
  tried in ascending `c`.
- Pure-Python bignum fallback (no GMP): derivation ≈ 3 min; still functional.
