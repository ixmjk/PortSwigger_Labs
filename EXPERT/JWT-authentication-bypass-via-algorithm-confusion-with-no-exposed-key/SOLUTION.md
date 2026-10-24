# SOLUTION — no exposed key (EXPERT)

## The vulnerability

Sessions are RS256 JWTs: header `{"kid":"<uuid>","alg":"RS256"}`, payload
`{"iss":"portswigger","exp":...,"sub":"<user>"}`, 256-byte RSA-2048 signature.
The app has an algorithm-confusion flaw: a token with `alg: HS256` is verified
with **HMAC-SHA256 where the key is the raw bytes of the key file** looked up
by `kid`. The lab hint states the server stores the public key as an **X.509
PEM file** — so if we can reconstruct that exact PEM, we can sign admin tokens.

The key isn't exposed, but two server-signed JWTs leak enough to recover the
RSA modulus (rsa_sign2n): for PKCS#1 v1.5 signatures,
`n | s^e − m`, so `n | gcd(s1^e − m1, s2^e − m2)`.

## Steps (manual)

1. **Collect two signed JWTs.** Log in as `wiener`/`peter` (POST `/login` with
   the form's `csrf` value). The `Set-Cookie: session=<JWT>` from each login is
   a (message, signature) pair; two logins give two distinct pairs (different
   `exp`).

2. **Recover `n`.** For each token:
   - `m = int(EMSA_PKCS1_v1_5(SHA256(b"header.payload"), 256))` — i.e.
     `00 01 FF..FF 00 3031300d060960864801650304020105000420 <H>` as an
     integer (the SHA-256 digest-info prefix is constant).
   - `s = int(signature_bytes)`.
   - `G = gcd(s1^65537 − m1, s2^65537 − m2)`.
   - Try `c = 1, 2, 3, ...`: if `G % c == 0` and
     `s1^65537 mod (G/c) == m1 mod (G/c)` (and same for token 2), then
     `n = G/c` is a candidate. (Usually `c` is a small integer; observed 1–62.)

3. **Rebuild the PEM.** With `n` and `e=65537`:
   - PKCS#1: `SEQUENCE { INTEGER n, INTEGER e }`.
   - X.509 SubjectPublicKeyInfo:
     `SEQUENCE { SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }, BIT STRING(0x00 ‖ PKCS#1) }`.
   - PEM = `-----BEGIN PUBLIC KEY-----\n` + base64 in 64-char lines +
     `-----END PUBLIC KEY-----\n` (trailing newline). This byte-exact variant
     is what the server compares against.

4. **Find the accepted encoding (if unsure).** Forge a token with
   `alg: HS256` (replace the 5 bytes `RS256`→`HS256` in the header JSON),
   keep `kid` and `iss`, set `exp` to the future, sign with HMAC-SHA256 over
   `base64url(header).base64url(payload)` using the PEM bytes; send it as the
   `session` cookie to `/my-account`. 200 ⇒ accepted; 302 ⇒ wrong bytes.
   (X.509 PEM + trailing newline works out of the box per the lab hint.)

5. **Become admin and delete carlos.** Same forging with
   `sub: "administrator"`; `GET /admin` (200, user list) →
   `GET /admin/delete?username=carlos` (a plain link, no CSRF) → 302.

6. **Verify.** Lab header status widget flips to *Solved*; carlos no longer
   appears on `/admin`.

## Reproduce with the solver

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"
```

Expected: `[derive]` candidates → `[keytest] ... x509_nl64: HTTP 200 ACCEPTED`
→ `[admin] delete result: HTTP 302` → `[verify] lab status widget: solved`
→ `[done] SUCCESS`, exit code 0, ~10 requests, ~30 s.
