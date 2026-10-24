#!/usr/bin/env python3
"""
Universal PortSwigger Web Security Academy lab launcher.

Usage:
    uv run python solve.py --url "https://<LAB_ID>.web-security-academy.net"
    uv run python solve.py --list
    uv run python solve.py --clean

What it does:
  1. Fetches the lab URL and reads the lab name from the page <title>.
  2. Searches <root>/<DIFFICULTY>/<LAB_TITLE>/ for a solve.py whose folder name
     matches that title (regardless of difficulty).
  3. Runs the matched solver with `uv run python solve.py --url <URL>` from its
     own directory, so that solver's uv project / venv / dependencies are
     preserved.
  4. Streams the solver's output, propagates its exit code, and reports the
     total execution time.

It never runs a solver for the wrong lab: it only launches when EXACTLY ONE
solver confidently matches the title (an exact folder-name match, or an
unambiguous close/substring match). Unknown, ambiguous, or missing matches are
reported clearly without running anything.

Nothing lab-specific is hardcoded: the lab is identified from the fetched page
title, and the solver is located by searching --root.
"""
from __future__ import annotations

import argparse
import difflib
import html as html_mod
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ROOT = "/root/Desktop/PortSwigger_Labs"
FETCH_TIMEOUT_S = 20.0
MIN_TITLE_TOKENS = 2        # a title must have at least this many tokens to be trusted
CONTAIN_RATIO = 0.75        # min shorter/longer length ratio for a substring match
USER_AGENT = "Mozilla/5.0 (PortSwigger universal launcher)"


def normalize(s: str) -> str:
    """Lowercase and collapse any run of non-alphanumerics to a single space."""
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def extract_title(text: str) -> str | None:
    """Return the first <title>...</title> as a single-line string, or None."""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    if not m:
        return None
    t = re.sub(r"\s+", " ", html_mod.unescape(m.group(1))).strip()
    return t or None


def fetch_title(url: str, timeout: float):
    """Fetch `url` and read its <title>.

    Returns (title, http_status, error): on success error is None and title is set;
    on failure title is None and error describes why (network / expired / no title).
    Never raises.
    """
    try:
        p = urllib.parse.urlsplit(url)
    except Exception as e:  # noqa: BLE001
        return None, None, f"invalid URL: {e}"
    if p.scheme not in ("http", "https"):
        return None, None, f"unsupported URL scheme '{p.scheme or '(none)'}' (need http/https)"
    if not p.netloc:
        return None, None, "URL has no host"

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(300000).decode("utf-8", "replace")
        title = extract_title(body)
        if not title:
            return None, status, "page returned no readable <title>"
        return title, status, None
    except urllib.error.HTTPError as e:
        # Any non-2xx means the instance is not serving the lab page — report it as
        # unavailable/expired rather than treating an error-page <title> as a lab name.
        try:
            e.read(100000)
        except Exception:  # noqa: BLE001
            pass
        hint = {404: "lab not found or expired (HTTP 404)",
                410: "lab removed/expired (HTTP 410)",
                502: "lab unavailable (HTTP 502, may be expired)",
                503: "lab unavailable (HTTP 503, may be expired)",
                504: "lab expired or gateway timeout (HTTP 504)"}.get(
                    e.code, f"lab unavailable (HTTP {e.code})")
        return None, e.code, hint
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        return None, None, f"network error (instance may be expired/unreachable): {reason}"
    except Exception as e:  # noqa: BLE001
        return None, None, f"fetch error: {e}"


def find_solvers(root: str) -> list:
    """Return [{'difficulty','lab','path','dir'}] for every <root>/<D>/<L>/solve.py."""
    out = []
    if not os.path.isdir(root):
        return out
    for difficulty in sorted(os.listdir(root)):
        if difficulty.startswith("."):
            continue
        dpath = os.path.join(root, difficulty)
        if not os.path.isdir(dpath):
            continue
        for lab in sorted(os.listdir(dpath)):
            if lab.startswith("."):
                continue
            lpath = os.path.join(dpath, lab)
            if not os.path.isdir(lpath):
                continue
            spath = os.path.join(lpath, "solve.py")
            if os.path.isfile(spath):
                out.append({"difficulty": difficulty, "lab": lab,
                            "path": spath, "dir": lpath})
    return out


def _pair_match(nfolder: str, ntitle: str):
    """True = exact match, False = close (substring/prefix) match, None = no match."""
    if nfolder == ntitle:
        return True
    # folder is a prefix of title (title carries trailing branding/suffix) -> close
    if len(nfolder) >= 8 and ntitle.startswith(nfolder):
        return False
    # generic substring match (either direction) with comparable lengths -> close
    shorter = min(len(nfolder), len(ntitle))
    longer = max(len(nfolder), len(ntitle))
    if longer > 0 and (nfolder in ntitle or ntitle in nfolder) and shorter / longer >= CONTAIN_RATIO:
        return False
    return None


def match_solver(title: str, solvers: list) -> dict:
    """Match the fetched title against available solvers.

    Returns a dict with 'status' in {exact, fuzzy, ambiguous, none, short} and,
    when it resolved, a single 'match'. Runs nothing here.
    """
    nt = normalize(title)
    if len(nt.split()) < MIN_TITLE_TOKENS:
        return {"status": "short", "match": None,
                "reason": f"title too short to trust: '{title}'"}
    matches = []
    for s in solvers:
        r = _pair_match(normalize(s["lab"]), nt)
        if r is not None:
            matches.append((s, r))
    if len(matches) == 1:
        s, exact = matches[0]
        return {"status": "exact" if exact else "fuzzy", "match": s,
                "note": "exact folder-name match" if exact else "close (non-exact) title match"}
    if len(matches) > 1:
        return {"status": "ambiguous", "match": None, "matches": matches}
    scored = sorted(
        ((difflib.SequenceMatcher(None, nt, normalize(s["lab"])).ratio(), s) for s in solvers),
        key=lambda x: -x[0])
    return {"status": "none", "match": None,
            "candidates": [(round(r, 2), s["difficulty"], s["lab"]) for r, s in scored[:5]]}


def print_solvers(solvers: list) -> None:
    for s in solvers:
        print(f"   [{s['difficulty']}] {s['lab']}\n        {s['path']}")


def clean_ignored(repo_root: str, *, confirm: bool = False,
                  expected: list[str] | None = None) -> tuple[list[str], bool]:
    """Preview/remove ignored untracked files using Git's ignore rules.

    Tracked files and non-ignored untracked files are never removed. The caller
    is responsible for obtaining explicit confirmation before setting confirm.
    """
    repo_root = os.path.realpath(repo_root)
    top = subprocess.run(["git", "-C", repo_root, "rev-parse", "--show-toplevel"],
                        capture_output=True, text=True)
    if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != repo_root:
        raise ValueError(f"not a Git repository root: {repo_root}")

    preview = subprocess.run(["git", "-C", repo_root, "clean", "-ndX", "--"],
                             capture_output=True, text=True)
    if preview.returncode != 0:
        raise RuntimeError(preview.stderr.strip() or "git clean preview failed")
    candidates = [line.removeprefix("Would remove ") for line in preview.stdout.splitlines()
                  if line.startswith("Would remove ")]
    if not candidates or not confirm:
        return candidates, False
    if expected is not None and candidates != expected:
        raise RuntimeError("ignored paths changed after preview; rerun --clean and review the updated list")

    result = subprocess.run(["git", "-C", repo_root, "clean", "-fdX", "--"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git clean failed")
    return candidates, True



def main() -> int:
    ap = argparse.ArgumentParser(
        description="Universal PortSwigger lab launcher: identify the lab from the "
                    "URL's page title, find its solve.py, and run it via uv.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  uv run python solve.py --url https://<id>.web-security-academy.net\n"
               "  uv run python solve.py --url <url> --dry-run\n"
               "  uv run python solve.py --list\n")
    ap.add_argument("--url", help="Full lab URL (required unless --list or --clean is used)")
    ap.add_argument("--root", default=DEFAULT_ROOT,
                    help=f"Labs root to search (default: {DEFAULT_ROOT})")
    ap.add_argument("--timeout", type=float, default=FETCH_TIMEOUT_S,
                    help=f"Fetch timeout in seconds (default {FETCH_TIMEOUT_S:.0f})")
    ap.add_argument("--dry-run", action="store_true",
                    help="Identify the lab and print the launch command; do not run it")
    ap.add_argument("--list", action="store_true",
                    help="List every available solver under --root and exit")
    ap.add_argument("--clean", action="store_true",
                    help="Remove ignored untracked files in this repository (asks before deletion)")
    args = ap.parse_args()

    if args.clean:
        if args.url or args.list:
            ap.error("--clean cannot be combined with --url or --list")
        repo_root = os.path.dirname(os.path.realpath(__file__))
        try:
            candidates, _ = clean_ignored(repo_root, confirm=False)
        except (ValueError, RuntimeError) as e:
            print(f"[clean] ERROR: {e}", file=sys.stderr)
            return 2
        if not candidates:
            print("[clean] No ignored untracked files found.")
            return 0
        print("[clean] The following ignored untracked paths will be removed:")
        for item in candidates:
            print(f"  {item}")
        try:
            answer = input("[clean] Continue? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in {"y", "yes"}:
            print("[clean] Cancelled; nothing removed.")
            return 0
        try:
            _, removed = clean_ignored(repo_root, confirm=True, expected=candidates)
        except (ValueError, RuntimeError) as e:
            print(f"[clean] ERROR: {e}", file=sys.stderr)
            return 2
        print("[clean] Removed ignored untracked files.") if removed else print("[clean] Nothing remained to remove.")
        return 0

    if not args.url and not args.list:
        ap.error("--url is required (or use --list or --clean)")

    # --list: show what is available, then exit
    if args.list:
        solvers = find_solvers(args.root)
        if not solvers:
            print(f"[launcher] no solve.py found under {args.root}")
            return 2
        print(f"[launcher] {len(solvers)} solver(s) available under {args.root}:")
        print_solvers(solvers)
        return 0

    print(f"[launcher] target URL : {args.url}")
    print(f"[launcher] labs root  : {args.root}")
    t_start = time.time()

    # 1. identify the lab from the fetched page title
    title, status, err = fetch_title(args.url, args.timeout)
    t_fetched = time.time()
    if err:
        print(f"[launcher] ERROR: could not identify the lab: {err}")
        print(f"[launcher] (url={args.url}, timeout={args.timeout:.0f}s) — nothing run.")
        return 2
    print(f"[launcher] lab title  : {title}   (HTTP {status}, fetched in {t_fetched - t_start:.1f}s)")

    # 2. find the matching solver
    solvers = find_solvers(args.root)
    if not solvers:
        print(f"[launcher] ERROR: no solve.py found under {args.root} — nothing run.")
        return 2
    result = match_solver(title, solvers)
    st = result["status"]
    if st == "short":
        print(f"[launcher] ERROR: {result['reason']} — nothing run.")
        print("[launcher] available solvers:")
        print_solvers(solvers)
        return 2
    if st == "ambiguous":
        print(f"[launcher] ERROR: AMBIGUOUS match for title '{title}' — refusing to run a solver.")
        print("[launcher] candidate solvers:")
        for s, _ in result["matches"]:
            print(f"   [{s['difficulty']}] {s['lab']}\n        {s['path']}")
        return 2
    if st == "none":
        print(f"[launcher] ERROR: no solver matches title '{title}' (unknown lab or no solver) — nothing run.")
        print("[launcher] closest available solvers:")
        for ratio, diff, lab in result["candidates"]:
            print(f"   (similarity {ratio}) [{diff}] {lab}")
        return 2

    s = result["match"]
    print(f"[launcher] matched    : [{s['difficulty']}] {s['lab']}   ({result['note']})")
    print(f"[launcher] solver     : {s['path']}")
    cmd = ["uv", "run", "python", "solve.py", "--url", args.url]
    print(f"[launcher] command    : {' '.join(cmd)}")
    print(f"[launcher] cwd        : {s['dir']}")

    if args.dry_run:
        print("[launcher] dry-run: not executing the solver.")
        print(f"[launcher] total    : {time.time() - t_start:.1f}s")
        return 0

    # 3/4. run the solver from its own directory, streaming output, and propagate its exit code
    if shutil.which("uv") is None:
        print("[launcher] ERROR: 'uv' not found on PATH — cannot run the solver.")
        return 2
    t_run = time.time()
    print(f"[launcher] running    : (streaming solver output) {'-' * 40}")
    try:
        proc = subprocess.run(cmd, cwd=s["dir"])
    except FileNotFoundError:
        print(f"[launcher] ERROR: failed to execute 'uv' (not found): {cmd}")
        return 2
    t_done = time.time()
    code = proc.returncode
    print(f"[launcher] {'-' * 40}")
    print(f"[launcher] solver exit code : {code}")
    print(f"[launcher] solve time       : {t_done - t_run:.1f}s")
    print(f"[launcher] total time       : {t_done - t_start:.1f}s")
    print(f"[launcher] result           : "
          + ("SUCCESS (exit 0)" if code == 0 else f"FAILED (exit {code})"))
    return code


if __name__ == "__main__":
    sys.exit(main())
