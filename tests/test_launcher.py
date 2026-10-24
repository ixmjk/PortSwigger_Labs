#!/usr/bin/env python3
"""
Test harness for the universal PortSwigger launcher (solve.py at the repo root).

Tests matching logic, error handling, and the end-to-end launch path WITHOUT
executing any live lab solution: titles are served by a local HTTP server and
"solvers" are tiny fake scripts in a throwaway root under the scratch dir.

Run:  cd /root/Desktop/PortSwigger_Labs && uv run python tests/test_launcher.py
"""
import http.server
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # .../PortSwigger_Labs
LAUNCHER = os.path.join(ROOT, "solve.py")
SCRATCH = tempfile.mkdtemp(prefix="launcher_test_")
FIXTURE_ROOT = os.path.join(SCRATCH, "root")
FIXTURE_ROOT_AMB = os.path.join(SCRATCH, "root_ambiguous")
DEAD_URL = "https://0a3900d404cee1638046629e005a0021.web-security-academy.net/"

os.makedirs(FIXTURE_ROOT, exist_ok=True)
os.makedirs(FIXTURE_ROOT_AMB, exist_ok=True)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"   [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -> {detail}" if detail and not cond else ""))


# ---------------------------------------------------------------- fixtures
def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)

PYPROJECT = "[project]\nname = \"%s\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = []\n"

# exact-match + launch + exit 0 + streaming
write(os.path.join(FIXTURE_ROOT, "MEDIUM", "Fake Widget Lab", "solve.py"),
      'import sys, os\n'
      'print("FAKE-WIDGET-SOLVER: file=" + __file__)\n'
      'print("FAKE-WIDGET-SOLVER: argv=" + repr(sys.argv))\n'
      'print("FAKE-WIDGET-SOLVER: cwd=" + os.getcwd())\n'
      'sys.exit(0)\n')
write(os.path.join(FIXTURE_ROOT, "MEDIUM", "Fake Widget Lab", "pyproject.toml"), PYPROJECT % "fake-widget-lab")

# exit-code propagation (exits 7)
write(os.path.join(FIXTURE_ROOT, "MEDIUM", "Exit Code Lab", "solve.py"),
      'import sys\nprint("EXIT-CODE-SOLVER: about to exit 7")\nsys.exit(7)\n')
write(os.path.join(FIXTURE_ROOT, "MEDIUM", "Exit Code Lab", "pyproject.toml"), PYPROJECT % "exit-code-lab")

# dependency preservation: imports a 3rd-party pkg declared only in THIS project
write(os.path.join(FIXTURE_ROOT, "MEDIUM", "Dep Lab", "solve.py"),
      'import requests, sys\nprint("DEP-SOLVER OK requests=" + requests.__version__)\nsys.exit(0)\n')
write(os.path.join(FIXTURE_ROOT, "MEDIUM", "Dep Lab", "pyproject.toml"),
      "[project]\nname = \"dep-lab\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = [\"requests\"]\n")

# ambiguous: same lab name under two difficulties
for diff in ("EASY", "HARD"):
    write(os.path.join(FIXTURE_ROOT_AMB, diff, "Twin Lab", "solve.py"),
          'import sys\nprint("TWIN-SOLVER in ' + diff + '")\nsys.exit(0)\n')
    write(os.path.join(FIXTURE_ROOT_AMB, diff, "Twin Lab", "pyproject.toml"), PYPROJECT % ("twin-" + diff))

# ------------------------------------------------------------- title server
class TitleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.parse.unquote(self.path).strip("/")
        body = f"<html><head><title>{path}</title></head><body>fake lab</body></html>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


httpd = socketserver.TCPServer(("127.0.0.1", 0), TitleHandler)
PORT = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
print(f"local title server: http://127.0.0.1:{PORT}  (title = URL path)")


def url_for(title):
    return f"http://127.0.0.1:{PORT}/{urllib.parse.quote(title)}/"


def run(*extra):
    """Run the launcher via uv; return (exit_code, combined_output)."""
    proc = subprocess.run(
        ["uv", "run", "python", LAUNCHER, *extra],
        capture_output=True, text=True, cwd=ROOT)
    return proc.returncode, proc.stdout + proc.stderr


# ----------------------------------------------------------------- logic
print("\n== Pure matching logic (imported) ==")
sys.path.insert(0, ROOT)
import solve as L  # noqa: E402

check("normalize collapses punctuation",
      L.normalize("Server-side_pause-based request smuggling") ==
      "server side pause based request smuggling")
check("extract_title basic", L.extract_title("<html><head><title>  My Lab </title></head>") == "My Lab")
check("extract_title multiline + entities",
      L.extract_title("<title>A &amp; B\n   Lab</title>") == "A & B Lab")
check("extract_title none", L.extract_title("<html><head></head></html>") is None)

S2 = [
    {"difficulty": "EXPERT", "lab": "Combining-web-cache-poisoning-vulnerabilities", "path": "x", "dir": "x"},
    {"difficulty": "EXPERT", "lab": "Server-side_pause-based_request_smuggling", "path": "y", "dir": "y"},
]
r = L.match_solver("Combining web cache poisoning vulnerabilities", S2)
check("exact match: combining", r["status"] == "exact" and r["match"]["lab"].startswith("Combining"))
r = L.match_solver("Server-side pause-based request smuggling", S2)
check("exact match: underscore folder", r["status"] == "exact" and "smuggling" in r["match"]["lab"])
r = L.match_solver("Some Totally Different Lab Name", S2)
check("no match -> none (reports candidates)", r["status"] == "none" and r["candidates"])
r = L.match_solver("Lab", S2)
check("short title -> short", r["status"] == "short")
r = L.match_solver("Combining web cache poisoning vulnerabilities - PortSwigger", S2)
check("branding suffix -> fuzzy (prefix) match", r["status"] == "fuzzy" and r["match"]["lab"].startswith("Combining"))
r = L.match_solver("Web cache poisoning", S2)
check("partial near-miss -> none (safe, no false run)", r["status"] == "none")

# ------------------------------------------------------------------ e2e
print("\n== End-to-end launch (local titles + fake solvers) ==")
code, out = run("--url", url_for("Fake Widget Lab"), "--root", FIXTURE_ROOT)
check("e2e exact: exit 0", code == 0, f"code={code}\n{out}")
check("e2e exact: matched lab", "[MEDIUM] Fake Widget Lab" in out and "exact folder-name match" in out, out)
check("e2e exact: launched from its dir + streamed",
      "FAKE-WIDGET-SOLVER: argv=" in out and "cwd=" in out, out)
check("e2e exact: passed --url through", "--url" in out and url_for("Fake Widget Lab") in out, out)
check("e2e exact: used 'uv run python solve.py'", "uv run python solve.py --url" in out, out)
check("e2e exact: reports total time", "total time" in out, out)

code, out = run("--url", url_for("Exit Code Lab"), "--root", FIXTURE_ROOT)
check("e2e exit-code: propagates 7", code == 7, f"code={code}\n{out}")
check("e2e exit-code: reports FAILED", "FAILED (exit 7)" in out, out)

code, out = run("--url", url_for("Dep Lab"), "--root", FIXTURE_ROOT)
check("e2e dependency: solver's own venv used (import requests succeeds)",
      code == 0 and "DEP-SOLVER OK requests=" in out, f"code={code}\n{out}")

code, out = run("--url", url_for("Fake Widget Lab"), "--root", FIXTURE_ROOT, "--dry-run")
check("dry-run: exit 0", code == 0, f"code={code}\n{out}")
check("dry-run: prints command, does NOT execute",
      "dry-run: not executing" in out and "FAKE-WIDGET-SOLVER: argv=" not in out, out)

code, out = run("--url", url_for("Some Nonexistent Lab XYZ"), "--root", FIXTURE_ROOT)
check("unknown lab: exit 2 + no run", code == 2 and "no solver matches" in out and "closest" in out, out)

code, out = run("--url", url_for("Twin Lab"), "--root", FIXTURE_ROOT_AMB)
check("ambiguous: exit 2, lists both, runs nothing",
      code == 2 and "AMBIGUOUS" in out and "[EASY] Twin Lab" in out and "[HARD] Twin Lab" in out
      and "TWIN-SOLVER" not in out, out)

print("\n== Error handling (network / invalid / expired) ==")
code, out = run("--url", "not a url")
check("invalid URL (no scheme): exit 2, safe msg", code == 2 and "unsupported URL scheme" in out, out)
code, out = run("--url", "ftp://example.com/x")
check("invalid scheme ftp: exit 2", code == 2 and "unsupported URL scheme" in out, out)
code, out = run("--url", "https://127.0.0.1:1/")
check("connection refused: exit 2, safe msg", code == 2 and "network error" in out and "Traceback" not in out, out)
code, out = run("--url", DEAD_URL, "--timeout", "8")
check("expired/dead instance: exit 2, safe msg (no traceback)",
      code == 2 and "Traceback" not in out and ("network error" in out or "could not identify" in out), out)

# ----------------------------------------------------------------- summary
httpd.shutdown()
shutil.rmtree(SCRATCH, ignore_errors=True)
print(f"\n== SUMMARY: {len(PASS)} passed, {len(FAIL)} failed ==")
if FAIL:
    print("FAILED TESTS:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
print("ALL TESTS PASSED")
