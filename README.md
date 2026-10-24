# PortSwigger Web Security Academy — Lab Launchers

A collection of autonomous PortSwigger lab solvers, plus a **universal launcher**
that finds and runs the right solver from a lab URL alone.

## Layout

```
PortSwigger_Labs/
├── solve.py            # universal launcher (this repo's entry point)
├── pyproject.toml      # launcher uv project (stdlib-only)
├── uv.lock
├── README.md
└── <DIFFICULTY>/
    └── <LAB TITLE>/
        ├── solve.py    # that lab's autonomous solver
        ├── pyproject.toml
        ├── uv.lock
        ├── README.md / REPORT.md / RESUME.md / LESSONS_LEARNED.md / SOURCES.md
        ├── scripts/ experiments/ requests/ responses/ evidence/ screenshots/ logs/
```

Each lab folder is self-contained: its own `solve.py` + uv project, so its
dependencies are preserved when launched.

## Universal launcher

Given a lab URL, the launcher:
1. fetches it and reads the lab name from the page `<title>`,
2. searches `<DIFFICULTY>/<LAB TITLE>/` (any difficulty) for the matching `solve.py`,
3. runs it with `uv run python solve.py --url <URL>` **from its own directory**,
4. streams the solver's output, propagates its exit code, and reports the total time.

### Usage

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<LAB_ID>.web-security-academy.net"
```

### Options

| Flag | Meaning |
|---|---|
| `--url URL` | The lab URL (required unless `--list`). |
| `--root DIR` | Labs root to search (default: this directory, `/root/Desktop/PortSwigger_Labs`). |
| `--timeout S` | Fetch timeout for the title (default 20 s). |
| `--dry-run` | Identify the lab and print the launch command; do not run the solver. |
| `--list` | List every available solver under `--root` and exit. |

### Examples

```bash
# Solve the lab whose URL is given (auto-detects lab + difficulty):
uv run python solve.py --url "https://0a...web-security-academy.net"

# See which lab would be launched without running it:
uv run python solve.py --url "https://0a...web-security-academy.net" --dry-run

# Show every solver that is installed:
uv run python solve.py --list
```

### Exit codes

- `0` — the matched solver ran and exited `0`.
- `N` (solver's code) — the matched solver ran and exited `N`.
- `2` — the launcher could not run a solver: bad/expired URL, network failure,
  unknown lab, ambiguous match, no solver, or `uv` missing.

### Matching & safety

- The lab is identified by normalizing the page `<title>` (lowercase,
  punctuation collapsed) and comparing it to each solver folder name.
- A solver is launched **only when exactly one confidently matches** (an exact
  folder-name match, or a single unambiguous close/substring match). If the match
  is unknown, ambiguous (multiple candidates), or missing, the launcher reports it
  and runs nothing — it never runs a solver for the wrong lab.
- Network failures, invalid URLs, and expired lab instances are reported cleanly
  (no traceback) and the launcher exits `2`.
