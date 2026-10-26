# RESUME — Partial construction race conditions

**Status: COMPLETE — lab solved and verified, solver tested, docs written,
changes left uncommitted pending manual approval.**

## State

- Lab instance `https://0a20006e045183128050ad0100900007.web-security-academy.net/`
  was solved on 2026-10-26. It currently shows `is-solved`; runs short-circuit
  unless `--force` is passed.
- `solve.py` verified three times end-to-end (`--force`, full exploit path):
  140 / 150 requests, ~13 s each, always ended with `solved=true` and
  `carlos` absent from `/admin`.
- Global launcher verified: exact folder-name match, exit code 0.

## Files

| Path | Contents |
|---|---|
| `solve.py` | final solver (httpx, threaded flood, early exit, verification) |
| `experiments/probe_01.py` | recon: register/login/confirm behaviour |
| `experiments/race_01.py` | first race prototype (1 confirm thread/attempt, slow) |
| `experiments/bench_latency.py` | `/confirm` latency + parallel throughput measurement |
| `experiments/followup_01.py` | manual: log in as raced account, delete carlos |
| `responses/confirm_token_variants.txt` | token-encoding probe results |
| `responses/status_final.html` | independent solved-widget evidence |
| `logs/solve_final_verified.log` | verified solver run |
| `evidence/writeup_*.html` | saved reference walkthroughs |

## Exact continuation instructions

1. If the instance still answers: `uv run python solve.py --url <URL>` — it
   will report "lab already shows as solved" and exit 0. Add `--force` to
   re-run the exploit itself.
2. If the instance is expired (502/504/404): request a fresh lab URL, then run
   the same command against it. Nothing in the solver is instance-specific.
3. If a fresh instance fails to land a hit: raise `--attempts` (e.g. 24) and
   `--parallel` (e.g. 10); the exploit is stochastic, not deterministic.

## Outstanding

- Manual approval of the repository changes, then a single commit (README,
  the five lab docs, `solve.py`, `pyproject.toml`, `uv.lock`).
- Nothing pushed; publishing is done by the repository owner.
