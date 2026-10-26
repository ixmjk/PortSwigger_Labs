# Partial construction race conditions (EXPERT) — automated solver

Fully automated, reusable solver for the PortSwigger Web Security Academy lab
**"Partial construction race conditions"** (EXPERT difficulty).

## Run

```bash
uv run python solve.py --url "https://TARGET_URL/"
```

Optional flags:

| Flag | Default | Meaning |
|---|---|---|
| `--attempts` | 16 | registration sessions prepared per run |
| `--confirms` | 90 | confirmation requests fired per attempt |
| `--parallel` | 8 | registrations in flight per batch |
| `--threads-per-attempt` | 6 | concurrent confirmation floods per attempt |
| `--max-batches` | 3 | full retries if no account gets confirmed |
| `--force` | off | run the exploit even if the instance already shows as solved |

**Exit code 0 only when the lab status widget reports `is-solved`** after
`carlos` has been removed from the admin user list.

## Requirements

- `uv` (https://astral.sh/uv) — `pyproject.toml` + `uv.lock` included
- Python ≥ 3.10
- `httpx` (declared in `pyproject.toml`, installed by `uv`)
- Network access to the lab host

## How it works

1. **Recon** — `GET /` confirms the page title, so the solver refuses to run
   against the wrong lab.
2. **Prepare** — one isolated PHP session + CSRF token per attempt
   (`GET /register`), with a random run nonce in the username so re-runs never
   collide.
3. **Race** — for each batch: start `threads_per_attempt` confirmation floods
   (`POST /confirm?token[]=`), then fire the registrations. Registration
   inserts the user row *before* writing the confirmation token, so for a short
   window the stored token is `NULL`; PHP's loose comparison makes
   `[] == null` true and the account is confirmed without any mailbox access.
   The flood stops as soon as one confirmation returns `200`.
4. **Confirm the account** — log in with the raced session: success is a `302`
   to `/my-account` (invalid credentials re-render `/login` with `200`).
5. **Delete carlos** — the `@ginandjuice.shop` address grants staff access:
   `GET /admin/delete?username=carlos`, then `GET /admin` must no longer list
   `carlos`.
6. **Verify** — re-fetch `/` and require the `is-solved` widget.

Nothing instance-specific is hardcoded: the host comes from `--url`, CSRF
tokens and session cookies are fetched live, usernames are nonce-based.

Typical result on a fresh instance: **~13 s, ~150 HTTP requests, 1 batch**.

## Layout

| Path | Contents |
|---|---|
| `solve.py` | the solver |
| `pyproject.toml`, `uv.lock` | uv project |
| `experiments/` | recon probes and the first (slow) race prototype |
| `evidence/`, `responses/`, `logs/`, `requests/` | local research artifacts (git-ignored) |
| `SOLUTION.md` | direct reproduction steps |
| `REPORT.md` | investigation report and verification evidence |
| `RESUME.md` | checkpoint / continuation notes |
| `LESSONS_LEARNED.md` | generalisable technique notes |
| `SOURCES.md` | references |
