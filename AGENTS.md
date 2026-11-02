# PortSwigger Labs — Hermes Instructions

**Repository / working directory:** `/root/Desktop/PortSwigger_Labs/`

A message containing a PortSwigger Web Security Academy lab URL is a complete instruction to solve that **authorized lab**. Start automatically. Discover its title, difficulty, and exact objective from PortSwigger and the live instance; do not require a pasted objective or blindly trust a walkthrough. Stay within the lab's authorized infrastructure.

## For every URL

1. **Resume first.** Inspect Git status, the existing root `solve.py` launcher, README, related solvers, and lessons. If a lab folder exists, read `RESUME.md` and continue from saved work. Never overwrite unrelated changes.
2. **Identify and organize.** Use `<DIFFICULTY>/<hyphenated-safe-lab-title>/`. Name the Hermes session `PortSwigger-Lab-<hyphenated-safe-lab-title>` using supported session controls when possible; reuse an existing session on resumption. If naming is unavailable, report it.
3. **Investigate efficiently.** Consult official solutions, writeups, documentation, and tools as useful; adapt and test against this instance. Save discoveries and failed attempts as you go.
4. **Create the automatic solver.** Every lab requires a reusable `solve.py` accepting `--url`, autonomously discovering required endpoints and instance-specific values. Never hardcode temporary domains/URLs, credentials, cookies, CSRF tokens, or session IDs. Use **uv exclusively** (`uv add`, `uv run`), with lab-local `pyproject.toml` and `uv.lock`.
5. **Verify twice.** Test `uv run python solve.py --url "<LAB_URL>"` from the lab folder **and** from the repository root through the existing universal launcher. The launcher must select the correct solver automatically. Modify it only if necessary; regression-test any affected behavior. Record execution time and HTTP request count. Exit **0 only with actual lab-solved evidence**; HTTP 200 or redirects alone do not count. Never claim success or reusability without testing.
6. **Preserve the investigation.** Keep `RESUME.md` (checkpoint, failures, next steps), `LESSONS_LEARNED.md`, and `SOURCES.md` updated continuously. Archive relevant scripts/revisions, commands, payloads, requests, responses, errors, logs, searches, timing, and evidence in `scripts/`, `experiments/`, `requests/`, `responses/`, `logs/`, `evidence/` as appropriate. Avoid overwriting past experiments. Keep temporary secrets and private artifacts out of Git.
7. **Maintain documentation.** Prepare lab `README.md`, `REPORT.md`, and concise `SOLUTION.md` with reproducible steps, commands, payloads, and proof—without temporary instance values. Update the root README solver list, verified count, and progress badge **only after verified success**. Review `.gitignore`; append exclusions only if needed. Preserve LICENSE, `.gitattributes`, assets, history, existing solvers, and research. Review Git diff and untracked files for sensitive or unintended material.
8. **Hand off, don't commit.** Report solved status/evidence, launcher result, request count/time, key lessons, saved evidence paths, and pending repository changes. Give this exact manual test form:

   `cd /root/Desktop/PortSwigger_Labs && uv run python solve.py --url "<LAB_URL>"`

   **Stop for my independent test and explicit approval.** If my test fails, fix it and repeat the handoff. **Never stage, commit, push, tag, reset, or rewrite history without explicit approval.** After I approve a commit, review the diff, stage only intended changes, create one descriptive commit, and verify Git status. **Never push.**

## Failure / continuity

- **Expired URL:** immediately save findings and exact continuation steps in `RESUME.md`; stop and request a fresh URL for the **same** lab. Do not restart or change targets.
- **Blocked or unverified:** save all evidence, report the blocker, return nonzero from the solver, and do not increase published coverage.
- **Resuming:** read checkpoints and existing experiments before doing anything already attempted. Keep historical research intact.
