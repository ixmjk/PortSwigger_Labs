![PortSwigger Labs Solver — automated Web Security Academy lab solutions](assets/banner.png)

# 🛡️ PortSwigger Labs Solver

### One lab URL. One command. The right solution.

[![Labs solved](https://img.shields.io/badge/Labs%20solved-5%20%2F%20274-FF6633?style=for-the-badge)](https://portswigger.net/web-security/all-labs)
[![Expert solvers](https://img.shields.io/badge/Expert%20solvers-5-00A884?style=for-the-badge)](#-supported-labs)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Powered by uv](https://img.shields.io/badge/Powered%20by-uv-5C3EE8?style=for-the-badge)](https://docs.astral.sh/uv/)
[![Hermes Agent](https://img.shields.io/badge/AI%20assisted-Hermes%20Agent-7C60D5?style=for-the-badge)](https://github.com/NousResearch/hermes-agent)

**A hobby project with an ambitious goal: build automated solvers and readable case studies for every PortSwigger Web Security Academy lab.**

> ⭐ **[Star this repository](https://github.com/ixmjk/PortSwigger_Labs)** if you find it useful! Each star helps other learners discover the project. ❤️

## 🚀 What is this?

**PortSwigger Labs Solver** is a growing, independently developed library of automated [PortSwigger Web Security Academy](https://portswigger.net/web-security) lab solutions, complete with research notes and case studies.

Rather than manually searching through scripts, the **universal launcher** reads the lab name from your active lab URL, identifies a matching solver, executes it in its own `uv` environment, and reports the result.

**Current coverage: 5 of 274 labs (~1.82%)** — with five supported **Expert** challenges. The denominator is based on PortSwigger's published Academy total, checked on **October 24, 2026**; the catalog changes over time.

### ✨ Why use it?

- 🧭 **Automatic lab identification:** detects the challenge from its page title.
- ⚡ **One-command execution:** finds and runs the appropriate solver.
- 🔁 **Fresh-instance support:** avoids hardcoded temporary lab hostnames and tokens.
- ✅ **Verified outcomes:** lab-specific solvers are designed to check genuine completion rather than interpreting any response as success.
- 📚 **Detailed case studies:** published Markdown reports, discoveries, sources, and lessons learned.
- 🐍 **Isolated environments:** each solver has its own `pyproject.toml` and `uv.lock`.

## ⚡ Quick start

**Requirements:** Python 3.10+, [`uv`](https://docs.astral.sh/uv/getting-started/installation/), and an active PortSwigger Academy lab instance.

```bash
git clone https://github.com/ixmjk/PortSwigger_Labs.git
cd PortSwigger_Labs

# See which labs have solvers
uv run python solve.py --list

# Automatically identify and solve a supported lab
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"
```

**Workflow:** `Lab URL → Detect title → Find matching solver → Execute → Verify`.

If a lab is unsupported, ambiguous, expired, or unreachable, the launcher reports the problem instead of guessing and running an unrelated solver.

## 🏆 Supported labs

| Difficulty | Lab | Topic |
|:--:|---|---|
| 🔴 **Expert** | [Server-side pause-based request smuggling](https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync/lab-server-side-pause-based-request-smuggling) | HTTP request desynchronization |
| 🔴 **Expert** | [Combining web cache poisoning vulnerabilities](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-combining-vulnerabilities) | Chained web cache poisoning |
| 🔴 **Expert** | [JWT authentication bypass via algorithm confusion with no exposed key](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key) | JWT algorithm confusion + RSA modulus recovery |
| 🔴 **Expert** | [Exploiting exact-match cache rules for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-exact-match-cache-rules) | Web cache deception + CSRF |
| 🔴 **Expert** | [Partial construction race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction) | Race condition + PHP type juggling |

Find their source code and case studies inside [`EXPERT/`](EXPERT/). The long-term target is **every Academy lab**, not just the Expert category.

## 🧰 Launcher options

| Flag | Description |
|---|---|
| `--url URL` | Lab URL (required unless `--list` or `--clean` is used). |
| `--list` | List all available lab solvers. |
| `--dry-run` | Identify the solver without executing it. |
| `--root DIR` | Use an alternative labs root. |
| `--timeout S` | Change the title-fetch timeout (default: 20 seconds). |
| `--clean` | Preview ignored untracked files in this repository and ask before removing them. |

```bash
# Preview the selected solver without running the lab
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/" --dry-run

# Remove ignored research artifacts and local runtime files after reviewing the list
uv run python solve.py --clean
```

`--clean` uses Git's ignored-file rules to remove ignored, untracked items only (the equivalent of `git clean -fdX`). It lists candidates and requires an interactive confirmation. Tracked files and non-ignored files—including source and documentation not yet committed—are preserved. This is useful for clearing local research artifacts before reviewing the project context; check the list carefully because ignored evidence and logs are deleted.

The launcher streams the lab solver's output and propagates its exit status. **Exit code `0`** means the selected solver reported success; **exit code `2`** means the launcher couldn't safely find or start a solver; other nonzero exit codes are returned by the matched solver.

## 📁 Repository structure

```text
PortSwigger_Labs/
├── README.md
├── solve.py                      # Universal launcher
├── pyproject.toml
├── uv.lock
├── assets/
│   └── banner.png
├── tests/                        # Launcher tests
└── EXPERT/
    ├── Combining-web-cache-poisoning-vulnerabilities/
    │   ├── solve.py
    │   ├── pyproject.toml
    │   ├── uv.lock
    │   └── *.md                   # Case study and notes
    ├── Exploiting-exact-match-cache-rules-for-web-cache-deception/
    │   ├── solve.py
    │   ├── pyproject.toml
    │   ├── uv.lock
    │   └── *.md
    └── ...                       # Remaining lab folders follow the same pattern
```

Each lab is a separate `uv` project. Large experimental artifacts and local environments aren't needed in a public clone.

## 🤖 Built with Hermes Agent

This is an **independent hobby project developed with AI assistance from [Hermes Agent](https://github.com/NousResearch/hermes-agent)** by Nous Research.

Hermes helps investigate challenges, develop and refine solvers, and preserve research notes. I direct the work, test the tools, review results, and maintain the public project. Some investigations use publicly available PortSwigger solutions and community writeups; references are included in the corresponding lab documentation where available.

**AI-generated or AI-assisted code is not guaranteed to be correct.** Infrastructure and temporary lab instances can change, so always review the logs and verify completion.

## 🗺️ Roadmap

**Goal: 100% Academy lab coverage** — Apprentice, Practitioner, and Expert.

The plan is to keep adding independently runnable solvers, improving reliability across fresh lab instances, and publishing readable case studies along the way. The progress badge above reflects currently implemented solvers, not your personal Academy completion score.

## ⚖️ Disclaimer

This repository is intended **only for learning and authorized security testing**, especially PortSwigger's deliberately vulnerable Web Security Academy labs. Never use these tools against systems without permission.

This is an **unofficial project** and is **not affiliated with or endorsed by PortSwigger or Nous Research**. Product names and marks belong to their respective owners. See [`LICENSE`](LICENSE) for project licensing terms.

---

## 📺 Join the Telegram channel

**Want video walkthroughs of the labs?** Watch demonstrations, follow new solutions, and see future project updates on Telegram.

### 👉 [Join @PortSwigger_Labs — t.me/PortSwigger_Labs](https://t.me/PortSwigger_Labs)

⭐ **[Enjoying the project? Give it a star on GitHub!](https://github.com/ixmjk/PortSwigger_Labs)** ❤️
