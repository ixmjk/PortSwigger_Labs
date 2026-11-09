# RESUME — Client-side desync (Expert)

## Checkpoint: SOLVED and verified (2026-11-10, UTC+03)

The instance used for this run (`https://<lab-id>.h1-web-security-academy.net`)
is **`is-solved`**. Do not re-exploit it: the solved lab header hides
`#exploit-link`, so `solve.py --force` correctly stops with "a full re-run needs
a fresh instance".

Verified facts to reuse on a fresh instance:

| item | value on this instance | discovered by |
|---|---|---|
| language prefix | `/en` | `302 Location` on `GET /` |
| vector | `POST /` answers `302 → /en` with `Content-Length: 40` and no body (0.38 s) | raw TLS probe |
| non-vector endpoints | `/en`, `/en/post?postId=N`, `/en/post/comment`, `/en/login`, `/en/my-account`, `/resources/js/tracking.js` all block | same probe |
| gadget | `POST /en/post/comment` (fields `csrf`, `postId`, `comment`, `name`, `email`, `website`) | post page HTML |
| post id used | `5` (first post link on the home page) | home page HTML |
| account route | `/my-account` (unprefixed; `/en/my-account` → 404) | probe |
| working slack | `Content-Length = len(body) + 800` | browser test, then victim |
| takeover result | `HTTP 200`, `Your username is: administrator` | replayed cookie |
| run cost | 5.75 s, 12 HTTP requests, first attempt | solver log |

## Evidence (local, git-ignored)

```
evidence/lab_solved.html            # widget is-solved
evidence/exploit_page.html          # exploit page as stored/delivered
evidence/vector_root.txt            # 302 in 0.38 s vs blocked control
evidence/leaked_comment.txt         # comment body with the leaked request (cookie redacted)
evidence/leaked_comments_page.txt   # all attacker comments on posts 1 and 5 (redacted)
evidence/victim_account_manual.txt  # replay: 200 + "Your username is: administrator"
evidence/victim_account.html        # 404 from the prefixed path (kept: it is the pitfall)
evidence/run1/                      # first-run copies
logs/last_run.json                  # elapsed / request count / slack / marker
```

## How to re-verify on a fresh instance

```bash
cd /root/Desktop/PortSwigger_Labs/EXPERT/Client-side-desync
uv run python solve.py --url "https://<new-lab-id>.web-security-academy.net/" --wait 300
```

Expected: vector confirmed, exploit stored verbatim, delivered, a comment whose
author is `CSD…<random>` storing the victim's request, `/my-account` → 200, then
`is-solved` and exit 0.

If no leak appears in the first window the solver re-delivers with slack
`+700`, `+950`, `+1100`, `+1300` (the failure mode is always a `Content-Length`
that either stops short of the `Cookie` header or overruns the follow-up
request).

Mechanism-only check (works on a solved instance, no victim, no exploit server):

```bash
uv run python smoke_paths.py --url "https://<lab-id>.web-security-academy.net/"
```

## Open items

* None functional. Nothing is committed: the handoff follows the repo convention
  (stop for the operator's independent test, then one descriptive commit).
* Root `README.md` was updated with this lab (count 24, Expert 24, table row).
