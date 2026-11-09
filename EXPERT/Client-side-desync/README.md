# Client-side desync — Expert

Automated solver for the PortSwigger Web Security Academy lab
[Client-side desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync).

Objective: make the victim's browser desynchronise its own connection to the
lab, capture the victim's session cookie from a public comment, and use it to
access the victim's account.

## The bug in one paragraph

`POST /` is answered with `302 Location: /en` **without the server reading the
request body**. The connection stays open, so every byte the browser sent after
the request head is left in the server's socket buffer and parsed as the next
request. If that body is a *partially complete* `POST /en/post/comment` whose
declared `Content-Length` is larger than the bytes supplied, the back-end waits
for the remainder — and the browser's next request on that connection supplies
it. That request carries the victim's `Cookie` header, so the appended bytes
(including `session=...`) are stored as the comment's text, on a public blog
post. Anyone can read the comment; the stolen session is then replayed against
`/my-account`.

## Run it

```bash
cd "EXPERT/Client-side-desync"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"

# from the repository root, through the universal launcher
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net/"
```

| flag | meaning |
|---|---|
| `--wait S` | seconds to wait for the victim per delivery (default 300) |
| `--extra N` | pin the `Content-Length` slack instead of the built-in ladder |
| `--force` | re-run even when the widget already reads solved |
| `--verbose` | print every request the solver sends |

Exit codes: `0` solved (stolen session reached the victim's account **and** the
lab widget reads `is-solved`), `1` exploit failed, `2` lab unreachable or
expired, `3` the instance does not answer `POST /` like the vulnerable CL.0
handler.

## What is discovered at runtime

Nothing instance-specific is hardcoded. The solver reads the language prefix
from the `302` on `/` (currently `/en`), the post id from the home page's first
post link, the comment form's `csrf`, its own `session` cookie, the exploit
server URL from `#exploit-link`, and the account path by probing
`/<lang>/my-account` vs `/my-account` (the blog routes are prefixed, the account
route is not).

## Verified run

* `POST /` with `Content-Length: 40` and no body → `HTTP/1.1 302 Found` in
  0.38 s; control `POST /en/post?postId=5` waits for its body.
* Deliver → victim's browser desyncs → comment `CSDmzm3kj7t` on post 5 stores
  the victim's raw request, `Cookie: session=…` included.
* `GET /my-account` with that session → `HTTP 200`, **Your username is:
  administrator**.
* Widget `is-solved`; total 5.8 s and 12 HTTP requests, first attempt.

## Files

| file | contents |
|---|---|
| `solve.py` | the solver |
| `smoke_paths.py` | live harness: vector + gadget proof with a synthetic victim request (works on a solved instance too) |
| `SOLUTION.md` | reproducible manual steps and payloads |
| `REPORT.md` | investigation narrative and evidence |
| `RESUME.md` | checkpoint / continuation notes |
| `LESSONS_LEARNED.md` | transferable lessons |
| `SOURCES.md` | references |
| `evidence/`, `logs/` | local artifacts (git-ignored) |
