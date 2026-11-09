# REPORT — Client-side desync (Expert)

**Status: solved and verified** on a live `<lab-id>.h1-web-security-academy.net`
instance, 2026-11-09/10 UTC+03.

| metric | value |
|---|---|
| widget before run | `is-notsolved` |
| widget after run | `is-solved` (evidence/lab_solved.html) |
| solver exit code | 0 |
| exploit attempts used | 1 of 5 (Content-Length slack `+800`) |
| elapsed | 5.75 s from launch to is-solved |
| HTTP requests (solver counter) | 12 |
| account takeover | `GET /my-account` → HTTP 200, `Your username is: administrator` |

## 1. Identification

* Instance `<title>`: `Client-side desync`.
* Academy description page (`/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync`)
  rendered in a browser: difficulty badge **EXPERT**. Static HTML contains no
  difficulty string, so the browser render was required.
* Objective: induce a client-side desync so the victim's browser discloses its
  session cookie, then use that cookie to access the victim's account.
* Instance quirks: all blog routes are language-prefixed (`/en/...`), `POST /`
  redirects to `/en`, and `/my-account` is **not** prefixed.

## 2. Vector discovery

`POST /` with `Content-Length: 40` and no body answered `302 → /en` in 0.38 s
(`evidence/vector_root.txt`). The same probe against `/en`, `/en/post?postId=5`,
`/en/post/comment`, `/en/login`, `/en/my-account` and
`/resources/js/tracking.js` all blocked until timeout — so the CL.0 behaviour is
specific to the root handler, which is exactly the CSD precondition.

## 3. Gadget and chain

The comment form (`/en/post/comment`, fields `csrf`, `postId`, `comment`, `name`,
`email`, `website`) stores attacker-controlled text publicly — the "store text"
gadget the lab asks for.

Exploit page (stored on the lab's exploit server, byte-for-byte verified before
delivery, `evidence/exploit_page.html`):

```js
fetch(LAB + "/", {method:"POST", body:SMUGGLED, mode:"cors", credentials:"include"})
  .catch(() => fetch(LAB + "/en/post?postId=5", {mode:"no-cors", credentials:"include"}));
```

where `SMUGGLED` is a `POST /en/post/comment` request head (our session +
CSRF, `Content-Length` = body + 800) followed by the incomplete form body. The
outer `POST /` is answered without its body being read, the comment request is
left hanging on the socket, and the victim browser's follow-up request — which
carries `Cookie: session=…` because of `credentials: "include"` — completes it.

Evidence: the comment `CSDmzm3kj7t` on post 5 stores the victim's raw request
line and headers, including the session cookie
(`evidence/leaked_comments_page.txt`, cookie value redacted).

## 4. Account takeover

Replaying the harvested session:

```
GET /my-account
Cookie: session=<victim>
→ HTTP/1.1 200 OK, <h1>My Account</h1>, Your username is: administrator
```

(`evidence/victim_account_manual.txt`, `evidence/victim_account.html`.)
The widget flipped to `is-solved` in the same second; the solver only exits 0
when both the account is reachable and the widget reads solved.

## 5. Browser-side confirmation before delivery

The same exploit page was first loaded in a local headless Chrome
(HeadlessChrome/145) to confirm the browser half of the chain: a comment
(`LEAK1`, post 1) appeared containing that browser's own request headers and
`Cookie: session=4dJD…`. The real victim delivery then reproduced it with the
victim's cookie. This local run is what proved the `+800` slack lands inside the
`Cookie` header before wasting a victim delivery.

## 6. Re-runs

The solved lab header drops `#exploit-link`, so the exploit cannot be replayed
on a solved instance. `solve.py` detects that and reports the verified state;
`solve.py --force` therefore stops with "a full re-run needs a fresh instance".
The mechanism remains provable on a solved instance with the local harness:

```bash
uv run python smoke_paths.py --url "https://<lab>"
# [4] fake victim session … found in a public comment: True
```

## 7. Requests sent (first attempt, 12 total)

1. `GET /?csd=…` — baseline widget (`is-notsolved`)
2. `GET /` — language prefix from `302 Location`
3. `GET /en/` — home page (post id, exploit link)
4. `GET /en/post?postId=5` — own CSRF + session
5. raw `POST /` probe (CL.0 confirmed)
6. raw control `POST /en/post?postId=5` (blocked, as expected)
7. `POST <exploit>/` STORE
8. `GET <exploit>/exploit` — byte-for-byte verification
9. `POST <exploit>/` DELIVER_TO_VICTIM
10. `GET /en/post?postId=5` — leak found on the first poll
11. `GET /my-account` with the stolen session → 200, `administrator`
12. `GET /?csd=…` → `is-solved`

The current solver adds three discovery requests (a second home-page fetch for
`#exploit-link`, plus `/en/my-account` and `/my-account` probes), so a fresh run
now reports ~15.
