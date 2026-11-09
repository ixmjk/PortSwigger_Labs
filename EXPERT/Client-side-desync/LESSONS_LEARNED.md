# LESSONS_LEARNED — Client-side desync

**A CL.0 handler is found by timing, not by payloads.** Sending a request head
with `Content-Length: 40` and no body over a raw TLS socket separates
"answered early" (0.3 s) from "waited for its body" (timeout) in one request per
endpoint. Probe a handful of paths and the odd one out is the vector; a control
request keeps you from misreading a server that simply answers everything early.

**CSD needs the *browser* to reuse the poisoned connection, so the exploit must
not await it.** `fetch(POST /)` with `mode: "cors"` and `credentials: "include"`
cannot read the 302 cross-origin, so the `.catch()` fires and the follow-up
`no-cors` fetch lands on the same (desynced) socket. Awaiting a response, or
navigating away first, gives the attacker nothing.

**The `Content-Length` slack is the one tunable, and the window is wide.**
The hanging comment request must be completed by the browser's *next* request:
too small and the `Cookie` header never lands inside the stored text; too large
and the request never completes. Chrome's follow-up is ~1.2 kB with the cookie
just past halfway, so `body + 800` worked first try. Keep a ladder
(700/950/1100/1300) and re-deliver rather than guessing once.

**Prove the browser half locally before spending a victim delivery.** Loading
the same exploit page in a local headless Chrome produced a comment containing
*that* browser's session — which is exactly the observable the victim delivery
would produce, and it validates the slack before the victim queue is involved.

**The leak is self-authenticating.** The smuggled comment request carries the
attacker's own `session` + CSRF, so the comment is written by a valid author;
the victim's identity only appears in the appended bytes. That is why the
gadget only needs "store text", not "store text as the victim".

**Language prefixes are not uniform.** `/`, `/post`, `/post/comment` live under
`/en`, but `/my-account` and `/login` do not. Discover the prefix from the `302`
on `/` and probe the account route separately; a prefixed `/en/my-account`
answers 404 and would otherwise read as "account takeover failed".

**`h1-web-security-academy.net` instances have no `/academyLabHeader`
WebSocket** — the status script answers `HTTP 404` there, so read the widget from
`GET /` (`widgetcontainer-lab-status is-solved`) instead of treating the missing
push channel as a failure.

**Once solved, `#exploit-link` disappears**, so `--force` cannot re-run the
exploit on the same instance. Detect it, report the verified solved state, and
keep a local raw-socket harness (`smoke_paths.py`) to demonstrate the mechanism
afterwards — it needs no victim and no exploit server.
