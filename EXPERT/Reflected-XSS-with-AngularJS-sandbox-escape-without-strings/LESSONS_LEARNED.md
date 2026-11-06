# Lessons learned — AngularJS sandbox escape without strings

## Query-parameter *names* can be expression sinks

Reading `?a=1&b=2` as a dictionary is a reflex; a controller that loops over the
parameters and then calls `$parse(key)` compiles the **name** as an Angular
expression. Always probe the name with an expression (`7*7` → `49` in the
heading) before hunting for HTML reflection. Values and names need separate
probes: here the value was inert while the name was the whole vulnerability.

## HTML entities inside `<script>` survive as literal text

`'` served as `&apos;` inside a `<script>` block does **not** terminate the JS
string — entities are only decoded in HTML content. Checking `&apos;` in the
response body is enough to rule out JS-string breakout, without a browser.

## `%3d` in a query key when the splitter uses the first literal `=`

A parameter is split on the first literal `=`; percent-decoding happens after.
So `charAt=[].join` must be sent as `charAt%3d[].join` — the encoded `=` reaches
the expression, while the trailing `=1` provides the value. Any client that
normalises the key (httpx `params=`, `urllib.parse.urlencode`) destroys the
vector; send a raw path and leave `[ ] | ( ) ,` unencoded.

## A quote-free expression is not a string-free payload

`toString()` yields `"[object Undefined]"` without quotes, `.constructor` reaches
`Function`, and `fromCharCode(...)` builds arbitrary strings from numbers. The
sandbox escape and the final `alert(1)` were both written with zero string
literals.

## Prove the sandbox break is load-bearing

Two browser controls make the write-up honest and make future regressions easy to
spot: the same `orderBy` predicate **without** `charAt=[].join` does nothing
(sandbox intact), and a benign expression key proves the name is compiled. Both
are in `solve.py`'s control phase and in `evidence/browser-alert-proof.txt`.

## Server-side check lags the request

This lab has no exploit server; the request alone flips it, but the flip was not
visible in the exploit response and appeared ~6 s later. Poll the status widget
for minutes, never judge on one response.

## Report the flip's author honestly

Recon flipped this instance. `solve.py` therefore prints
`caused by solver: no (was already solved)` while still re-proving the sink,
the filter state and the reflected vector, and exits 0 only on the lab's own
solved widget.
