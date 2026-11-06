# LESSONS LEARNED — Reflected XSS with event handlers and href attributes blocked

## 1. A 400 with a reason string is a map of the filter

`"Tag is not allowed"`, `"Event is not allowed"`, `"Attribute is not allowed"`
are three different rejection classes. Sending one probe per class localises the
filter in three requests and tells you which bypass family applies, instead of
guessing from a write-up. This lab's split — tags whitelisted, `on*` and `href`
blocked — points straight at attributes that can be *created* client-side.

## 2. When attribute names are filtered, build the attribute later

`href` is rejected as an attribute, but `<animate attributeName=href …>` is just
a tag with ordinary attribute *values*. The animation writes `href` into the DOM
after the request has been accepted. The general pattern: if a filter inspects
the markup you send, look for a mechanism (SVG animation, DOM clobbering,
`<base>`, CSS injection) that produces the forbidden construct after parsing.

## 3. SVG `animate` is the canonical href bypass

`<svg><a><animate attributeName=href values=javascript:alert(1) /><text>…</text></a>`
turns the text node into a `javascript:` link with no `href` ever appearing in
the request. `attributeName` and `values` are innocuous attribute names to a
whitelist; `javascript:` inside a `values` attribute is not.

## 4. The "Click" label is a lab mechanic, not a browser one

The alert fires on any click. What makes the *lab* solve is the simulated user
only clicking vectors whose text contains "Click". Before blaming the payload,
check the objective text for delivery constraints — the Academy page states it
explicitly ("you need to label your vector with the word Click").

## 5. Reflection into an `<h1>` inside quotes is still markup context

The term lands as `…for '<svg>…'`. The `'` before it is text, not a delimiter
the payload has to escape, and the browser happily parses the SVG element inside
the heading. Read the surrounding HTML to decide context — "inside quotes" alone
does not mean "inside a string".

## 6. Probe the whitelist before shipping a hardcoded vector

`solve.py` asks the instance whether `svg`, `a`, `animate`, `text` are still
allowed and asserts the three block reasons before sending the payload. If
PortSwigger tightens the filter, the run fails on a named tag instead of
reporting a mysterious "not solved". That is what makes the solver reusable on
a fresh instance rather than merely re-runnable.

## 7. The solved check can arrive in the exploit response itself

The response to the crafted search already carried
`academyLabBanner is-solved` and the congratulations block. Reading the status
widget from that response is a valid authoritative oracle — no extra request and
no polling drift. Still capture the pre-exploit baseline, otherwise the flip
cannot be attributed.
