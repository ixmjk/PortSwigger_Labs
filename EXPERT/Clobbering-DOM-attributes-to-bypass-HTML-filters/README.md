# Clobbering DOM attributes to bypass HTML filters — Expert

Automated solver for the PortSwigger Web Security Academy lab
[Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters).

## The bug in one paragraph

Blog comments are stored raw and sanitised **in the browser** by HTMLJanitor
with the allow-list `form:{id:true}`, `input:{name,type,value}`. Its attribute
filter trusts the DOM property `node.attributes.length`, and a `<form>`
element exposes its descendants as named properties. A form containing
`<input id=attributes>` therefore resolves `form.attributes` to that **input
element** instead of a `NamedNodeMap`; `input.length` is `undefined`, the
filter loop never runs, and every attribute on the form survives — including
`onfocus`. The parent is sanitised before its children, so the `id` is removed
from the input only after the parent's attributes were already skipped. With
`tabindex=0` the form is focusable, so a `#x` fragment navigation fires
`onfocus` and the smuggled handler runs.

## Run it

```bash
cd "EXPERT/Clobbering-DOM-attributes-to-bypass-HTML-filters"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

From the repository root the universal launcher finds this solver by page title:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

Options: `--timeout S` (per request, default 25), `--wait S` (polling window
after delivery, default 300 — the Academy bot queues deliveries and can take
several minutes), `--verbose` (print every request).

Exit codes: `0` verified solved, `1` exploit sent but lab not marked solved,
`2` usage/environment problem, `3` lab unreachable/expired.

## What the solver does

1. Reads the lab root, refuses to run unless the page title matches this lab,
   and reads the authoritative `widgetcontainer-lab-status` widget.
2. If the lab is already solved it stops there (the header only exposes
   `#exploit-link` while unsolved) and says so honestly.
3. Discovers the per-instance exploit-server host from `#exploit-link` and a
   blog post from the home page.
4. Fetches `htmlJanitor.js` + `loadCommentsWithHtmlJanitor.js` and asserts the
   vulnerable pattern is really deployed (`form:{id:true}` allow-list and an
   attribute loop over `node.attributes.length`).
5. Posts the documented comment and reads the comment JSON back to prove the
   payload is stored verbatim (the filter is client-side). An identical
   existing comment is reused, and if another comment already owns `id=x` a
   free id is chosen so the fragment cannot focus the wrong form.
6. Stores the documented exploit body, verifies the exploit server actually
   serves it, then delivers it to the victim.
7. Polls the lab widget until it reports `is-solved` / `Solved` and prints the
   exploit-server access log.

Success is the lab's own solved state — not a 200, not a redirect, not a
reflected payload.

## Payload (documented, verbatim)

```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

Exploit-server body:

```html
<iframe src=https://<lab>/post?postId=<n> onload="setTimeout(()=>this.src=this.src+'#x',500)"></iframe>
```

The delay is required: comments are fetched by XHR after load, so `#x` must be
applied once the form exists. Keep this vector byte-identical — `REPORT.md`
§5 lists variants that executed in the victim but never flipped the widget.

## Verified result

| instance | baseline | after exploit | evidence |
|---|---|---|---|
| `0aab008d039ebda980a985a9004900c8` | not solved | **SOLVED** | victim `GET /exploit/ 200` at 19:56:13 UTC, widget `is-solved` by 19:56:35 UTC (background poller), re-confirmed at 19:58:35 |
| same instance, solver re-run | already solved | SOLVED (pre-existing) | 2 requests, 0.8 s, exit 0 |
| `0a8c00ac033581c380adbca6004d00f6` (earlier) | not solved | **SOLVED** | same vector, first investigation |

A clean solver-only run needs an unsolved instance: the lab stays solved once
flipped and the header then hides `#exploit-link`, so a re-run can only report
`caused by solver: no (was already solved)`. The solving request sequence is
exactly what the solver performs (comment → store → serve check →
`DELIVER_TO_VICTIM` → poll); evidence is in `evidence/` (local, git-ignored)
and summarised in `REPORT.md`.
