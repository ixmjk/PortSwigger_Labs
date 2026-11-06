# Sources

## Primary

* PortSwigger Web Security Academy — lab page (objective + official solution and
  its explanation of the exception-handling / `toString` trick):
  https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked
* Live lab instance (this session, EXPERT):
  `https://0a4c002e0333a1ef80438a6f00b70076.web-security-academy.net/`
  — `/post?postId=N` for the `javascript:fetch(...)` back-link, `/exploit` → 404.

## Standards / engine behaviour relied on

* WHATWG URL / browser behaviour: the source of a `javascript:` URL is
  percent-decoded before evaluation, which is why the app's escaping of `'`,
  `>`, `=`, `&` does not stop the payload.
* ECMAScript: `throw` is a statement (illegal in an expression), arrow-function
  bodies are blocks, and `ToString` on an object invokes its `toString` — the
  three facts the vector chains; `/**/` as a zero-width comment in place of a
  space.

## Method notes

* Character-filter table produced locally by sending single characters as an
  extra query parameter and diffing the reflected href
  (see `scripts/recon.sh`, notes in `experiments/`).
* Difficulty confirmed from the rendered Academy page DOM
  (`widget-container-labelevel` / `label-purple-small` → `EXPERT`); the static
  HTML carries no difficulty string.

## Secondary (cross-checks only)

* Community write-ups consulted to confirm the shape of the documented vector
  (e.g. siunam321, dark5301). One labels the lab "Expert"; the rendered badge is
  the authority. No write-up code was copied — the solver derives the post id and
  injection point from the live responses.
