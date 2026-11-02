# SOURCES — Clobbering DOM attributes to bypass HTML filters

## Primary

- Lab page (objective, difficulty, official solution sketch):
  https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters
- DOM clobbering topic page (the `attributes` clobbering pattern):
  https://portswigger.net/web-security/dom-based/dom-clobbering
- Live instance assets (deployed code, read for the analysis):
  - `/resources/js/htmlJanitor.js` — sanitiser implementation (v0.x, vendored)
  - `/resources/js/loadCommentsWithHtmlJanitor.js` — allow-list and call site
- Upstream library: the npm package `html-janitor` (same `_sanitize`
  implementation, vendored unchanged into the lab's `/resources/js/htmlJanitor.js`).

## Secondary (consulted for corroboration, not copied)

- Sec-Llama, web-security-academy-solutions — DOM-Based Vulnerabilities #07
  (same clobbering payload and iframe + `#fragment` delivery).
- siunam321, "Clobbering DOM attributes to bypass HTML filters"
  (https://siunam321.github.io/ctf/portswigger-labs/DOM-Based-Vulnerabilities/dom-7/).
- PortSwigger Web Security Academy bot behaviour: victim UA
  `Mozilla/5.0 (Victim) ... Chrome/156.0.0.0` observed in the exploit-server
  access log (no documentation available; conclusions in `REPORT.md` are
  empirical, from beacon and dialog observations on this instance).

## Tooling

- `httpx` 0.28.1 (HTTP client), `uv` for project/venv management.
- Local Chrome via CDP (`browser_exec`) for the sanitised-DOM and focus tests:
  confirmed `onfocus` survives and `#fragment` focuses the form.
