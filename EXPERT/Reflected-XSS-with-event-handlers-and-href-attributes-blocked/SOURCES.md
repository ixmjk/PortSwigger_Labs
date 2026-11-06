# SOURCES — Reflected XSS with event handlers and href attributes blocked

## Primary

* PortSwigger Academy lab page —
  https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked
  *Objective, filter behaviour and the "label your vector with the word Click"
  delivery constraint all come from here. Fetched 2026-11-06.*
* Official solution hint on the same page: replace `YOUR-LAB-ID` in
  `https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E`
* Live lab instance (`https://<LAB-ID>.web-security-academy.net`) —
  filter probes, reflection markup and the solved banner were all captured from
  the running lab (see `evidence/`).

## Background

* MDN, `<animate>` element and `attributeName` / `values` —
  https://developer.mozilla.org/en-US/docs/Web/SVG/Element/animate
* PortSwigger, "Cross-site scripting contexts" —
  https://portswigger.net/web-security/cross-site-scripting/contexts
* PortSwigger, "SVG markup and XSS" (why `<animate>`/`<set>` can carry
  `javascript:` URLs) —
  https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## Repository

* Sibling solver `EXPERT/Reflected-XSS-in-a-JavaScript-URL-with-some-characters-blocked/`
  — same blog application, different sink; the status-widget oracle and the
  "control request proves the precondition" pattern were reused from it.
* `references/academy-lab-mechanics.md` in the `portswigger-weblabs` skill —
  where the solve oracle lives and how the instance lifecycle behaves.
