# Sources

* PortSwigger Academy — lab description and objective:
  https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter
  (difficulty badge read from the rendered page: EXPERT)
* PortSwigger Academy — SSRF topic, "Bypassing SSRF filters" / whitelist section:
  https://portswigger.net/web-security/ssrf
* PortSwigger Academy — SSRF cheat sheet (URL parsing quirks, userinfo and
  fragment confusion): https://portswigger.net/web-security/ssrf/ssrf-cheat-sheet
* WHATWG URL Standard — host parsing, userinfo, fragment semantics:
  https://url.spec.whatwg.org/
* Observed live behaviour of this instance (all payloads in `requests/` and
  `evidence/`): whitelist rejection text, `%2523` acceptance, admin panel listing.
