# SOURCES & REFERENCES

## Lab
- Target (ephemeral): `https://0a9a0059033608fe80ed030b00a40091.web-security-academy.net/`
- Exploit server: `https://exploit-0a3b00cc030c083f8029022601f300a9.exploit-server.net`
- Official lab page: `https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-combining-vulnerabilities`
  (solution is login-gated; only the description was retrieable without auth)

## Walkthroughs / writeups consulted (saved to evidence/)
- **pasindu-sd** (Jul 2026, most detailed, matches current lab code):
  `https://pasindu-sd.github.io/writeups-blog/PortSwigger---Labs/Web-Cache-Poisoning/Combining-web-cache-poisoning-vulnerabilities`
  → `evidence/writeup_pasindu_ssd.html`
  Chain: poison Spanish page via `X-Forwarded-Host`; poison redirect via
  `X-Original-URL: /setlang\es`; victim EN → ES → malicious JSON → DOM XSS.
- **siunam321** (Jan 2023):
  `https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-11/`
  → `evidence/writeup_siunam321.html`
  Breaks down `translations.js`, `translations.json`, and the `translate()` DOM sink.
  (Note: skill warns some siunam321 walkthroughs can be stale vs current lab code —
  re-verified every behavior on the live lab.)
- Video solutions (not transcribed):
  `https://www.youtube.com/watch?v=3fStGzXQ4EY`, `https://www.youtube.com/watch?v=w_nxsG-JXHA`

## Search queries
- `PortSwigger "Combining web cache poisoning vulnerabilities" solution walkthrough`
- (web_extract backend is search-only here; walkthroughs fetched via `curl`.)

## First-party lab artifacts (authoritative over any walkthrough)
- `evidence/home_page_UNSOLVED_first.html` — original home page (unsolved).
- `evidence/exploit_server_form.html` — exploit-server config form (fields/defaults).
- `evidence/solved_state_FINAL.html` / `solved_state_exploit_FINAL.html` — solved widget.
- `evidence/browser_alert_capture.json` — browser XSS capture.
- `requests/*.request` — exact on-the-wire poison + config requests.
