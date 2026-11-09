# SOURCES — Client-side desync

* PortSwigger Academy, lab description and objective:
  <https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync>
  (difficulty badge `EXPERT` read from the rendered
  `widget-container-labelevel`; the static HTML carries no difficulty string).
* PortSwigger Academy, "Client-side desync attacks" topic page:
  <https://portswigger.net/web-security/request-smuggling/browser/client-side-desync>
* PortSwigger Research, *Browser-Powered Desync Attacks: A New Frontier in HTTP
  Request Smuggling* (James Kettle) — origin of the CSD class and the
  `fetch(...).catch()` delivery pattern.
* siunam, "Client-side desync" walkthrough (2023) —
  <https://siunam321.github.io/ctf/portswigger-labs/HTTP-Request-Smuggling/smuggling-20/>
  used for the raw-socket desync probe framing (`CL: 30` + smuggled `GET`).
* Hacking Notes Jordan, "Client-Side Desync" —
  <https://hacking-notes.jord4n.pro/web/request-smuggling/client-side-desync>
  (markdown: append `.md`), used for the swollen-`Content-Length` comment gadget
  and the "series of cross-domain requests" framing.
* Dinh Tuan Kiet, "[PortSwigger] Lab 20: Client-Side Desync" (2026) —
  <https://k0z1l.github.io/writeups/portswigger-http-request-smuggling/lab-20-http-request-smuggling-client-side-desync/>
  confirms the `mode: 'cors'` + `.catch()` connection-reuse trigger.

All findings above were re-tested against the live lab instance; no payload was
taken on faith.
