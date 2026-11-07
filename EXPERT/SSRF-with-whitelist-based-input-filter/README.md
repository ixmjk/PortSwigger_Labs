# SSRF with whitelist-based input filter — Expert

Automated solver for the PortSwigger Web Security Academy lab
[SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter).

## The bug in one paragraph

The stock-checker fetches a URL taken from the request body
(`POST /product/stock`, `stockApi=...`) and blocks anything whose host is not
`stock.weliketoshop.net`, answering
`"External stock check host must be stock.weliketoshop.net"`. The check inspects
the once-decoded string while the fetcher decodes again, so a **double-encoded
fragment** hides the real authority behind a userinfo decoy:

```
http://localhost%2523@stock.weliketoshop.net:8080/
  whitelist decodes -> http://localhost%23@stock.weliketoshop.net:8080/   (host = stock.weliketoshop.net)
  fetcher decodes   -> http://localhost#@stock.weliketoshop.net:8080/    (# starts the fragment)
  actual request    -> http://localhost/                                 (port 8080 ignored, loopback)
```

That turns the stock checker into a full read/write SSRF into the internal
service: `.../admin` renders the admin panel and
`.../admin/delete?username=carlos` deletes the target user.

## Run it

```bash
cd "EXPERT/SSRF-with-whitelist-based-input-filter"
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

From the repository root the universal launcher finds this solver by page title:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

Options: `--wait S` (status polling window, default 90 — this lab's checker is
synchronous), `--verbose`.

## What the solver discovers vs. what is fixed

Discovered from `--url` at runtime: the product id, the stock-check endpoint, the
whitelisted host/port and the form's own option URL. Fixed: the documented vector
shape (`http://<loopback>%2523@<discovered-host>/`) and the `carlos` username
supplied by the lab objective. Nothing instance-specific is hardcoded.

## Verification

Success is read from the lab's own widget (`widgetcontainer-lab-status` /
`<p>Solved</p>`), never from a status code. The solver also proves the mechanism
on a re-run: control request through the whitelisted host, rejection of a plain
`http://localhost/`, then the admin panel through the bypass.
