# Lessons learned

1. **A whitelist that parses the once-decoded string is bypassed by a second
   encoding layer.** `%2523` reads as inert text (`%23`) to the check, but becomes
   `#` for the fetcher, so `http://localhost%2523@allowed-host/` requests
   `http://localhost/`. The `@` only has to look like userinfo to the *checker*.
2. **Encode the wire body, not just the parameter value.** The lab splits the
   POST body itself: a literal `&` inside `stockApi` truncates the value and the
   endpoint answers `"Missing parameter"` (HTTP 400). Keep `%2523` literal but
   encode `&` and `=`; a generic encoder that rewrites `%` → `%25` destroys the
   extra decode layer, and a fully raw body breaks on `&`.
3. **Discover the whitelisted host from the form's own option URL**, not from a
   write-up: scheme, host, port (`:8080` appeared only there) and the
   `productId`/`storeId` values all came from `/product?productId=1`.
4. **Difficulty labels can differ from memory.** The live Academy page badge for
   this lab reads EXPERT (`widget-container-labelevel`), so the folder went under
   `EXPERT/` — always read the rendered badge rather than trusting a write-up's
   claim of "practitioner".
5. **A single delete request is enough for the checker** — the widget flipped by
   the next `GET /`; no exploit server or victim delivery is involved on this lab.
6. **The `***` in terminal output is display redaction, not corrupted data.**
   Verify suspicious vectors by hex-dumping (`c.encode().hex()`) before debugging
   logic that was already correct.
7. **Delete-then-verify via the same SSRF** is the cheapest proof that the write
   primitive worked: re-fetching `/admin` shows `carlos` gone even when the root
   page widget has not been re-read yet.
