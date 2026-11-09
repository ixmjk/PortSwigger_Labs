# Lessons learned

1. **HTTP/2 header *names* are a CRLF injection point when a front-end
   downgrades.** HTTP/2 treats names as opaque bytes, so `\r\n` survives into
   the HTTP/1.1 rewrite and splits the header block. Probe it with a fake
   `Host` line and watch for a gateway error naming the injected host; do not
   look for a reflected `<script>`.

2. **A lab that hides h2 from ALPN still speaks h2.** Complete the TLS handshake
   with `http/1.1` (or no ALPN), then send the HTTP/2 preface. In Burp this is
   *Allow HTTP/2 ALPN override*; in Python it is a plain socket plus the `h2`
   client on the same TLS session.

3. **Disable h2's protocol validation when you are the one breaking the
   protocol.** `H2Configuration(validate_outbound_headers=False,
   normalize_outbound_headers=False)` is required to send CRLF in a header name
   and to keep its capitalisation. On the receive side, `h2` rejects a HEAD
   response that carries a body, which is exactly what the tunnelling front-end
   returns: bypass `H2Stream._track_content_length` or the exploit response is
   unparseable (`InvalidBodyLengthError: Expected 0 bytes, received N`).

4. **The front-end's framing error is a measurement oracle.**
   `Server Error: Received only N of expected M bytes of data` gives the exact
   byte length of the tunnelled response in one request. Use it instead of
   guessing which outer page to point at.

5. **When the response is truncated, choose the outer page by measured size.**
   HEAD-probe candidate paths on the live instance and pick the largest whose
   `content-length` is ≤ the tunnelled length. Hardcoded `/login` happens to work
   here, but only because its 3351 bytes fit inside 3712.

6. **Verify a blind write by reading it back, not by the write's response.**
   The tunnelled delete answers a front-end byte-count error because a `302` is
   shorter than the outer page; the user is nevertheless gone. Re-tunnel
   `/admin` and require `carlos` to be absent *and* the widget to flip.

7. **A greedy regex over reflected CRLF text eats the delimiters.** The leaked
   value ends with `<key>'</h1>`; `[^\s\\]+` captured the quote and
   tag, producing a 401 tunnel and a misleading "cannot read admin" failure.
   Match the value's character class (`[0-9]{4,}`) rather than "not whitespace".

8. **A fresh TLS connection per request is fine for tunnelling.** Because the
   front-end does not reuse back-end connections, the smuggled request and its
   response belong to the attacker's own connection; there is no pool to poison
   and no need to keep the socket alive between steps.
