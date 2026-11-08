# Lessons learned

1. **0.CL starts with an invisible header, not with chunked encoding.**
   `Content-Length : N` (space before the colon) is unknown to the front-end and
   forwarded verbatim; the back-end parses it. Establishing *which* side sees the
   obfuscated header is the whole recon step — `Host : <decoy>` versus
   `Xost : <decoy>` separates front-end from back-end behaviour in two requests.
2. **A deadlock is the signature, not an error.** A body-less request with the
   hidden length gets forwarded and then nothing comes back, because the
   front-end is waiting on a back-end that is waiting on N bytes. Do not read
   that as a wedged instance; it is the 0.CL precondition.
3. **You need an early-response gadget to escape the deadlock.** A path the
   back-end answers before reading the body — here any non-existent name under
   `/resources/css/` or `/resources/js/`, which produces a server-level
   `302 → /resources/css/<name>/` — keeps the connection open after answering.
4. **The split length is `len(stage2_header_block)`, nothing else.** The back-end
   eats exactly that many bytes of the next front-end-forwarded request as the
   body; if the byte count lands anywhere else the leftovers surface as a
   "mystery 400" instead of a controlled pipelined response. Glue the smuggled
   request line onto the end of a header value (`X: YGET /404 HTTP/1.1`) so the
   cut lands exactly on a request line.
5. **Separate connections are what reaches the victim.** With a persistent
   pipelined connection the smuggled page comes back to *the attacker* (great for
   evidence: ~0.6 hits/s at ~150 pairs/s), because the front-end pairs the
   response with the attacker's own next request. Splitting stage 1 and stage 2
   across fresh client connections lets the front-end's shared upstream pool
   hand the poisoned response to someone else — Carlos.
6. **An abrupt socket close destroys the desync.** Closing straight after
   `sendall` with unread data sends RST and the front-end aborts the upstream
   request; drain the response for ~180 ms first.
7. **Expect the front-end to be unusable for ~10 s after a burst.** Requests come
   back as stray responses (a 302 for an admin page, a 500, an empty body). The
   solver retries baseline, gadget and status reads rather than declaring failure
   from one request.
8. **Only the widget decides.** 200/302/400/404 and even a smuggled page in the
   attacker's own stream are not success; `widgetcontainer-lab-status is-solved`
   in the lab header is.
9. **`HEAD /` answers 404 while `GET /` works** on these instances — never use it
   as an expiry check.
10. **A status read taken during a smuggling storm is worthless.** The front-end
    answers `GET /` from its pool of queued/stale responses, so the widget page
    can be one rendered *before* the flip (`is-notsolved`) or an unrelated
    302/400/500. Attack in bursts, pause ~1 s, then read; the flip was detected
    in one cycle after the change and was missed for 80 s before it.
11. **Do not trust a single "not solved".** Only `is-solved` is actionable; a
    negative read may be a stale page, so keep the loop running on it.
