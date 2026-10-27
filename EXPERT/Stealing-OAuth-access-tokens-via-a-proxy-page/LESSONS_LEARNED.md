# Lessons learned

1. **A page that posts its own `location.href` is a token exfiltrator.** `parent.postMessage({data:
   window.location.href}, '*')` includes the fragment, which the server never sees. When an implicit
   OAuth flow is combined with such a page, framing matters, not the response body.
2. **"Leaks tokens to arbitrary pages" means `redirect_uri` validation is path-blind.** Probe it with
   `<registered-path>/../<target-page>`; a traversal that renders the normal sign-in page is accepted,
   a foreign origin returns 400. Confirm both directions before building the payload.
3. **Every OIDC interaction is cookie-bound.** Requests to `/auth` must go through a cookie jar, or the
   interaction redirect ends in `SessionNotFound: invalid_request` — which looks like a broken lab but
   is only a missing cookie.
4. **A `nonce` is single-use.** Re-using one (e.g. by re-visiting a cached exploit page whose payload
   already carries it) makes the provider refuse the flow with no obvious error in the attacker's
   tooling. Generate a fresh nonce per stored payload.
5. **Harvest by log position, not by "does a token exist".** Polling the exploit server's access log
   and accepting the first token found re-uses a stale token from an earlier run — and a
   token-validity check cannot tell you the difference. Capture the log length before delivering and
   only parse lines appended afterwards.
6. **The Academy victim browser retires with the lab.** Once the lab flips to solved, deliveries still
   return 302 but no victim request appears. Do not interpret that as a broken payload; verify the
   chain while the lab is unsolved, or reset it.
7. **`GET /me` on the OAuth server is the API-key oracle** in this lab family: a valid token yields
   `sub` and `apikey`, so administrative attribution (`sub == "administrator"`) and the final answer
   come from the same request.
8. **Chrome caches the stored exploit page.** A second visit can replay an old `nonce`; add a distinct
   query string or re-`STORE` before testing the leak again.
9. **`DELIVER_TO_VICTIM` is a two-step action.** The form POST answers `302 /deliver-to-victim`; the
   bot is only queued when that redirect is followed. A client with `allow_redirects=False` prints
   "Delivered" while the access log stays empty of victim hits — always follow the 302 and confirm the
   follow-up GET returns 200.
10. **The solved banner hides the exploit-server link.** Persist the discovered URL locally if you need
   `--force` re-runs, or pass it with `--exploit-url`.
11. **Verify with two facts.** `{"correct":true}` from `/submitSolution` plus the
    `widgetcontainer-lab-status is-solved` class — the response alone is not completion evidence.
