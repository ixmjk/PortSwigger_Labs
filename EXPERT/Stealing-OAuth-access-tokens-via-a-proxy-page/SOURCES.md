# Sources

## Lab

- PortSwigger Academy — *Stealing OAuth access tokens via a proxy page*
  https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page
- PortSwigger — OAuth authentication topic hub
  https://portswigger.net/web-security/oauth

## Observed in this instance (not external references)

- `GET /social-login` → `meta http-equiv=refresh` to `oauth-<id>.oauth-server.net/auth?...`
  (`client_id`, `redirect_uri`, `response_type=token`, `nonce`, `scope=openid profile email`).
- `GET /post/comment/comment-form` source:
  `parent.postMessage({type: 'onload', data: window.location.href}, '*')`.
- `GET /oauth-callback` source: reads `window.location.hash`, calls `oauth/me`, then posts to
  `/authenticate`.
- Provider behaviour: `oidc-provider` (Node) — `/interaction/<id>/{login,confirm}`, `_interaction`
  cookie required, `SessionNotFound: invalid_request` without it.

## General background

- RFC 6749 §4.2 (implicit grant) — why tokens are returned in the fragment:
  https://www.rfc-editor.org/rfc/rfc6749#section-4.2
- OWASP WSTG — Testing for client-side URL redirect / path traversal in redirect targets:
  https://owasp.org/www-project-web-security-testing-guide/
- MDN — `Window.postMessage` and target-origin pitfalls:
  https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
