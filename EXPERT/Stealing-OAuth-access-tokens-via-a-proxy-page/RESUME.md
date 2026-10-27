# Resume / checkpoint log

Instances used:
- `https://0ad6007c042aa53680f7ef3400420019.web-security-academy.net` — first solve (manual chain).
- `https://0a6000f304bd2afd80f462e20004007f.web-security-academy.net` — clean re-verification from an
  unsolved state through the global launcher (6.05 s, 12 requests, exit 0).

Any replacement URL is all that is needed to re-run.

## State: COMPLETE

- Lab solved: `POST /submitSolution` → `{"correct":true}`; lab page → `widgetcontainer-lab-status is-solved`.
- Administrator API key obtained from `GET oauth/me` with the stolen token (`sub=administrator`).
- `solve.py` implemented, `uv` project locked, self-test passing, launcher path confirmed.
- Documentation written (README / SOLUTION / REPORT / LESSONS_LEARNED / SOURCES).

## Chronology

1. `GET /` → title `Stealing OAuth access tokens via a proxy page`, exploit link extracted.
2. `GET /my-account` → 302 `/social-login` → `meta refresh` to the provider's `/auth` with
   `client_id`, `redirect_uri`, `response_type=token`, `nonce`, scope.
3. Full manual flow as `wiener:peter`: `/auth` → `/interaction/<id>` → `POST …/login` → consent →
   `POST …/confirm` → 302 `/auth/<id>` → 302 `…/oauth-callback#access_token=…`.
   `GET oauth/me` with that token → `{"sub":"wiener","apikey":…}` (so `/me` is the API-key oracle).
4. `GET /post/comment/comment-form` → inline `parent.postMessage({type:'onload', data: window.location.href}, '*')`
   — the proxy page.
5. `redirect_uri` validation probe: `/oauth-callback/../post/comment/comment-form` accepted;
   `https://evil.example.net/oauth-callback/../x` rejected (HTTP 400). Probe needs a cookie jar
   (the provider binds interactions to `_interaction`).
6. Payload (message listener + iframe of the authorize URL) stored on the exploit server and
   delivered: victim hit at 16:22:29 leaked `access_token=<REDACTED>`.
7. `GET oauth/me` → `sub=administrator`, `apikey=<REDACTED>`; `POST /submitSolution` → `{"correct":true}`;
   lab page shows `is-solved`.
8. Rewrote the chain as `solve.py` (discovery → traversal probe → store → deliver → baseline-aware
   harvest → admin check → submit → widget check). End-to-end on the live lab: exit 0, 10 requests,
   5.4 s.
9. Added `--self-test` (offline log-parser checks, all PASS) and a live browser replay proving the
   production harvest picks up a *fresh* leak (`sub=wiener`).

10. Fresh-instance launcher run initially failed with zero victim hits: the delivery POST answers
    `302 /deliver-to-victim` and the solver was not following it, so the bot was never queued. Fixed
    in `store_and_deliver` (follow the redirect, expect HTTP 200) and re-verified end-to-end.

## Known environment quirk

After the lab is solved the victim bot stops loading delivered exploits: `DELIVER_TO_VICTIM` still
returns 302 but no victim request appears in the access log, so `--force` ends with
"no fresh token" and exit 1. That is expected. To re-demonstrate the full chain, reset the lab in the
Academy UI (or use a fresh instance) and run `solve.py` once.

## If work resumes

```bash
cd /root/Desktop/PortSwigger_Labs/EXPERT/Stealing-OAuth-access-tokens-via-a-proxy-page
uv sync
uv run python solve.py --self-test
uv run python solve.py --url "https://<new-lab-id>.web-security-academy.net/"
```

Artifacts already captured: `responses/` (home, social-login, comment-form, oauth-callback, exploit
server), `experiments/payload.html`, `evidence/access-log.txt`, `evidence/leaked-access-log.txt`,
`evidence/solved-home.html`, `evidence/run-summary.json`, `evidence/live-harvest-check.json`.
