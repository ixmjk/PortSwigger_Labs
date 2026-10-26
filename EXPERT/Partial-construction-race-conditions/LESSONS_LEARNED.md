# LESSONS LEARNED

## Technique (partial-construction race)

1. **Partial construction = uninitialised column, not uninitialised object.**
   The exploitable window here is between `INSERT` of the user row and the
   `UPDATE` that stores the confirmation token. Anything that reads that row
   during the gap sees `NULL`.
2. **PHP type juggling is the second half of the primitive.** `token[]=` turns
   the parameter into `[]`, and `[] == null` is `true` under loose comparison.
   Test the token encodings *before* racing: an empty scalar (`token=`) was
   explicitly rejected with `403`, only the array form is processed
   (`400 Incorrect token: Array`). The error text is the tell that the array
   reached the comparison instead of the validator.
3. **Send the confirms outside the registering session.** PHP's native session
   handler serialises requests that share a session id; confirms must use no
   cookie (or a different session) or they simply queue behind the
   registration and the window closes first.
4. **Throughput is concurrency, not request count.** One `/confirm` costs
   ~440 ms on this lab, so 4 flood threads only produce ~7 req/s while 16
   threads produce ~35 req/s. Measure this early — it decides the whole design.
5. **Fire the flood slightly before the registration** (~50 ms) so requests are
   already in flight when the row appears; a burst that starts afterwards
   wastes its fastest requests on a window that is still closed.
6. **Stop the flood on the first success.** The winning confirmation arrives
   within ~1–2 s; letting 700 queued confirms drain turned a 13 s exploit into
   a 69 s one for no extra reliability.
7. **`302` is the success signal for login, `200` is failure.** With
   `follow_redirects=False`, valid credentials redirect to `/my-account` and
   invalid ones re-render `/login` with `200`. Checking page text on the
   pre-redirect response is what caused a false "not confirmed" reading in the
   first prototype even though the accounts were already confirmed.
8. **Verify with two independent facts**: the admin user list no longer
   containing `carlos`, *and* the lab status widget flipping to `is-solved`.
9. **Registration policy is an asset.** `@ginandjuice.shop` is both the only
   accepted domain and the staff domain, so the bypass hands out admin access
   in the same step — no second vulnerability needed.

## Tooling

10. **Randomise usernames per run** (`rc<nonce><i>`); a fixed name turns every
    re-run into `User already exists` and quietly weakens the race.
11. **One isolated `httpx.Client` per attempt** carries that attempt's session
    cookie, which is what makes the later login check possible; the flood uses
    a separate cookie-less client.
12. **`httpx` keep-alive did not matter** (~440 ms either way) — don't spend
    time tuning transport when the server itself is the bottleneck; scale
    threads instead.
13. **`uv init` scaffolding is noise**: the generated `src/` package,
    `.python-version`, `[build-system]`/`[project.scripts]` and an empty
    `README.md` all break the "plain script project" convention. Delete them
    and keep a minimal `[project]` table before running `uv lock`.
