# Lessons learned

* **A character blacklist on a `javascript:` URL is neutered by percent-decoding
  — and by the URL itself.** The lab escapes `'`, `<`, `>`, `=` into `%27`,
  `%3c`, `%3e`, `%3d` and considers that safe. But the browser decodes a
  `javascript:` URL *before* evaluating it, so the escaping is undone and the
  string is escaped regardless. Whenever a reflection sits in a `javascript:`
  sink, judge the filter on the *decoded* text, never on the served text.

* **Measure the filter; don't inherit it from a write-up.** Sending one character
  at a time as an extra parameter and diffing the served href took six requests
  and produced the exact table (deleted vs escaped vs allowed). That table is
  what made the payload shape obvious: no `(`, so `alert` must be assigned to
  `onerror` rather than called.

* **No parentheses is not no syntax.** `throw` is a statement and cannot appear
  in an expression, but an arrow function gives it a block: `x=>{throw/**/…}`.
  Then `toString=x` + `window+''` forces the conversion that runs it. `/**/`
  is a legal stand-in for the blocked space — comments are the cheapest way
  around a whitespace ban.

* **Check whether the lab is server-side before building a delivery pipeline.**
  `/exploit` returned 404 (no exploit server), and the official solution's "the
  lab will be solved, but the alert only fires if you click" says the checker is
  the HTTP request. Baseline → exploit → re-read state proved it in three
  requests. No browser, no victim queue, no waiting.

* **Verify the payload in a real engine anyway.** The checker greps the request;
  the *objective* is an alert. Loading the crafted URL in Chromium, hooking
  `window.alert`, and clicking the anchor produced `Uncaught 1337` — proof the
  vector is genuine XSS and not just a string the grader likes.

* **The difficulty badge is client-rendered.** The Academy page's static HTML
  contained no `apprentice`/`practitioner`/`expert` text at all; the badge only
  exists in the rendered DOM. Read it from the rendered page instead of guessing
  from the topic or trusting a third-party write-up (one labelled this lab
  "Expert", which happened to be correct — but that is not a source).

* **`curl` globbing eats `{}` and `[]` in payload URLs.** `curl: (3) unmatched
  close brace/bracket` on a perfectly valid URL; `-g`/`--globoff` fixes it.
  Anything that shells out to curl with an XSS payload needs `-g`.

* **A re-run against a solved instance must say so.** The solver reads the
  baseline first and prints `caused by solver: no (was already solved)` instead
  of claiming a fresh win. Capture the not-solved → solved pair the moment it
  happens; it cannot be recreated later on the same instance.
