# LESSONS LEARNED — Reflected XSS with AngularJS sandbox escape and CSP

Generalisable rules, not run logs.

1. **When CSP forbids inline script, an Angular app is still a script engine.**
   Check for `ng-app` on `<html>`/`<body>` and a harness-loaded `angular*.js`
   before trying HTML vectors. Angular evaluates directive expressions itself,
   so `script-src 'self'` cannot stop it — the "CSP bypass" is architectural,
   not a header trick.

2. **Read the AngularJS version from the served bundle, never assume it.** The
   vector family depends on it: 1.2–1.5 carry a sandbox (sandbox-escape vectors
   apply), 1.6+ removed it (plain `{{constructor.constructor(...)}}` territory).
   Extracting the version with `angular[_-](\d+)[_-](\d+)` from the script
   `src` lets one solver refuse to run the wrong-generation vector instead of
   failing silently.

3. **The sandbox does not police filter arguments.** `value|filter:'expr'`
   compiles `expr` per element of `value` outside the usual member-name checks.
   Feeding the filter an array that ends in `window` (`$event.composedPath()`)
   gives an execution context in window scope while the expression itself never
   names `window`. This generalises to other Angular filters that take
   expressions (`filter`, `orderBy`, `limitTo` with a predicate).

4. **A fragment can replace the click.** `id=x` on the injected element plus
   `#x` on the URL makes Chrome focus the element during navigation, which
   fires `ng-focus` — no simulated user interaction, and no dependence on
   `autofocus` being honoured after injection. This keeps delivered exploits
   deterministic for a bot.

5. **Prove the store before delivering.** Fetch the exploit server's
   `responseFile` back and compare it byte-for-byte with the body you posted.
   A mangled body (or a stale one from a previous session) otherwise presents
   as "the exploit didn't work" after a multi-minute victim queue, and you
   cannot tell which half failed.

6. **`ACCESS_LOG` re-stores the response.** Send the same
   `responseFile`/`responseHead`/`responseBody` you want kept when requesting
   the log, otherwise the log request silently overwrites the live exploit.

7. **Already-solved instances hide the exploit server.** Read the status widget
   first; if it is already solved, report `caused by solver: no` and exit 0
   instead of erroring on a missing `#exploit-link`. This keeps re-runs useful
   as regression checks without pretending to have solved anything.
