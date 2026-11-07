# Report — SSRF with whitelist-based input filter

## Lab

* Title: **SSRF with whitelist-based input filter**
* Difficulty: **EXPERT** (read from the live Academy description page element
  `widget-container-labelevel`, not inferred)
* Topic: server-side request forgery — host whitelist bypass
* Objective: delete the user `carlos` by reaching the internal admin panel through
  the stock checker.

## Instance

* Host: temporary `*.web-security-academy.net` instance (not recorded here).
* Baseline captured before any exploit request: `is-notsolved` / `<p>Not solved</p>`.
* First exploit request flipped it to `is-solved` / `<p>Solved</p>`; `/admin`
  fetched afterwards lists only `wiener`, confirming carlos was deleted.

## Mechanism

1. `POST /product/stock` takes `stockApi` and fetches it server-side.
2. Whitelist: parsed host must be `stock.weliketoshop.net`; literals `#` and `@`
   are recognised/rejected.
3. Double URL-encoding of `#` (`%2523`) survives the whitelist's single decode as
   `%23`, which is not a fragment to the whitelist parser but *is* one after the
   fetcher decodes again — with `@` providing the decoy authority.
4. Result: arbitrary path against loopback → admin panel → delete carlos.

## Result

| Item | Value |
|---|---|
| Status | solved (verified by lab widget) |
| Caused by solver on this instance | yes (baseline unsolved, delete request flipped it) |
| Re-run on the same solved instance | exit 0, mechanism re-proven, carlos already absent |
| Requests per solver run (solved instance) | 8 |
| Elapsed (solved instance) | ~3.5 s |
| Launcher run from repo root | exit 0, exact folder-name match, 4.0 s total |

## Limitations / notes

* The instance is single-use; a repeat run reports
  `caused by solver: no (instance was already solved at baseline)` honestly.
* The bypass candidate list is ordered (localhost first, then `127.0.0.1`, with a
  path-confusion variant) so a stricter future filter fails on a named vector
  instead of silently.
