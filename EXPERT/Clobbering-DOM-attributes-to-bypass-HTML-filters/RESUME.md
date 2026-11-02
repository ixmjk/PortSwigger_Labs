# RESUME — Clobbering DOM attributes to bypass HTML filters

**Status: SOLVED on two instances**, most recently
`0aab008d039ebda980a985a9004900c8` (victim visit 19:56:13 UTC, widget solved by
19:56:35 UTC, 2026-11-02).

## Where things stand

- `solve.py` ships the documented vector verbatim: comment
  `<form id=x tabindex=0 onfocus=print()><input id=attributes>` and exploit body
  `<iframe src=<lab>/post?postId=n onload="setTimeout(()=>this.src=this.src+'#x',500)">`.
- Every phase was exercised against live instances: title check, baseline,
  exploit-server discovery, post discovery, sanitiser assertions, comment
  storage, exploit store + serve check, `DELIVER_TO_VICTIM`, access log,
  solved detection, id-collision fallback.
- Universal launcher matches the folder exactly
  (`Clobbering-DOM-attributes-to-bypass-HTML-filters`) and exits 0.
- `tests/test_launcher.py`: 27 passed, 0 failed.
- Lab widget on both instances: `widgetcontainer-lab-status is-solved` +
  `<p>Solved</p>`.

## Timeline that led to the fix (instance 2, UTC)

| time | action | result |
|---|---|---|
| 18:55:03 | solver payload `print();alert(document.domain)` delivered | victim visited 18:55:05, **not solved** |
| 18:57–19:02 | beacon+alert variants, iframes | beacons fired (handler ran), not solved |
| 19:24 | `try{print();beacon}catch{…}` (id `fin1`) | `finalhit-ok` ×2 at 19:25:19, not solved by 19:52 |
| 19:31 | popup + `print()` in the top-level lab page | `pop2-print-ok`, not solved |
| 19:38 | popup + `alert()` | navigation confirmed, handler did not run |
| 19:52:39 | **documented vector** (id `x`, `print()`, stock iframe) | delivered 19:53 |
| 19:56:13 | victim `GET /exploit/ 200` | — |
| 19:56:35 | background status poller (5 s interval) | **SOLVED** |
| 19:58:35 | manual re-check | still solved |

Conclusion: the lab's checker only accepted the lab's own vector. Extra sinks
and alternative delivery paths executed but were not credited, and a popup
`alert()` plausibly wedged the bot (a 10-minute gap in visits followed).

## Open item

`solve.py` itself has not delivered against an *unsolved* instance — both
instances were already solved by the time the final payload was in place
(each flipped from the identical probe sequence the solver now performs). The
header drops `#exploit-link` once solved, so a re-run can only report
`caused by solver: no (was already solved)`.

To re-verify on a fresh instance:

```bash
cd /root/Desktop/PortSwigger_Labs
uv run python solve.py --url "https://<fresh-lab-id>.web-security-academy.net" --wait 300
```

Expect: comment stored, exploit served (153 bytes), victim `GET /exploit/ 200`
in the access log within ~1–7 min, widget flips to solved, exit 0 with
`caused by solver: yes`.

## Housekeeping

- Instance 2 carries the investigation comments (`xss` ×3, `v` ×8,
  `dtest2`, `pt1`, `qt1`, `fin1`, `pop2`, `pop3`, `pp4x`, plus the final
  `xss` comment with `id=x`). Comments cannot be deleted; the solver's
  collision check keeps a stale `id=x` from stealing focus.
- `evidence/` and `logs/` are git-ignored local artifacts.
- Nothing staged or committed; waiting for review/approval.
