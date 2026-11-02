# LESSONS LEARNED — DOM clobbering an HTML sanitiser

## 1. Sanitisers that read `node.attributes` are clobberable

`node.attributes.length` is a DOM *property*, not a snapshot. On a `<form>`,
named properties from descendant `id`/`name` shadow `Element.attributes`, so a
child with `id=attributes` turns the loop into a no-op. Audit filters for any
read of a clobberable property (`attributes`, `children`, `length`, `tagName`)
before deciding a filter is sound.

## 2. Parent-first sanitising lets the clobber survive its own clean-up

The clobbering child (`<input id=attributes>`) is itself stripped later — but
the parent's attributes were already skipped. When reasoning about a filter,
check traversal order: a payload only needs to be present at the moment the
vulnerable read happens, not to survive the whole pass.

## 3. Prove the payload mechanism in a browser before trusting a blind delivery

Beacon images from the injected handler (`new Image().src='…/beacon'`) turn an
invisible victim run into an access-log line. That is what separated "the
delivery chain is broken" from "the handler runs but the checker ignores it"
here — without the beacon, two failures looked identical. Use beacons in
throwaway diagnostic payloads, then remove them from the solving payload.

## 4. Ship the lab's own vector verbatim; do not "improve" it

On two instances, every variant that added an observable sink solved nothing,
while the documented vector solved:
`<form id=x tabindex=0 onfocus=print()><input id=attributes>` plus
`<iframe src=<lab>/post?postId=n onload="setTimeout(()=>this.src=this.src+'#x',500)">`.
`print();alert(…)`, beacons inside the handler, deferred `print()` and popup
delivery all executed in the victim (beacon-confirmed) and never flipped the
widget; a popup `alert()` plausibly wedged the bot for ten minutes. The
checker is fiducial — extra creativity only adds failure modes.

## 5. The exploit-server ACCESS_LOG action re-stores the response

`formAction=ACCESS_LOG` requires `responseFile`/`responseHead`/`responseBody`
(400 otherwise) and persists whatever body is posted with it — send the body
you want to keep, or you will silently overwrite the stored exploit with junk.

## 6. A solved lab hides `#exploit-link`

Read the lab status *before* discovering the exploit server. Solved instances
drop the header link, so a solver that parses it first dies with a misleading
"no exploit server" error on exactly the instances it should report as done.

## 7. The Academy bot queues deliveries — poll for minutes, not seconds

Observed gaps between `DELIVER_TO_VICTIM` and the victim's `GET /exploit/`
ranged from ~1 s to ~7 minutes, with one 10-minute stall and the solving run
taking ~3.5 minutes. A 90-second polling window produces false "not solved"
verdicts; `--wait 300` is the sane default here.

## 8. A `#fragment` focuses the FIRST element carrying that id

Reused instances keep old comments, so an earlier payload with the same form id
can absorb the focus and silently neutralise a new one. Detect a conflicting
`id=x` comment and fall back to a free id before delivering.

## 9. Instances are single-shot evidence

Every delivery can flip the lab. Once solved, the instance cannot demonstrate a
fresh solve; capture the before/after HTML, the served exploit and the access
log immediately, and be explicit in the docs that the end-to-end claim rests on
the manual sequence, not on a clean solver-only run.
