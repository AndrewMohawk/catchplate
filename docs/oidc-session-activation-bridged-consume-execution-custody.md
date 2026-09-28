# Bridged consume execution custody

This source slice connects distinct bridge-aware grant, reservation and SQL
receiving purposes to their actual private workers. It does not turn a planning
receipt into execution authority, and it does not by itself enable a public
historical-consume endpoint. The source is unbuilt and unexecuted.

## Separate original purposes

The actual history owner selects only its fixed legacy/bridge pair: v3/v8 for
grant, v4/v9 for reservation, v5/v10 for SQL receiving and v6/v11 for completion.
Selection reads only a bounded schema locator; the corresponding genuine
signature/payload verifier then admits that exact original. Planning v7 is not
a grant, reservation, SQL or completion purpose. Legacy signature domains and
closed payload shapes remain unchanged.

The existing current-root-signed execution-custody original binds all detached
planner, planning-history and receiving-history bytes. A genuinely admitted
planner v3 requires the matching fixed v8/v9/v10 receiving original. The two
independent history admissions must bind identical issuer-policy bytes, old
activation-planner bytes, historical root and typed consume request. Current
configuration, generation, runtime identities and state enrollment come from
the independently signed current planner context, not the historical cohort.

The actual receiving owner rechecks its exact purpose and original association.
Protected replay supplies the admitted historical operation key only for old
activation evidence; current state, new caller/grant authority and new SQL
execution remain rooted in the current context. Existing independently signed
enrollment/resource/key checks still apply. Grant and reservation signing keys
also cannot reuse the historical root.

## Completion is not live execution

The owner retains the signed consume-evidence root and policy interval in its
immutable configuration and checks them on genuine re-admission. Fixed v11
completion can bind a fresh outer root to an independently named older consume
evidence root. `_completion_context_on_work` admits only that v11 purpose,
matches the supplied evidence root/configuration/state against the historical
policy and derives the older activation provenance context from originals.

This private same-call result is never accepted as an authority input. Its
base-only guard preserves actual owner identity, current processing clocks and
the fresh outer interval without recursively taking the custody lock. Expired
consume policy/planner dates are historical facts, not renewed live permission.
The live context method excludes v11, and ordinary completion v6 retains its
strict legacy path.

## Fixed whole-call capacity

Each worker preflights sealed lengths for its root, role and four detached
originals before the first cold body read. Six exact lengths reserve sixteen
footprints plus 128 KiB within the existing 64 MiB ceiling; the nested policy,
old/current planners and repeated receiving admissions must fit that inventory.
Root file delivery enforces the same remaining capture bound before each body
and binds each admitted descriptor identity. Role admission repeats the check
before decoding. No descriptor, role or larger budget is introduced.

Request transports accept an optional tightening cap only. The actual workers
subtract their retained cold reservation, four fixed response footprints and
framing, then reserve eight request footprints before accepting body bytes.
Existing source-specific frame limits still apply. Default transport grammar
and callers remain unchanged; large otherwise valid inventories can refuse.
The original validation work and processing deadline are retained, and no
original delivery expiry is changed.

These are source connections, not runtime validation, production release,
retry permission or evidence that an uncertain prior effect did not happen.
