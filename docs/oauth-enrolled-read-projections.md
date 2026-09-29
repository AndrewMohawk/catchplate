# Read-only enrolled OAuth observations

The enrolled branches of `GET /api/oauth/pending` and the pending/work collections
in `GET /api/bootstrap` use bounded, source-fixed `SELECT` queries. They do not
call the development helpers that mark pending rows expired, lock revocation
work, or rewrite interrupted exchange state during a read. Other bootstrap
collections are outside this change.

Selection comes from the actual retained cold application owner. An admission
error or expired owner fails the observation with a generic unavailable response;
it does not select development, return invented empty history, or run cleanup.
The independently unconfigured development profile retains its existing readers.
The original read authorization remains: authorized administrators can observe
all selected rows, while other authorized credential readers retain the existing
requester/actor filter. A reader does not need activation's literal
`credential_owner` role merely to observe data. Readers without credential-view
permission continue to receive no credential collections from bootstrap.

Pending rows retain the existing public sixteen fields. The projector selects
only those scalar columns plus the metadata/review originals needed for the
existing pure review validator. It never selects, decrypts or returns token
ciphertext. Duplicate or malformed review JSON, unexpected review fields,
invalid scalar types or inconsistent review/account bindings fail the whole
observation. No malformed JSON becomes an empty review; no null status becomes
`pending`; and expired timestamps never cause an update. The stored status and
expiry are observations, not a statement that activation is presently admissible.

Work retains the existing public eight fields. Selection includes every retained
`enrolled-oauth-exchange/v1` work state as well as the existing persisted issuance
uncertainty states. Thus reserved, in-flight, held, cleanup-reserved and terminal
local observations are not omitted merely because a read no longer runs the old
expiry writer. Status strings and original timestamps remain unchanged. In
particular, `revocation_observed_accepted` and `revocation_observed_rejected`
describe local HTTP observations, not proved provider revocation. The controlled
source's `last_error` remains null; arbitrary provider error bodies are not added.

The limits are 64 pending rows, 100 work rows, 32 KiB for each metadata/review
original and 1 MiB per completed public collection. Queries request one extra
row to detect overflow and fail rather than silently truncate history. The
actual owner and bounded wall/monotonic read window are checked around database
reads and projection. These are bounded observations, not an atomic snapshot of
both collections, a continuous-state guarantee or a transferable permit.

Valid integer fields, including the enrollment generation in review, remain
exact Python integers in the server projection; they are not converted to
floating point or strings to fit a browser. Activation commits the exact server
originals using its four string binding fields, not an echoed numeric review.
Review display is data only. This differs from consent's nanosecond-bearing
18-field request, whose portal retains the exact raw JSON for its required echo.

The enrolled portal work panel has no confirm/clear/retry controls. It displays
stored states with explicit incomplete/unknown-evidence wording, and even an
empty collection is not a clean-state or no-issuance proof. The generic uncertainty
resolution handler refuses enrolled/unavailable profiles before making a request.
Cancellation, provider cleanup, retry and history retirement require separate
controlled successors; these readers authorize none of them.

This is source integration only. No database, browser, provider, build, test or
runtime execution is claimed.
