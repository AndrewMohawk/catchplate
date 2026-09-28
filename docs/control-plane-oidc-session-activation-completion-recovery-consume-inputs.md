# Original-only inputs for fresh consume continuation

`control_plane_oidc_session_activation_completion_recovery_consume_inputs`
extracts the existing raw16 consume-input request only from the exact active
`completion_recovery_consume._ConsumeAttempt`. The actor must be the genuinely
fresh `consume` purpose, activation profile, on the source-fixed consume path.
This is a private owner connection, not a public action or successful execution
result. No `_ActivationPermission` is constructed, revived or accepted.

The source owner's one-use `_require_inputs_call` selects the actual historical
controls, acknowledged activation raw4 and genuine receiving guard before
extraction. The helper requires the `inputs` phase and empty original seals.
It repeatedly checks actual owner/global/actor association, parent/root/custody
identity, cold enrollment bytes, retained originals, work/lifetime and old-token
possession around the original current and receiving guards. It accepts no
caller-supplied completed result or substitute continuation.

The historical activation controls already retain the needed original bytes;
there is no second journal read or reconstructed preparation body:

| Raw16 positions | Exact source |
| --- | --- |
| 0–3 | Actual acknowledged activation response raw4 |
| 4–5 | Historical signed activation plan and encrypted execution original |
| 6–8 | Original reserve request, receipt and snapshot |
| 9–10 | Historical activation caller authorization and grant |
| 11–12 | Independently configured activation caller and grant enrollments |
| 13–14 | Original expectations bytes and independently joined before-vector |
| 15 | Actual fresh actor's 64-byte old-token possession |

The `.223` extractor takes the caller/grant enrollment originals from the exact
selected historical target authority and requires the controls to retain that
same authority object. Their old root is distinct from the owner's current
root; neither current enrollment substitution nor a root supplied by request
data is accepted. This source connection does not lift the actor's historical
effect refusal. The signed input bridge and actual current-authority planning
and caller joins remain separate from raw16 extraction.

Existing transport/frame limits and raw13 activation framing are applied on the
same work. The actual old token is grammar-checked and hashed against the genuine
historical target commitment. Expectation bytes are preserved unchanged: the
consume-input issuer still checks their canonical encoding and independently
re-admits the complete original inventory under its separately supplied policy.
Extraction is not that admission and does not renew old signature validity.

`INPUT_RESERVATION_BYTES` is a fixed 16 KiB bookkeeping reservation carried once
inside the future capacity reserved before the first historical target body.
The helper creates reference tuples, not new copies of large prepared bodies.
The selected complete inventory must fit its already-held reservation and the
existing whole-request bound. There is no new 64 MiB allowance or process-heap
claim; the same ledger is charged for shape/hash work and referenced originals.

Raw16 is ephemeral DATA and includes old-token possession. It must not be
journaled, logged, emitted as HTTP or retained beyond the actual same-call
continuation. The helper itself opens no socket, key or private reader and
performs no SQL, completion, release or cookie effect. Missing local records
prove neither SQL nonexecution nor retry authority. Fresh independently
configured consume authority, the same durable one-use consume boundary and
protected completion remain required before a public continuation is enabled.
Source only: unbuilt, unexecuted and unprovisioned.
