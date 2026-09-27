# Historical registration caller authorization

The private [`_verify_historical_on_work`](../serverware/authority_registration_execution_authorization.py)
authenticates an original caller authorization for
`webauthn.registration.evidence.admit`, including an expired original. It does
**not** make that authorization executable again. The existing live
`_verify_on_work` and its expiry checks are unchanged.

## Inputs and checks

The keyword-only API takes `authorization_bytes`,
`authorization_enrollment_bytes`, `current_root_enrollment_bytes`,
`grant_enrollment_bytes`, independently supplied `root_public_key`,
`configuration_digest`, `planner_public_key`, `evidence_public_key`, and the
caller's existing `live_window` and cumulative `work`. Optional
`transport_deadline_ns` can shorten that same processing window; it cannot
renew it.

Before decoding, cryptographic operations or clock callbacks, it retains exact
immutable originals and validates the scalar/window inputs. Original limits
are 64 KiB for the request, 16 KiB for caller enrollment, 128 KiB for current-root
enrollment, and 16 KiB for grant enrollment: at most 224 KiB together. Existing
bounded decoders, canonical-byte checks and source-version rules apply.

The verifier checks the genuine root-signed caller/current-root/grant
enrollments, caller-key separation from root, computation, completion, state,
authorizer, planner and evidence keys, and the actual caller signature. It
joins configuration, database, generation, enrollment identities, caller
identity/measurement and intended authorizer audience. It recomputes the
operation identity from the fixed operation and signed request digest, and
the authorization identity from the exact original signed bytes.

The original positive issue/expiry interval must fit the authenticated caller
enrollment's maximum age. Those enrollment formats do not contain calendar
validity intervals; this helper does not invent them. Future-issued originals
beyond enrolled clock skew fail. Expiry in the past does not fail this
historical-only check. Actual current-processing wall and monotonic checks
still reject expired processing windows or clock rollback, including the
inherited monotonic deadline. No new clock window or work allowance is opened.

## Result and remaining boundary

The distinct frozen `_HistoricalAuthorization` contains only authenticated
original request/operation/authorization identities, the original issue and
expiry, and immutable configuration, database, generation, enrollment,
caller/audience and enrolled age/skew metadata. It contains no live window,
deadline, live-check callback, signing key or permission token. No public
entrypoint accepts that result as authority.

This is one prerequisite for historical completion admission, not an enabled
recovery workflow. A future caller must still authenticate the original
verifier-signed planning request, planner-signed response and historical
expectations; join the original grant/reservation/completion; and enforce
present caller permission and appropriate durable retention. The current
[handoff admission](registration-execution-handoff-admission.md) remains
explicitly live-only. Independently authorized caller/key provisioning and
root/configuration provenance remain external requirements. A valid historical
signature does not prove present human approval, current pending state,
revocation status, database effects, SQL permission or credential finalization.

No network, SQL, signing, storage, public route or deployment is added here.
This source-only implementation has not been executed. Deferred frozen
verification must cover expired-but-consistent originals versus live rejection;
signature, scope, key-separation and operation-identity negatives; noncanonical
or oversized originals; interval/future-time failures; and unchanged current
window/work exhaustion and inherited-deadline behavior.
