# Historical evidence-planning response admission

[`authority_webauthn_evidence_plan_response_history.py`](../catchplate/authority_webauthn_evidence_plan_response_history.py)
authenticates an original planner-signed response for historical inspection.
It is separate from the unchanged [live response verifier](../catchplate/authority_webauthn_evidence_plan_response.py).
An expired response can be inspected here; this does not make it live again,
authorize execution, renew a grant or establish current state. This source has
not been built, imported, tested or executed.

## Required originals and independent scope

The private `_verify_on_work` takes the live verifier's exact original controls
and bodies: `control_bytes`, `request_control_bytes`, `envelope_bytes`,
`inputs_bytes` and `evaluation_context_bytes`. It also takes independently
admitted `pins`, `generation_sequence`, `generation_digest`, the actual
`verifier_public_key`, genuine original `request_issued_at_epoch_ns` and
`request_expires_at_epoch_ns`, `maximum_control_age_ns` and the existing `work`.
Instead of `request_window`, it requires the caller-owned **current processing**
`live_window`; optional `transport_deadline_ns` only narrows that original bound.

The caller must genuinely verify the original request and independently admit
keys/configuration/history in the same call. Timing arguments are observations
from that verification, not a successful DTO or substitute for request
authentication. This helper accepts no caller-selected clock, verifier callback,
successful response object, replacement work allowance or private key.

The real shared primitives enforce:

- Exact source schema, purpose and revision, closed canonical signed control,
  signature encoding and original per-body/aggregate bounds.
- Actual planner Ed25519 signature and independently pinned SPKI, configuration,
  generation and source operation; planner/verifier keys remain distinct.
- Every original request-control and raw3 body hash **and** byte count,
  including the exact evaluation-context original.

No body commitment is reconstructed from a caller's claimed successful plan.
Signature verification does not replace the caller's full semantic plan replay.

## Historical time versus current processing

Both original request and response intervals must be positive and within the
admitted control-age ceiling and source maximum. The response must retain the
request's exact original expiry, cannot precede its issue beyond the configured
clock skew, and neither issue can be in the future beyond that skew relative
to the actual processing clock. Historical expiry and age alone are not failure
conditions on this path.

The supplied seven-field processing window is validated unchanged. Actual epoch
and monotonic checks spend the same caller work before, between and after the
verification phases. The original monotonic deadline is clipped only by the
optional inherited transport deadline; rollback and expiry fail closed. No
window is opened from signed issue time, no expired deadline is advanced, and
no synthetic historical clock is passed to the live verifier.

The result is only frozen `_HistoricalPlanResponse(issued_at_epoch_ns,
expires_at_epoch_ns)`. It has no live window, executable plan, current-head
claim or permission field and is never accepted as an input authority token.
Present-caller/purpose admission, genuinely live execution controls and
independent action-time currentness remain separate requirements.

## Deferred frozen verification

Planned coverage includes valid expired originals; malformed, duplicate or
noncanonical controls; planner signature/SPKI/key-separation failures; changed
request/context/body commitments; scope mismatch; invalid original intervals,
changed expiry, reversed original issue ordering and future issue; and unchanged
processing-window, transport-bound, rollback and work-exhaustion rejection.
Live-verifier expiry behavior must remain unchanged. These are planned checks,
not executed evidence or a production acceptance claim.
