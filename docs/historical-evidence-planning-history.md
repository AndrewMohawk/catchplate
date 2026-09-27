# Historical evidence-planning history

[`authority_webauthn_evidence_plan_history._admit_history_on_work`](../serverware/authority_webauthn_evidence_plan_history.py)
is a private continuation after the original
[verifier-signed request](historical-evidence-planning-request.md) and
[planner-signed response](historical-evidence-planning-response.md) have actually
authenticated the original request, all three response byte strings, their
commitments and original timing. A stored context or successful-verification
carrier cannot replace those upstream checks.

## Contract

The keyword-only inputs are `envelope_bytes`, `inputs_bytes`,
`evaluation_context_bytes`, authenticated `request_context`, original
`request_issued_at_epoch_ns` / `request_expires_at_epoch_ns`, original
`response_issued_at_epoch_ns` / `response_expires_at_epoch_ns`, independent
configuration `pins`, `maximum_control_age_ns`, and the caller's existing
`live_window` / cumulative `work`. Optional `transport_deadline_ns` only
shortens the current processing bound.

It holds all original bytes, pins, times and a detached request graph before
native callbacks. Existing per-original plan/input/context limits and the
response aggregate limit apply. The derived eighteen-field history takes its
request, before roots and input commitment only from the authenticated request;
configuration, role identities/keys, ages, skew and purpose settings only from
independently admitted pins. Only `databaseCutoffUs`, `nowEpochNs` and
`deadlineEpochNs` come from the original planner context.

The canonical encoding of that derived history must equal the entire original
context byte-for-byte. The actual `EvidencePlanVerifier.verify` then runs once,
performing genuine plan signature, primary-proof, original-input semantics and
resulting-root replay on the same work. Signed plan issue, expiry and database
cutoff must exactly match the derived observations.

## Original time bounds, not a new clock

Both signed control intervals must be positive and within the configured
control age. Response expiry equals request expiry, which cannot exceed the
authenticated request context's deadline. Response issuance cannot predate
request issuance beyond configured skew.

Plan issuance and cutoff must lie between request issuance minus skew and
response issuance plus skew. The plan's deadline cannot exceed request expiry;
its exact signed expiry is the lesser of that deadline and issue time plus
configured plan age. The signed response must have been issued before that
original plan expiry. Cutoff must also precede expiry and remain within skew
of plan issuance. Request/response issuance and planner observations cannot be
future-dated beyond the current processing sample plus configured skew.

Expired historical originals can satisfy these comparisons. Their timestamps
are never substituted for the current clock, and no live verifier is given an
expiry bypass. Current processing still checks the caller's unchanged wall and
monotonic window, rollback floors and inherited deadline. No new window, work
allowance or original expiry is generated. Signed planner observations are not
independently trusted database-clock truth or proof that roots remain current.

The result is an ordinary owned history dictionary, not an authority token.
It does not authorize SQL, fresh execution, registration completion or a public
recovery action. Caller permission, original caller/grant/reservation/completion
joins and durable retention remain separate composition requirements. No
network, SQL, signing, storage or public route is added by this module.

This implementation is source-only and unexecuted. Deferred frozen verification
must cover genuine expired exchanges, tampered request/context/plan joins,
noncanonical or oversized originals, proof/semantic failures, every original
temporal boundary, future observations, and processing expiry/work exhaustion.
