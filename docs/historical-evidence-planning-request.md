# Historical evidence-planning request authentication

[`authority_webauthn_evidence_plan_request_history.py`](../serverware/authority_webauthn_evidence_plan_request_history.py)
adds a separate private original-byte verifier. The existing live request
verifier and its expiry semantics remain unchanged. This implementation is
source-only; it has not been executed or admitted for production.

The keyword-only `_verify_on_work` accepts the same `control_bytes`,
`context_bytes`, `inputs_bytes`, independently admitted `pins`,
`generation_sequence`, `generation_digest`, `verifier_public_key`,
`maximum_control_age_ns` and `work` as the live request verifier. It additionally
requires the caller's already opened current `live_window`, with optional
`transport_deadline_ns` to impose an earlier monotonic cutoff. It never opens
a replacement window or work allowance.

It reuses the actual request helpers to require:

- Bounded immutable originals, exact source/schema/purpose and canonical bytes.
- A genuine verifier Ed25519 signature, independent configuration/generation/
  operation scope, and actual verifier/planner key separation.
- Both complete original context and input byte commitments **before** context
  decoding, followed by exact context shape, canonical bytes, input identity,
  typed-request digest and operation-ID reconstruction.
- Positive original issuance preceding expiry, an interval within the source
  and configured maximum age, and expiry no later than the authenticated
  original context deadline.
- No issuance later than actual current processing time plus the configured
  clock skew. Current processing remains inside the unchanged caller window
  and inherited deadline, with nondecreasing local clock samples.

An old request may already be expired. Its original issue time is never supplied
as a substitute for the current clock, and its old expiry neither renews nor
defines the caller's present processing window. Local clock/deadline checks are
not a hard watchdog or independent time/currentness authority.

The distinct frozen `_HistoricalPlanRequest` contains only an owned `context`
dictionary and its original `issued_at_epoch_ns` and `expires_at_epoch_ns`.
Frozen fields do not make the nested dictionary an authority token. No live
window, executable result, successful replay claim or renewed permission is
returned. Before using historical observations, the caller must authenticate
the complete original planning response and perform the required plan,
evidence, enrollment, authorization and grant joins on the same work allowance.
Authenticated request roots alone do not establish the current database head.
This helper performs no signing, transport, SQL, reserve, completion or replay
consumption, and it introduces no historical bypass into existing live APIs.
