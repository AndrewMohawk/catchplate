# Private consume execution-original replay

[`authority_oidc_session_activation_delivery_execution_replay.py`](../catchplate/authority_oidc_session_activation_delivery_execution_replay.py)
genuinely replays the original `oidc.session.activation-delivery.consume` plan
and encrypted private document. It returns ordinary same-call token-free facts,
not a grant, reservation, SQL permission, successful-proof input or token release.
This is live-only, current-source admission: no expired-plan or older-cohort fallback.

```text
_replay_on_work(*, envelope_bytes, encrypted_originals_bytes,
    expected_request, expected_scope, expected_journal_digest,
    state_enrollment_bytes, before_vector_bytes,
    activation_expectations, activation_scope,
    planner_public_key, activation_planner_public_key, operation_public_key,
    state_root_public_key, historical_custody, bundle_key,
    live_window, transport_deadline_ns, work) -> _ReplayedDelivery
```

All external graphs are detached and immutable originals, actual key references,
window and history owner are held before hashing, clock or native callbacks.
The owning receiver must independently authenticate their provenance. In
particular, request/scope/journal identity, state enrollment, complete current
before-vector and activation expectations/scope are not learned from ciphertext.
The exact consume-grant historical owner is required before private opening;
the old consume-planning and completion purposes cannot substitute for it.
Its original root, enrollment and request bindings are checked, and genuine
current admission supplies retained owner guards and only narrower processing
bounds. The consume bundle key must differ from both historical AES purposes;
its independent delivery and other key-separation pins belong to the receiver.

## Known signature before opening, then full original replay

The consume planner key authenticates the known envelope, request identity,
configuration and planner identity before AES decryption. Its original interval
is checked against actual current time and independent scope; the remaining
window is narrowed to its signed expiry without changing the opening samples.
The distinct [consume bundle](oidc-session-activation-delivery-execution-bundle.md)
then opens with the independently derived seven-field context. The
[retained-original decoder](oidc-session-activation-delivery-journal.md)
reconstructs the real context, query records and proofs from the canonical
sixteen-field document; it is not an authority carrier.

The receiver exactly compares stored request/scope, activation expectations and
activation scope to independently supplied data, and compares the original
envelope, state enrollment and complete vector bytes. It source-validates the
entire independent vector and joins every selected primary root and all seven
counted heads. Stored pins never become independent expectations.

The actual consume-plan full verifier runs once on those originals. It repeats
current-state signatures, old-token possession/current policy and complete read
proofs, completed-activation provenance through genuine grant-purpose history
custody, and the three actual effects with their five indexed writes. The
signed proof/context/input/transition commitments must match that derivation.
Neither a producer result nor authenticated ciphertext alone can replace it.

## Ordinary derived output and remaining boundary

The distinct `_ReplayedDelivery` contains the typed request, original signed
plan/ciphertext raw2, their exact record identity, canonical before/after complete
vectors and digests, token-free result/mutations, original plan interval and
identity, work units, narrowed window/deadline, expiry and a same-call live guard.
The raw2 identity uses the bundle's fixed `RECORD_IDENTITY_DOMAIN`. Selected
private rows, plaintext tokens, keys, stored document and historical owner are
not output fields. Delivery mutations contain encrypted delivery data, not a
released token; the result still says `tokenReleased: false`.

Only genuine replayed roots are merged into the complete vector; unrelated
descriptors stay unchanged and the actual source delta validator checks the
operation's writable inventory and event bounds. Reusing these neutral helpers
does not register consume in generic replay or return its `_ReplayedPlan` type.

The caller's work remains cumulative for capture, decryption, reconstruction,
proofs, commitments and output. The original clock bracket and positive inherited
deadline remain in force, with custody, plan, state and delivery guards retained
through the final return. The returned guard returns actual current time and
must remain live during same-call downstream work; no later API accepts this
object as proof. No allowance is renewed and no retry, signing, durable outcome,
execution or plaintext-release path is added here. Actual consume-grant issuance
and its cold service remain separate integration work. Source only: unbuilt,
unexecuted, unprovisioned, with no production acceptance claim.
