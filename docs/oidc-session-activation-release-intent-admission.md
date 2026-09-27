# Original release-intent admission

This source-only producer/live verifier authenticates a fresh private release
intent and possession of the original old token. A separate historical verifier
authenticates the exact old intent as evidence, not present permission. Neither
path authenticates a consume commit, opens delivery ciphertext, returns a new
token, executes SQL or establishes
public present permission. It is unbuilt, unexecuted and unprovisioned.

The actual composition is
`authority_oidc_session_activation_release_intent.py`. It combines the distinct
[wire contract](oidc-session-activation-release-intent.md) with genuine
[root-enrolled caller admission](oidc-session-activation-release-intent-enrollment.md).
The original live scope is token-release diagnostic 15.1; the historical seam
supports separately authorized recovery at 15.6. Neither alone completes row 15.

## Original-only interfaces

```text
_verify_on_work(*, intent_bytes, enrollment_bytes, root_public_key,
    forbidden_public_keys, expected_scope, expected_release, old_token_bytes,
    live_window, transport_deadline_ns, work)
    -> _AdmittedIntent(payload, intent_digest, live)

_produce_on_work(*, enrollment_bytes, root_public_key, forbidden_public_keys,
    expected_scope, expected_release, old_token_bytes, caller_private_key,
    live_window, transport_deadline_ns, work) -> original bytes

_verify_historical_on_work(*, intent_bytes, enrollment_bytes, root_public_key,
    forbidden_public_keys, expected_scope, expected_release, old_token_bytes,
    live_window, transport_deadline_ns, work)
    -> _HistoricalIntentEvidence(payload, intent_digest, live)
```

`expected_scope` is closed to `configurationDigest`, `databaseId`,
`generationDigest`, `runtimeClosureDigest`, `callerId` and `receiverIdentity`.
The receiver identity contains the actual three pinned identity digests.
`expected_release` is closed to `activationRequestDigest`,
`activationOperationId`, `consumeRequestDigest`, `deliveryEnvelopeDigest`,
`deliveryScope` and `consumeBinding`. Delivery scope is the existing eleven-field
AEAD scope. Consumption binding contains exactly `packetDigest`,
`pendingDecisionDigest`, `completionRequestDigest`, `effectsDigest` and
`afterVectorDigest`.

The caller supplies these expectations independently. Before any native/key
callback, both whole mutable graphs are detached with exact closed scalar
shapes; original bytes, actual key references, the immutable forbidden-key
tuple and original processing bracket are held. Bounded capture and every
cryptographic step charge the same work. Root enrollment admits the actual
caller key and independently expected scope, rejecting role-key reuse. The
actual caller signature, enrollment digest, enrolled measurement and every
scope/release binding must then agree.

The verifier derives the activation operation ID from the actual independently
expected activation request digest, and derives the delivery ID through the
existing `activation-delivery` derivation. The old token must be the genuine
64-byte URL-safe original accepted by the delivery helper; its actual SHA-256
must equal `deliveryScope.oldTokenDigest`. A posted digest is not possession.
The token never enters the signed graph, output payload or diagnostic digest.

## Freshness and signing

The producer admits the enrollment, target identities and possession before
signing. It requests one actual 32-byte nonce, rejects all-zero or malformed
output without a retry loop, and chooses the real current issue time. Expiry is
clipped to the unchanged processing window, caller age policy and original
delivery expiry. The actual private/public pair must match the enrolled caller.
The resulting original is genuinely signature-verified and joined back to the
same independently held expectations before return.

The live `_verify_on_work` checks the enrolled maximum age/skew, signed lifetime
and original delivery interval against actual current samples. It never accepts
expired intent, uses an old issue time as a clock, or opens a replacement allowance.
Narrowing preserves the original first three epoch/monotonic samples and can
only reduce the absolute bound, age and skew. Sticky guards surround native
steps and final return. A stricter receiving processing window is allowed; it
does not extend the intent's signed expiry. Returned `live()` uses privately
held lifetime scalars and returns a current epoch integer; mutating the ordinary
output payload cannot extend it. No input API accepts that result as authority.

## Historical evidence under separate recovery authority

`_verify_historical_on_work` has the same original-only inputs but a distinct
evidence result. It still performs genuine root enrollment, role-key separation,
caller signature, nonce grammar, exact scope/target/measurement joins, activation
and delivery identity derivation, and actual current old-token possession. No
digest or successful result object replaces any original.

The original signed interval must remain positive, fit its original enrolled
age, expire no later than the original delivery, and obey the original delivery
ordering under the original enrolled skew. These are algebraic checks on
authenticated originals. Expired intent expiry or issue-plus-age is not a
current deadline, and the old issue time is never sampled as now.

Actual processing still uses the supplied work and unchanged opening bracket,
narrowed only by the enrolled processing ceilings and **live original delivery
expiry**. Future-dated originals, expired delivery, elapsed current deadlines or
reversed epoch/monotonic samples fail closed. Current future-date checks use the
minimum of enrolled and supplied processing skew; they do not replace the
original skew in original interval algebra. The returned epoch guard retains
these private scalars and sticky history through final return.

This evidence does not renew the intent or establish present permission. The
surrounding custody composition must independently admit a fresh root recovery
purpose, pin the unchanged durable outcome and exact original identities, and
retain all current guards. Live producer/verifier APIs have no historical flag
and keep their original expiry behavior. This is strict current-source original
authentication, not cross-source historical authority resolution (H05).

## Remaining release boundary

The five consume digests are authenticated **expected identities**, not proof
that their named packet, commit or completion exists. Genuine original-based
commit/completion-to-release admission, exact durable outcome retention,
guarded private opening and separately authorized recovery remain separate
composition requirements; none is supplied by this intent module alone.
There is no new outcome table, successful-result carrier input, AES operation,
service, public action or portal dispatch here.

The actual [release custodian](oidc-session-activation-release-custody.md) must
join the framed identity of the exact intent original to its independent root
pin and supply its own independently admitted scope and role-key exclusions.
Those custody pins alone do not replace this original admission, and this
admission alone does not authorize token release. Private caller key delivery
and target-bound public permission remain separate implementation obligations.
