# Original OIDC activation plan

This is a separate source-only signed-plan contract for `oidc.session.activate`.
It does not widen the three-operation WebAuthn transition plan, its raw-four
inputs or its custody protocol. The contract codec does not establish a
signature, current caller permission, database/root currentness or a successful
activation. No build, cryptographic execution or runtime verification is claimed.

## Public wire and original commitments

[`authority_oidc_session_activation_plan_contract.py`](../serverware/authority_oidc_session_activation_plan_contract.py)
defines the closed payload
`serverware.policyAuthorityOidcSessionActivationPlan/v1` and the three-field
envelope `serverware.signedPolicyAuthorityOidcSessionActivationPlan/v1`:
`schema`, `payload`, `signatureBase64Url`.

The exact 22 payload fields contain only fixed source metadata, bounded
identities, digest/count commitments and the original issue/expiry interval:

| Group | Fields |
| --- | --- |
| Fixed source | `schema`, `sourceRevision`, `operation`, `operationManifestDigest`, `queryManifestDigest`, `authorizationManifestDigest`, `handlerContractDigest` |
| Independently admitted scope | `requestDigest`, `operationId`, `configurationDigest`, `plannerIdentity`, `plannerSpkiDigest` |
| Detached originals | `proofDigest`, `proofByteCount`, `contextDigest`, `contextByteCount`, `inputsDigest`, `inputsByteCount`, `transitionDigest`, `transitionByteCount` |
| Original lifetime | `issuedAtEpochNs`, `expiresAtEpochNs` |

There are no plaintext-token, custody-key, raw assertion, raw envelope, result
graph or supplied-success fields. Planner identity is the existing closed
three-digest identity, not a key-enrollment claim. Payload and envelope are each
capped at 16 KiB, 128 JSON nodes and depth four. The positive lifetime cannot
exceed the existing 30-second source plan ceiling; actual freshness and the
independent configured interval remain the producer/verifier's responsibility.

`_source_fields()` returns a fresh fixed seven-field source projection.
`_capture(value, *, envelope=False, work)` owns and bounds the complete graph.
`_encode_on_work` and `_decode_on_work` use the same arguments; decoding requires
canonical originals and rejects duplicates, unknown fields and alternate
encodings. They create no new work allowance and return ordinary data only.

`_body_commitments_on_work(*, proof_bytes, context_bytes, inputs_bytes,
transition_bytes, work)` captures all four exact immutable originals and checks
their individual and aggregate 64 MiB bounds before hashing any of them. It
returns the eight digest/count fields, derived from actual bytes rather than
caller-supplied successful commitment objects. This opaque helper does not
parse or admit the detached bodies.

The domain-separated body identities are
`serverware.policyAuthorityOidcSessionActivationProof/v1`,
`serverware.policyAuthorityOidcSessionActivationContext/v1`,
`serverware.policyAuthorityOidcSessionActivationPrivateInputs/v1` and
`serverware.policyAuthorityOidcSessionActivationTransition/v1`. The last commits
the complete canonical `mutations`, `result` and `workUnits` graph, including
the real audit-capacity query/mutation work; it does not duplicate a separate
`kernelWorkUnits` allowance.

## Signing, privacy and same-call replay boundary

The distinct signing domain is
`serverware.policyAuthorityOidcSessionActivationPlanSignature/v1`; the envelope
identity domain is `serverware.policyAuthorityOidcSessionActivationPlanIdentity/v1`.
The actual producer must bind the real independently enrolled planner public
key/SPKI and private-key pair, perform genuine original replay, then use the
existing metered Ed25519 sign-and-verify primitive over the domain-framed
canonical payload. The verifier must authenticate the signature and every
detached byte commitment before decoding context or relying on original-body
contents. A received context cannot supply independent expectations.

The owner retains the exact assertion, old/new server token originals and
encrypted delivery envelope privately. `inputs_bytes` is only a canonical
closed digest/count projection derived from those actual originals: it must
never serialize either token's plaintext or the custody key. The exact
assertion and ciphertext also remain privately retained, not embedded in the
outward envelope. The owner—not this opaque hashing helper—must enforce that
projection. The independently admitted AEAD key remains outside serialized
inputs, plan, context and return representations.

The request first binds target session/credential/challenge, old/new token
digests, original assertion digest, configured TTL and business intent. Its
digest determines the delivery identity; only then can the exact delivery
envelope be sealed for the selected database creation/expiry times. The genuine
transition decrypts that original and derives the actual effects before their
commitment is signed. No ciphertext-digest request argument introduces a
request/delivery/encryption cycle. See the separate
[delivery contract](oidc-session-activation-delivery.md).

Full activation replay requires the original assertion and tokens, independently
admitted custody key, target/user/session policy and trust, complete selected
rows, primary proofs, counted-query heads/frontiers and independent before
roots. A public-key signature alone cannot replace that replay or decrypt the
private delivery. Existing generic raw-four retention preserves complete input
bytes and is not a place to insert a new plaintext-secret serialization.

## Actual producer and verifier

[`authority_oidc_session_activation_plan.py`](../serverware/authority_oidc_session_activation_plan.py)
implements `_produce_on_work` and `_verify_on_work`. Both take the exact
`KernelContext`, original typed request, independent scope, original assertion,
old/new token bytes, ciphertext and private custody key, primary/range proofs
and independent roots, actual planner key, and existing work/window/deadline.
Neither accepts an alleged successful replay or a caller-computed transition.

The independent scope is exactly `userId`, `sessionId`, `credentialId`,
`credentialRecordId`, `challengeId`, `rpId`, `origin`, `authenticationPolicy`,
`trustPolicy`, `configurationDigest`, `plannerIdentity`, `plannerSpkiDigest`,
`maximumPlanAgeNs`, `maximumClockSkewNs`, and `deadlineEpochNs`. Request and
operation digests are genuinely recomputed and joined to the owned context.
All raw graphs and exact immutable originals are held before native callbacks.
This captures independently supplied expectations; it does not enroll them.

The producer constructs private canonical bodies from the actual read records,
proof originals and independent scope. Its input body contains only four
domain-separated digest/count pairs derived from the assertion, old token, new
token and ciphertext; it has no token or key serialization. It calls the real
full transition, including audit capacity, before committing its six mutations,
result and complete work count. Actual key/SPKI and key-pair checks precede
Ed25519 signing and verification of the signature produced. Only the closed
signed envelope is returned; no original or private key is returned with it.

The verifier requires the originals again, independently binds request and
planner/configuration pins, verifies the actual signature, reconstructs and
compares the proof/context/input byte commitments, then invokes the actual
full transition again and compares its complete transition commitment. It
returns only that newly computed ordinary `KernelTransition`, not authority to
execute it. A forged result, correct signature over incorrect effects, altered
original or supplied secret digest cannot substitute for this replay.

Both calls keep the supplied work and original dual-clock window, including
the inherited earlier monotonic deadline. The plan expiry is clipped to the
original invocation, configured age, provider/session/pending-session,
challenge and delivery intervals. Sticky liveness checks bracket signing and
verification and run again before return. Verification is active-window only;
it cannot re-date an expired plan or establish cross-host historical admission.

The actual [read-acquisition owner](oidc-session-activation-planning.md) and
these signing mechanics remain separate pieces. A configured owner must still
join them with genuine token generation/sealing and private durable original
retention; callers cannot publicly supply this private key/policy interface.

## Remaining implementation boundary

The codec adds no writer, indexed-after-root authority, durable private-original
retention, registered execution owner, reservation, protected SQL, one-use
delivery or activation/recovery route. Original current processing work and
window/deadline must remain unchanged through the real owner; an encoded or
signed plan does not renew the assertion, session or delivery lifetime.
The [retained-finalization prerequisite](retained-registration-activation.md),
[original assertion admission](oidc-session-activation-admission.md) and
private token delivery remain separate inputs to that unfinished flow.

Verification is deferred until the source freeze. Required cases include
actual successful original replay, bad signatures/keys, altered request/scope/
body commitments, mutation and work-count disagreement, raw secret absence in
the output, token/envelope tampering, original expiry and clock reversal,
post-sign failure and cumulative work exhaustion. No such test was run here.
