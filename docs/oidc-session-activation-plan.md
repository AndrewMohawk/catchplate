# Original OIDC activation plan

This is a separate source-only signed-plan contract for `oidc.session.activate`.
It does not widen the three-operation WebAuthn transition plan, its raw-four
inputs or its custody protocol. The contract codec does not establish a
signature, current caller permission, database/root currentness or a successful
activation. No build, cryptographic execution or runtime verification is claimed.

## Public wire and original commitments

[`authority_oidc_session_activation_plan_contract.py`](../serverware/authority_oidc_session_activation_plan_contract.py)
defines the closed payload
`serverware.policyAuthorityOidcSessionActivationPlan/v2` and the three-field
envelope `serverware.signedPolicyAuthorityOidcSessionActivationPlan/v2`:
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
`serverware.policyAuthorityOidcSessionActivationPrivateInputs/v2` and
`serverware.policyAuthorityOidcSessionActivationTransition/v1`. The last commits
the exact canonical indexed-transition original from the genuine
[write replay](oidc-session-activation-writes.md): fixed source/request identity,
write-proof digest, complete `mutations`, `result`, `workUnits`, business and
authorization after-roots, and all thirteen counted after-heads. Work includes
the real audit-capacity query/mutation work, not a separate duplicated allowance.

## Signing, privacy and same-call replay boundary

The distinct signing domain is
`serverware.policyAuthorityOidcSessionActivationPlanSignature/v2`; the envelope
identity domain is `serverware.policyAuthorityOidcSessionActivationPlanIdentity/v2`.
The actual producer must bind the real independently enrolled planner public
key/SPKI and private-key pair, perform genuine original replay, then use the
existing metered Ed25519 sign-and-verify primitive over the domain-framed
canonical payload. The verifier authenticates the signature, repeats genuine
original replay and compares every detached byte commitment before returning.
A received context cannot supply independent expectations.

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
roots. It also requires the canonical original write proof and an independently
admitted, fixed thirteen-head union; heads copied from that proof are not
independent pins. A public-key signature alone cannot replace replay or decrypt
the private delivery. Existing generic raw-four custody is not widened into a
plaintext-secret serialization.

## Actual producer and verifier

[`authority_oidc_session_activation_plan.py`](../serverware/authority_oidc_session_activation_plan.py)
implements `_produce_on_work` and `_verify_on_work`. Both take the exact
`KernelContext`, original typed request, independent scope, original assertion,
old/new token bytes, ciphertext and private custody key, primary/range proofs
and independent roots, required `write_proof_bytes` and
`expected_counted_heads`, actual planner key, and existing work/window/deadline.
V2 also requires `state_enrollment_bytes`, `state_root_public_key`,
`complete_root_vector_bytes`, `head_query_bytes` and `head_observation_bytes`.
The head input is an exact tuple of thirteen closed dictionaries with
`indexId`, `indexRevision`, `rootDigest` and `leafCount` in source-fixed order.
Neither call accepts a successful replay carrier or caller-computed transition.

The private `_verify_full_on_work` has exactly the same explicit inputs as
`_verify_on_work` and performs that same genuine verification and indexed replay
once. Its frozen internal `_VerifiedPlan` retains `invocation` (the owned
`_Invocation`), `write_result` (the actual `writes._ReplayedWrites`), `payload`
(the owned authenticated payload dictionary), and `plan_digest` (the actual
envelope identity under `contract.IDENTITY_DOMAIN`). The existing verifier is
an explicit-signature wrapper returning only `write_result.transition`; no
caller can submit this result instead of originals. This private data includes
secret-bearing replay inputs and must not be serialized or exposed publicly.
The envelope digest and return remain within the original replay's final live
guard, supplied work, window and inherited deadline. No allowance is reopened.

The independent scope is exactly `userId`, `sessionId`, `credentialId`,
`credentialRecordId`, `challengeId`, `rpId`, `origin`, `authenticationPolicy`,
`trustPolicy`, `configurationDigest`, `plannerIdentity`, `plannerSpkiDigest`,
`maximumPlanAgeNs`, `maximumClockSkewNs`, and `deadlineEpochNs`. Request and
operation digests are genuinely recomputed and joined to the owned context.
All raw graphs and exact immutable originals are held before native callbacks.
This captures independently supplied expectations; it does not enroll them.

## Original planning-state admission

V2 requires the separate [nonce-bound head observation](authority-current-root-head.md),
not a completion-recovery lookup or a root-signed launch snapshot alone.
[`authority_oidc_session_activation_state.py`](../serverware/authority_oidc_session_activation_state.py)
binds the exact fifteen-field scope, assertion, old token and complete vector to
the query's context digest. The actual cold caller generates a fresh 32-byte
challenge; neither a supplied nonce nor a successful observation object can
replace that exchange. Root enrollment, state signature, query commitment and
vector identity are genuinely reverified by both plan production and receiving
verification. Either pending-state field being non-null prevents planning.

The full source/manifests/vector inventory is decoded before projecting roots.
The actual semantic replay inputs must equal its business/authorization roots
and all thirteen counted heads. A signed unrelated vector or a copied head
subset cannot supply these expectations. The four exact originals—enrollment,
complete vector, head query and signed observation—each contribute a distinct
digest/count entry in the v2 private-input body, alongside assertion, old/new
tokens and delivery envelope. The independent state root key is never serialized.

Plan expiry and its live guard are bounded by the original observation expiry,
in addition to the request window, inherited deadline and selected row lifetimes.
Retained verification repeats the same original observation within that interval;
it neither generates another challenge nor claims a newly observed head. V1 plans
lacking these commitments are not admitted as v2. Source/configuration migration
remains separate; the distinct historical verifier below authenticates originals
without making an expired observation current.

This is an observation of the enrolled, independently admitted local state owner.
It does not reserve that head, make the host rollback-resistant or authorize SQL.
State may change after observation: action-time rechecking and atomic one-use
execution remain mandatory, as do independently operated production witnesses.

## Retained read inputs

`_capture` holds the exact immutable write bytes and detaches the independent
head dictionaries alongside every other caller graph before native callbacks.
`_read_inputs(invocation, work)` projects a fresh, ordinary nine-field graph for
private original retention: `schema`, `selectedRows`, `beforeProofs`, `readHeads`,
`queryFrontiers`, `queryReads`, `businessBeforeRoots`, `authorizationBeforeRoots`
and `countedBeforeHeads`. Its schema remains the existing proof domain; the
head/root descriptors are data, not independent authority merely by storage.
Read heads/frontiers retain the existing raw array shapes, and each query-read
record retains its five fields and exact original declaration/resolution text.
Every tuple is normalized into an actual JSON list using the same supplied
work and bounded byte/node/depth accounting, so producer, journal and retained
verifier share one storage graph without a consumer-specific fallback.

The producer constructs private canonical bodies from those real read records,
proof originals and independent scope. `writeProofBase64Url` binds the exact
write original into the proof body; the context body binds the independent
thirteen before-heads. Base64 allocation is bounded first, and both producer
and verifier enforce the four detached bodies' aggregate 64 MiB ceiling.
The input body contains eight domain-separated digest/count pairs derived
from the assertion, old token, new token, ciphertext and four state originals;
it has no token or key serialization. The actual
`authority_oidc_session_activation_writes._replay_on_work` derives the full
six-mutation transition, reconstructs twelve indexed write frontiers and all
primary after-roots, and preserves the read-only publication head in the full
thirteen-head result. Its exact `transition_bytes`, including those derived
roots and heads, supply the signed commitment. Actual key/SPKI and key-pair
checks precede Ed25519 signing and verification of the signature produced. Only the closed
signed envelope is returned; no original or private key is returned with it.

The verifier requires the originals again, independently binds request and
planner/configuration pins, verifies the actual signature, reconstructs the
proof/context/input bodies, then invokes actual indexed replay and compares
all four complete body commitments. The existing transition-only wrapper
returns only that newly computed ordinary `KernelTransition`; the private full
variant retains the same call's authenticated inputs and actual indexed result
without repeating replay. Neither return is authority to execute it. A forged
result, correct signature over incorrect effects, altered
original, substituted head, invalid write frontier or supplied secret digest
cannot substitute for this replay. No caller can supply derived after-roots.

Both calls keep the supplied work and original dual-clock window, including
the inherited earlier monotonic deadline. The plan expiry is clipped to the
original observation, invocation, configured age, provider/session/pending-session,
challenge and delivery intervals. Sticky liveness checks bracket signing and
verification and run again before return. After genuine write replay, both
paths retain that same call's `live` closure and `valid_until_epoch_ns`; signing
cannot discard its narrower original lifetime. These live verification APIs are
active-window only; they cannot re-date an expired plan or establish cross-host
historical admission.

The actual [acquisition owner](oidc-session-activation-planning.md) supplies
read and write originals from one read-only database snapshot. The source
[`OidcSessionActivationPlanOwner`](../serverware/authority_oidc_session_activation_plan_owner.py)
now composes it with signing and [encrypted original retention](oidc-session-activation-journal.md),
and the explicit successor planning factory constructs that real owner.
`prepare` returns only token-free request/scope/envelope originals and local
locators; `verify_retained` requires the known exact envelope, independent
request/scope/roots/thirteen heads, and genuinely replays the retained originals.
It remains live-only, not expired-history or lost-locator recovery. These
configured APIs do not themselves admit cold keys or establish current roots,
and callers cannot publicly supply this private key/policy interface.
The separate [cold service](oidc-session-activation-planner-delivery.md) now
authenticates root originals before this composition, including its complete
planning snapshot; fresh off-host latest-head authority remains separate.

## Separate historical replay

The [historical full-plan verifier](oidc-session-activation-historical-plan.md)
adds `_verify_historical_full_on_work` with the same original inputs and a
distinct private `_HistoricalVerifiedPlan`. It authenticates the original
signature before passing its interval to genuine historical assertion, delivery,
complete-read and indexed-write replay. All detached commitments and derived
roots/heads are checked again. No live API accepts that result instead of originals.

[Historical head/state admission](oidc-session-activation-historical-state.md)
rechecks the exact enrollment/query/observation/vector and nonpending state.
Because plan issue records the processing opening rather than signing time,
the original plan/head intervals must have a possible live overlap under enrolled
state skew and age; plan expiry still cannot exceed head expiry. No computed
historical instant is supplied as a clock. Current processing retains its actual
supplied window, deadline and cumulative work without old-expiry clipping.

The [historical encrypted-original and caller/grant exchange](oidc-session-activation-historical-exchange.md)
uses these separate primitives as partial completion/reconciliation source work.
They grant no current execution permission, change none of the three live cold
owners and leave generic activation completion rejected. Dedicated historical
cold custody, completion signing/delivery and reconciliation remain unfinished;
protected token release and public activation/recovery remain separate.

## Remaining implementation boundary

The codec and signing module add no database writer or authority that derived
after-roots are current, and perform no durable retention themselves. An
indexed signed plan is not a registered execution owner, reservation, protected
SQL, one-use delivery or activation/recovery route. Original current processing work and
window/deadline must remain unchanged through the real owner; an encoded or
signed plan does not renew the assertion, session or delivery lifetime.
The [retained-finalization prerequisite](retained-registration-activation.md),
[original assertion admission](oidc-session-activation-admission.md) and
private token delivery remain separate inputs to that unfinished flow.

Verification is deferred until the source freeze. Required cases include
actual successful original replay, bad signatures/keys, altered request/scope/
body commitments, independent thirteen-head substitution, altered write
frontiers/after-roots, mutation and work-count disagreement, raw secret absence in
the output, token/envelope tampering, original expiry and clock reversal,
post-sign failure and cumulative work exhaustion. No such test was run here.
