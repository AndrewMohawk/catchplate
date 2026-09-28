# Original-only recovery grant production

Source only, unbuilt, unexecuted and unprovisioned. This is a pure private
root-issuance library, not a recovery service or a completed public recovery
path. The existing LIVE release producer remains unchanged.

`authority_oidc_session_activation_release_recovery_grant_production._produce_on_work`
returns exactly `(client_authorization_bytes, server_bootstrap_bytes,
outcome_original)`. No private key, old/new token or successful admission
object is returned. The output server and client are explicitly recovery-profile.

## Independent originals

Inputs are the existing recovery transport's exact seven-frame prefix:

`(recoveryPurpose, proof, proofEnrollment, intent, intentEnrollment, oldToken64,
encryptedEnvelope100)`.

Separate mandatory inputs are the fresh signed recovery issuer policy,
historical release custody original, independent proof and intent enrollment
originals, actual root key pair, and original work/window/deadline. There is
no caller-supplied expected scope, launch policy, authority DTO or root key in
the request frames. The supplied key pair is independently held by the caller
of this private library, not by the public application.

The policy genuinely authenticates historical custody and both root-enrolled
purpose-separated public keys. It independently pins proof scope, caller,
release target, custody/intent/state-receipt identities, exact outcome digest,
client identity, endpoint and release launch/resources. The two request
enrollments must byte-match these separately supplied originals.

Historical intent admission verifies its enrolled signature, exact target and
actual old-token possession. Historical proof admission verifies its distinct
enrolled signature and independently pinned scope, release and evidence.
Neither candidate proof nor candidate outcome supplies its own expected claims.
The encrypted envelope must match the authenticated original envelope digest.

Old custody, intent and proof issue/expiry intervals remain historical facts;
they are not renewed release authority or backdated processing clocks. The
original delivery must still be live. Fresh root policy and its processing
bounds authorize this derivation, not a stale browser cookie.

## Canonical outcome and fresh grants

The genuine historical evidence reconstructs the canonical token-free outcome;
no candidate outcome or fabricated placeholder is an input. Its identity must
match the independently signed policy's expected outcome digest. Only then is
the original appended to the prefix and the complete raw8 admitted by the
actual recovery framing, which derives its exact eight-frame request identity.

The producer uses existing genuine producers and original readback verifiers
for checkpoint-one storage authorization, recovery authorization, recovery
server bootstrap and matching client authorization. Storage is fixed to
`recordCount=1` and the exact outcome digest. The server embeds the unchanged
historical custody plus the newly signed storage and recovery authorizations.
Client scope17 binds that exact signed server original, recovery request,
outcome, target and independently selected client/endpoint.

The canonical outcome and checkpoint are expected bindings, **not evidence
that the outcome exists in storage**. This library reads no directory, mutates
no store, runs no SQL, opens no delivery ciphertext and performs no transport.
Actual recovery must independently observe and read the unchanged exact
checkpoint-one record before any token opening or response claim.

## Original allowance and remaining work

Before nested admission or signing, a conservative 64 MiB complete inventory
reserves actual request/policy/history originals, nested custody captures and
bounded generated output/readback capacity. Individual maxima cannot all be
allocated together. All operations share the supplied cumulative work ledger.

Policy, enrollment age/skew, original delivery and endpoint limits only narrow
the original window. The optional restrictive continuity hook exchanges only
nondecreasing epoch/monotonic floors. It threads through actual historical
intent/proof and all generated grant admissions without replacing authority
or introducing a new allowance. Live guards remain attached through return.

The private `_derive_on_work` helper freshly re-admits originals for the
independent response verifier; no API accepts its tuple as authority. Actual
independent issuer key custody, finite acquisition/staging service, protected
recovery exchange, public recovery orchestration and guarded cookie delivery
remain separate work. Reconstruction does not authorize automatic SQL retry
or establish a current session, delivery acknowledgment or production readiness.
