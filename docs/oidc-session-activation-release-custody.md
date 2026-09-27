# Delivery-key custody without token egress

This is **partial step 20 source**, unbuilt, unexecuted and unprovisioned. It adds
root-original-admitted delivery-key custody, fresh original release-intent
admission, independently signed committed-consumption proof admission and exact
authenticated ciphertext metadata inspection. A separately root-authorized
store now supports first-exact token-free outcome retention. It does **not**
release a token, execute SQL or complete the browser flow.

## Distinct root scope

The bootstrap schemas are `serverware.signedOidcSessionActivationReleaseCustody/v1`
and `serverware.oidcSessionActivationReleaseCustody/v1`. The fixed consumer is
`token-release`; process mode is `oidc-session-activation-token-release`, UID/GID
**65502**. The source scan found no existing use of that identity; no account,
descriptor loader, service or filesystem is provisioned by these modules.
Neither live execution consumers nor completion-history custody are widened.

The genuine root signature covers current source, receiver identity, exact
configuration/generation/runtime cohort, delivery-key digest, original planner
bootstrap, activation request/operation identities, original delivery-envelope
digest, exact eleven-field AEAD scope, fresh outer interval and the fixed
`oidc.session.activation-delivery.consume` operation. It also pins
`releaseIntentDigest` and `consumeRequestDigest`. These are **independent expected
identities only**, not a claim that either original intent or committed
consumption has been verified. The separate original-intent method below now
authenticates intent; the bootstrap alone still does not. `releaseIntentDigest`
is the domain-framed identity of the exact signed intent original under
`serverware.oidcSessionActivationReleaseIntentIdentity/v1`, not a raw byte hash.
No signed status or scalar success replaces committed-consumption admission.

The original planner signature/configuration/policies/vector/enrollment are
genuinely admitted historically within the current source cohort. Its dedicated
delivery-key digest must match; genuine v3 admission preserves separation from
the bundle and private-journal keys. This new owner receives **only the delivery
AES key**, never bundle, planner, caller or completion signing keys. The root
signature supplies trusted-host-local authority, not measured-runtime evidence;
all hardware/TEE/HSM/witness flags remain false. The owner's independently
supplied receiver identity must match the signed identity; it is not derived
from the bootstrap it is meant to check.

The root-pinned operation identity is rederived from the activation request
digest, and delivery ID uses the actual request-bound `activation-delivery`
derivation. The scope is exactly `deliveryId`, `userId`, `sessionId`,
`credentialId`, `credentialRecordId`, `challengeId`, `assertionDigest`,
`oldTokenDigest`, `newTokenDigest`, `createdAt`, `expiresAt`. Canonical credential
encoding, digests, UTC timestamps, rotation and source lifetime bounds are
checked. The fresh outer expiry cannot exceed the original delivery expiry;
historical admission of an old planner never revives an expired delivery.

## Private interfaces

The bootstrap exposes:

```text
_verify_on_work(*, custody_bytes, root_public_key,
               live_window, transport_deadline_ns, work)
_produce_on_work(*, payload, root_private_key, root_public_key,
                live_window, transport_deadline_ns, work)
```

Originals are immutable, canonical and bounded at 8 MiB for the outer and 4 MiB
for its planner original. The actual bounded decoder/capture and cryptographic
helpers share the supplied cumulative work. The producer owns its payload
before callbacks, checks genuine original/key joins, and signs/verifies under
the new domain. Returned material is ordinary owned data, never accepted as an
authority input.

`OidcSessionActivationReleaseCustody` requires original custody bytes, the root
key, independently expected receiver identity, an exact 32-byte delivery key and
the caller's current window/work/deadline. It binds exact class/PID/UID/GID,
empty supplemental groups, fixed mode, source revision and held configuration.
A nonblocking owner lock excludes overlapping checks and inspection.

- `check_on_work(*, live_window, transport_deadline_ns, work)` reauthenticates the
  original bootstrap and actual key binding; it returns no success carrier.
- `inspect_delivery_on_work(*, envelope_bytes, live_window,
  transport_deadline_ns, work)` hashes the exact 100-byte original, joins the
  root pin and genuinely invokes the existing live AEAD/delivery-row helper
  under the held key and root-owned scope. It returns only owned ordinary
  `{deliveryScope, deliveryEnvelopeDigest}` metadata. No row, plaintext token,
  intent-verification claim or consumption receipt is returned or retained.
- `verify_intent_on_work(*, intent_bytes, intent_enrollment_bytes,
  expected_caller_id, expected_consume_binding, old_token_bytes, live_window,
  transport_deadline_ns, work)` joins the exact independently root-pinned
  intent identity before genuine [original-intent admission](oidc-session-activation-release-intent-admission.md).
  It derives configuration, generation, runtime, receiver and database scope
  from the actual custody/planner/state originals; the caller and five consume
  identity pins remain independently supplied expectations. Its enrolled intent
  signer must differ from the actual root, planner, computation, completion and
  state keys. The actual old-token original must match the signed delivery
  scope. Both custody and intent retain current expiry/clock guards under the
  same work/window. This method returns **nothing**: it does not establish
  committed consumption, decrypt a token, create an outcome or mint reusable
  permission for a later release call.
- `close()` closes the same-process owner and drops held references; this is not
  a claim of guaranteed memory erasure.

`verify_committed_on_work` accepts original proof/enrollment and intent/enrollment
bytes, independently expected producer ID/identity, caller ID, five consume
bindings and state-receipt digest, the old-token original and the existing
work/window/deadline. Both external graphs are structurally owned before native
callbacks. Under one nonblocking lock it reauthenticates root custody, invokes
the same genuine intent/possession admission, and admits the distinct
[proof original](oidc-session-activation-release-proof-admission.md). Its expected
configuration/database/generation/runtime/receiver and release target come from
the actual root/planner/state originals, never from the proof being checked.
The proof must bind the domain-framed exact custody original and root-pinned
intent identity as well as the independently expected state receipt.

The proof key must differ from the actual root, activation planner, state,
computation, completion and freshly admitted intent keys. This is separation
from these actual known keys, not a universal claim about every deployed key.
No completion history or signing key crosses into UID 65502. Original custody,
intent and proof guards survive the join; persistent owner clocks retain nested
samples, and final owner checks are also clipped to both signed expiries.
The method returns **nothing** and does not save a permission for another call.
The [proof producer](oidc-session-activation-release-proof-production.md) must
genuinely verify packet/replay/commit/completion originals on the separate
completion side. The receiver checks its signed evidence; it does not repeat
historical decryption or treat a successful Python object as that evidence.

`retain_outcome_on_work` accepts the same original proof/intent and independent
pins as `verify_committed_on_work`, plus the exact independently constructed
[`ReleaseOutcomeStore`](oidc-session-activation-release-outcome-store.md). It
performs the genuine admissions itself under the custody lock; a previous
successful verification call cannot authorize it. The store must separately
authenticate a [root storage authorization](oidc-session-activation-release-outcome-authorization.md)
for this exact release-custody original, receiver, configuration, database,
generation, delivery and independently pinned directory/checkpoint. The
existing custody v1 does not implicitly grant filesystem authority.

The resulting [outcome record](oidc-session-activation-release-outcome.md) holds
only metadata and commitments to the exact proof, intent, enrollments, state
receipt, ciphertext and consume outcome. It contains no old/new plaintext token,
private key or caller-supplied successful proof object. Storage authorization is
checked separately rather than included in the outcome digest: a renewed
checkpoint grant must be able to pin an unchanged record without a circular
hash. The stable slot depends on database, generation and delivery, not a fresh
intent nonce. Changed records conflict instead of replacing the first record.

The same original custody/intent/proof guards enclose actual no-replace
publication, normal-close durable readback, store identity and digest checks.
The method returns the exact retained record digest, not a claim that the token
was delivered or permission for a later call. Any failure after store invocation,
including a late outer guard failure, closes both owners and preserves visible
bytes. It never deletes, retries, regenerates or reconsumes. Cold checkpoint
admission is not hostile-host antirollback or authorization for plaintext
recovery; independent witness and explicit recovery work remain separate.

Every check, inspection and original admission reauthenticates root scope, identity and key
under the same supplied work. Narrowing preserves original epoch/monotonic
opening samples and caps at the fresh release interval and inherited deadline.
Sticky guards surround callbacks and final return. Old planner expiry is never
a current clock sample, and no new work/window is opened.

## Deliberately absent release path

There is **no open, release or consume method**. Internal AEAD authentication
cannot replace fresh original release intent and genuine committed one-use
consumption through the separate protected operation. A pure kernel transition,
`consumed_at` scalar, activation completion ACK, metadata result or caller-posted
proof object is not that evidence. The legacy environment-secret decrypt/direct
database recovery helper is not invoked.

Fresh intent and signed committed facts now have a same-call original-consuming
join and first-exact durable retention, but future plaintext egress must perform
that join and the durable binding inside the actual release operation before
opening. Neither the standalone admission nor retained digest authorizes a
future call. Authorized recovery, guarded plaintext egress, cold key/FD service, public
permission, token response and current-session confirmation remain open.
No test, parser, interpreter, build, provisioning or runtime verification was run.
