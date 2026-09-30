# Five-service cold generation admission

This source batch adds actual local generation gates to the five existing
serving owners. It is not the generation coordinator, a completed
`GenerationInstallEnvelope`, native key attestation, or PIDFD cleanup.
Those remain required implementation work. No runtime acceptance is claimed.

## Explicit selection and authority

The old `policyCustodyServiceRuntimeConfig/v4` remains ungated. Its successor
`serverware.policyCustodyServiceRuntimeConfig/v5` requires
`generationAdmission: {"grantFdName":"generation-grant"}`, one additional
inherited `generation-journal` directory with its exact configured directory
identity, and the fixed `generation-grant` sealed descriptor. Host/environment
bootstrap cannot select this profile: each real service retains its original
signed guest delivery and original boot/time namespace/lifetime.

The public grant is signed with the independently pinned **authority-history
root**, using a new, explicit generation-admission purpose. It binds the exact
service role, actual Guest13, complete runtime-configuration hash, history
manifest, predecessor/successor scope, driver/descriptor/manifest pins,
assignment and checkpoint/revocation identities, and an original BOOTTIME
window wholly inside that guest's lifetime. Scope also pins the exact original
installation `issuedAtUnixNanos` and `expiresAtUnixNanos`; request clocks cannot
renew either the installation interval or local grant lifetime. It is not key-generation authority.
The existing independently assigned service key signs only its own effects and
observations. Existing software service reports remain software reports; a
native bridge must not relabel them as NSM evidence.

The grant input is deliberately **not** a content-hashed C9 credential: doing
that would create a grant → Guest13 delivery digest → grant digest cycle.
The independent launcher must create the real memfd first, record its actual
descriptor identity in C9, then obtain the grant over those exact signed
originals, write its public bytes and apply all four seals before release.
The service accepts only that fixed name, exact signed descriptor identity,
regular memfd, complete seals, and 1..65536 bytes. It retains and rechecks the
same sealed file. This is a required input-provisioning contract, not permission
to predict process identities or synthesize a signed grant.

Schema: `custody-service-generation-admission.v1.schema.json`, anchors
`serviceSelection`, `bridgeSelection`, `grant`, `command`, `receipt`,
`observation`, and `replies`. Integer nanoseconds are canonical JSON integers;
producers must not round them through binary64. All nullable fields are present.
The retained existing generation request enum uses snake_case fields inside
its `body`; its `install_context` and the new envelopes use their original
camelCase struct fields. The schema preserves those actual wire spellings.

Signature domains use the existing
`policy_custody::protocol::domain_separated_signature_preimage` framing:

- `serverware.custodyServiceGenerationGrant.signature/v1`
- `serverware.custodyServiceGenerationEffect.signature/v1`
- `serverware.custodyServiceGenerationObservation.signature/v1`

## Actual local effects

Before commit, ordinary service requests are refused. The real single-owner
receive path handles generation commands before its existing business handler.
PREPARE captures and freezes that owner's state and appends the exact command
and signed effect to its separate durable journal. COMMIT or ABORT requires the
same transition, exact local prepared-effect digest, unchanged owner snapshot,
and a deadline no later than the original prepare deadline. COMMIT opens only
that exact cold successor's local admission. ABORT remains closed. A cohort
does not hot-swap its immutable configuration, key set, descriptors, or code;
a different successor needs genuinely new admitted owners.

The snapshot sources are the real recovery-store state/version/journal head;
cleanup-consumer state and response journal; recovery-target registrations,
revalidated retained descriptors and sealed bootstrap; current-signature
subjects and their original current authorizations; and the cleanup helper's
sealed inventory, actual journal head and actual pending-work census. No
caller-supplied state digest is accepted as a snapshot. A pending helper effect
or pending reply cannot be declared drained.

The bounded journal worker performs genuine record/file/directory/head fsync
through the existing append owner. The gate remains poisoned during append;
unknown completion, timeout, owner drift or overflow never opens admission.
Its source-selected strict journal constructor refuses detached records on
open, recovery and append; the older journal callers retain their old repair
behavior. No orphan repair turns an unknown generation effect into permission.
Restoration requires the complete bounded exact journal chain. The gate admits
at most one PREPARE and one decision, under the same original grant/window.
There is no reset, timeout unlock, automatic reissue, or new grant migration.

RECOVER is observation-only. It signs the current actual owner snapshot and
nullable exact retained effects. An empty history is *never-installed*, not a
completed installation. It does not create a journal entry or execute a phase.
Exact replay of an already durable command returns its original receipt only.

## Actual bridge caller and remaining coordinator

The explicit `serverware.policyCustodyProductionRpcRuntime/v5` adds required
`generationAdmission` with `apiVersion: serverware.custodyGenerationServices/v1`
and exactly five role-to-grant-digest pins. The original v4 runtime forbids this
selection. Existing authenticated handshakes still match all five exact
configuration hashes and authority histories; the new client uses those same
retained sessions, epochs, original guest lifetime, and request deadline.

The actual `call_generation_endpoint` caller now performs the five fixed
local commands and sends `GenerationAdmission {request,services}` to the
existing endpoint. `services` carries the full five command/response originals,
not booleans. A failed/unknown member or endpoint response poisons the client;
there is no automatic resend. New normal dispatch remains closed until the
coordinator response also passes the existing complete five-service generation
response verification. The aggregate carrier is bounded at 256 KiB in addition
to existing framing limits. Recovery never sets a local committed flag.

The following are still required, and this batch deliberately does not claim
them:

- A genuine native coordinator owner and operational assignment, durable
  intent/install/abort state, historical-key state, and actual installation
  signature. The endpoint's name alone supplies none of these.
- An explicit authenticated all-five never-installed branch in the selected
  coordinator/facade recovery contract. Old v4 Recover requires a full signed
  installation and cannot honestly represent fresh empty histories.
- Genuine v4/native five-service transition certification after the complete
  final artifact exists. Local admission effects are a distinct purpose, never
  renamed into those receipts or a fabricated result hash.
- Actual RequestTermination/Settle operation ownership, retained PIDFD/cgroup
  work, independent cleanup permission and definite durable settlement.
- The launch/input producer for the five sealed public grants and independent
  deployment of their signing authority. This source creates no keys, grants,
  deployed processes or cloud resources.

The gate's existing signed assignment/load/policy/startup verification is
unchanged. No verification-only RPC bypasses the unimplemented effects above.
