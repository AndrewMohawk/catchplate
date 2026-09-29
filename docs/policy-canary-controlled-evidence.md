# Controlled native canary evidence intake

This is a source-only receiver/transaction implementation, not deployed or
accepted canary evidence. The previous bearer-selected `/api/data-plane/policy-canary/evidence`
and its v1 bytes are unchanged. They do not authorize the new purpose.

## Owner and wire contract

`authority_policy_canary.py` fixes the ordered original batch, native statement,
outer evidence and controlled request. `authority_policy_canary_policy.py`
admits only the independently signed `policyCanaryIntakePolicy` purpose from
the actual measured authority configuration. The paired schema is
`schemas/policy-canary-controlled-evidence.v1.schema.json`.

The native sender uses these fixed HTTPS POST paths:

- `/api/data-plane/policy-canary/controlled-evidence` consumes an intake proof.
- `/api/data-plane/policy-canary/controlled-evidence/inspect` consumes a fresh
  inspection-only proof over the same original batch; it cannot renew intake.

Both bodies have exactly `apiVersion`, `batchOriginal`, and `nativeEvidence`.
The batch is an unchanged canonical Python-ASCII JSON string with exactly
`apiVersion`, `requestId`, `canaryId`, and the ordered 1–128 `events`. Numbers
must not pass through a JavaScript floating-point representation. Inner records
remain the actual independently signed, kind-specific originals.

The statement has 22 fields. Native `bootId` is canonical base64url of the
actual 32-byte native boot original. `canaryBootId` is a separate prefixed
SHA-256 identity from the exact assigned canary member. Neither substitutes for
the other. The signature is `ed25519:` plus canonical base64url of 64 bytes,
over the ASCII statement schema, one NUL byte, and the full canonical ASCII
statement. The NSM nonce is SHA-256 of
`serverware/canary-evidence-intake-attestation/v1`, NUL, nonce32,
SHA-256(statement bytes), and signature64. This is not the audit signature
preimage. Native evidence retains the original role-4 NSM COSE document and
raw Ed25519 public key; configured boot strings or successful-verifier DTOs
cannot stand in for those originals.

The outer envelope adds the exact public client certificate DER. The genuine
native TLS owner must retain its private key and send using that same identity.
The URI is source-fixed as
`spiffe://serverware.policy-canary/{deploymentId}/{instanceId}`. The receiver
requires the actual TLS 1.3 peer, exact leaf DER/SPKI, clientAuth EKU and sole
URI SAN under the independently assigned measured CA. The authority verifier
and planner independently verify the signed leaf/assignment and original NSM
proof. Ingress mTLS, forwarded certificate headers, audit assignments and bearer
tokens do not substitute for the actual dedicated sender.

## Cold public-policy delivery

The explicit `control-plane --policy-canary-intake` descriptor entrypoint adds
only the new profile. Older startup selection is unchanged. It opens the fixed
root-owned `policy-canary-intake.json`, `policy-canary-root-public-key`, and
`policy-canary-authority-configuration.json` sources below
`/run/serverware/authority-trust/`, retains distinct read-only descriptors, and
delivers their actual inventory before privilege drop. It accepts no caller
pathname or private authority key.

The exact nine-field receiver configuration independently pins both the root
original hash/SPKI and the original signed authority configuration hash/domain
digest. Its control-plane configuration digest is separately compared with the
actual retained custody binding. A custody digest is not policy bytes. The
receiver validates the original v6 authority root signature and the explicit
canary purpose; it does not impersonate a private authority role or replace
that role's genuine current generation/admission checks. No silent reload,
deadline renewal, environment-selected root, or lazy request-time FD admission
is allowed. The runner initializes before the listener and closes the selection
before borrowed custody is closed.

## Commit and uncertainty contract

The exact response has six fields: `apiVersion`, `requestId`,
`batchSha256`, `status`, `result`, and `recordOriginal`. The intake response
requires a definite signed controlled commit and exact retained-row readback.
On inspect, `committed` is only a control-plane-authenticated observation of the
exact retained row: it is not a fresh writer receipt, authenticated database
read-proof original, physical proof, or permission to claim/contact/resend.
Its nested result
has exactly `ok`, `operation`, `requestDigest`, `auditEventDigest`,
`idempotentReplay`, `accepted`, and ordered `results`. Each result has exactly
`kind`, `recordSha256`, and the canonical `storedOriginal`. An inspection that
cannot establish the exact retained original returns `unknown` with both
nullable fields null. `unknown`, absence, timeout, or an expired statement
never authorizes resend, splitting, re-signing, or a new effect.

The batch row is an atomic known-commit original/result store. It is NOT a
pre-contact durable sender journal. The required successor is a protected
delivery slot plus a current-slot head per admitted assignment/canary/sender.
Separate closed prepare, claim and recovery purposes must persist the exact
future HTTP original before effects, retain definite writer completion and
authenticated writer-read-proof originals, and atomically bind the prior
claimed slot/head when intake commits. A fresh request ID or expired claim
must not bypass an unresolved earlier slot. One irreversible claim admits one
contact; loss, timeout and inspection are never permission to send again.
The original absolute deadline cannot be renewed. New-boot recovery needs its
own independently admitted historical/current association, not reconstructed
native ownership. These slot and native contact/exporter owners are required
follow-on source work, not operational provisioning. An in-memory pending
object or ordinary SELECT cannot close the boundary.
The outer sender's permission authenticates authorship only; each inner record
still requires its original signature, assigned role, historical/current trust,
unrevoked keys, complete transaction roots and exact predecessor associations.

## Actual controlled transaction and record inventories

`control_plane_policy_canary.on_request` is called by the two explicit app
routes; the request body and actual TLS peer remain bound on the same cold
request owner. Its SELECT-only snapshot is data. PostgreSQL bounds row count
and original bytes before the receiver transfers row data. These resource
checks confer no authority. The planner reconstructs each fixed complete
relation root against the actual transaction before-root before
the kernel repeats the ordered program. The request commitment includes the
exact batch, proof, configuration and complete prestate original. All mutations,
inner verification rows, transition audits, outer outbox event and retained
batch/result are one controlled commit. The registry, signed configuration
producer, verifier and planner independently select the new operation; no
generic runtime DML grant is added.
The signed mutation array preserves actual immutable predecessor/audit order;
coalesced mutable heads are written last, after all referenced successors.

The scalar record inventories below are the actual existing `db.py` constants,
not a second guessed wire grammar. The handler refuses missing/extra fields.
Canonical nested originals remain strings; computed verification/transition
fields belong only to returned stored rows, not caller inputs.

| Kind | Exact input inventory / controlled handler |
| --- | --- |
| assignment | `_POLICY_CANARY_ASSIGNMENT_FIELDS` / membership.assignment |
| canary-revision | `_POLICY_CANARY_REVISION_FIELDS` / lifecycle.canary_revision |
| load-receipt | `_POLICY_CANARY_LOAD_RECEIPT_FIELDS` / membership.load_receipt |
| runtime-attestation-handoff | exact `canary_id, instance_id, boot_id, candidate_id, runtime_attestation_json, actor_id` / handoff.handoff |
| custody | `_POLICY_CANARY_CUSTODY_EVIDENCE_FIELDS` / custody.custody |
| ingress | `_POLICY_CANARY_INGRESS_OBSERVATION_FIELDS` / custody.ingress |
| active-decision | `_POLICY_CANARY_ACTIVE_DECISION_FIELDS` / active.active |
| shadow-observation | `_POLICY_CANARY_SHADOW_OBSERVATION_FIELDS` / shadow.shadow |
| instance-revision | `_POLICY_CANARY_INSTANCE_REVISION_FIELDS` / lifecycle.instance_revision |
| checkpoint | `_POLICY_CANARY_CHECKPOINT_FIELDS` / actual checkpoint algorithm with internal typed state |
| compiler-analysis | `_POLICY_COMPILER_AUTHORITY_ANALYSIS_FIELDS` / compiler.compiler_analysis |
| readiness | `_POLICY_CANARY_READINESS_FIELDS` / actual readiness/sealed aggregate algorithm with internal typed state |

Checkpoint/readiness reuse the existing pure fold, heartbeat, sealed membership
and readiness checks through a source-only typed-state branch. It accepts no
SQL connection, query adapter or preverified aggregate DTO. The authoritative
caller supplies only the owned complete transaction state; the preflight copy
selects queries and cannot commit. Current and historical signature checks,
trust revocations, CAS predecessors and whole-program work accounting remain.
Human publication approval stays in the separate candidate-generation profile.

## Required emitter and continuation connections

The following real producers must join the fixed contract. No fixture record,
unsigned builder, human upload substitute or local completion flag closes them:

| Kind | Required genuine producer/original owner |
| --- | --- |
| assignment | Independently signed assignment and actual member/attestation/role originals |
| canary-revision | Signed canary-state owner over the exact protected predecessor |
| load-receipt | Actual native loader and admitted runtime identity |
| runtime-attestation-handoff | Real attestation/role authorization originals and native handoff |
| custody | Actual immutable request-facts retrieval and monotonic custody owner |
| ingress | Real ingress sampling/accounting and credential-free facts commitment |
| active-decision | Actual active evaluation plus resolved effect/final enforcement evidence |
| shadow-observation | Real shadow worker, comparison, latency and required authority context |
| instance-revision | Actual instance lifecycle owner with exact checkpoint/sealing predecessor |
| checkpoint | Complete retained ingress/active/shadow/custody population and derived aggregate |
| compiler-analysis | Independently signed compiler authority analysis |
| readiness | Independently signed readiness over exact sealed membership/aggregate roots |

The native dedicated TLS/signing primitive is a prerequisite, not all twelve
exporters. Protected candidate-artifact intake remains a separate actual
producer requirement; generation publication does not manufacture its row.
Protected Setup policy continuation/materializer evidence, genuine onboarding
canaries, measured JIT, proxy-ready handoff and final completion receipt remain
later required product work. No proxy-ready or completed-Setup claim is made.

The new finite intake keeps whole-batch atomicity, ordered 1–128 events and the
original absolute deadline. Explicit original/argument/query/mutation/work and
complete-table capacity bounds refuse before any effect, never truncate,
prune, reset replay history or pretend larger populations are absent. Capacity
lifecycle/scaling and deployment acceptance remain separate requirements.
The current source profile caps each of 44 retained relations at 32 rows and
the complete batch at 240 selected rows (including absence proofs), 96 business
mutations and 8192 kernel work units. The batch is at most 1 MiB, arguments at
most 3 MiB, HTTP body at most 1 MiB + 192 KiB, and response at most 4 MiB.
The retained nested result is separately capped at its 2 MiB storage bound. JSON
escaping can make an otherwise individually bounded original exceed a whole
envelope budget; that refuses without splitting or changing originals. These
are explicit temporary capacity limits, not claims of full production scale.
