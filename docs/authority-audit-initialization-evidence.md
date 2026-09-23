# Signed audit initialization evidence

Status: source-only, unbuilt and unexecuted. This implements a purpose-specific
signature consumer joined to the [offline preparation](authority-audit-initialization.md),
not an independent checkpoint producer, provisioning path or atomic installer.
`installationPermitted` remains literal false in both preparation and evidence.
Global-counter runtime INSERT, phase-2 activation and startup acceptance remain
disabled.

## Inputs and trust boundary

`authority_audit_initialization_admission.verify_audit_initialization_evidence`
accepts the exact checkpoint and authorization envelope bytes, explicit trust
and expected facts, an explicit nanosecond verification time, both primary-root
descriptors, the complete outbox proof stream and exact aggregate-key absence.
It accepts no preconstructed preparation or inventory observation as proof.

`AuditInitializationTrust` supplies separate Ed25519 SPKI pins for checkpoint
and authorization. Each pin binds its role, authority identity, measurement
and attestation-receipt digest. The keys and authority identity digests must
both differ. Distinct keys and labels alone do not prove independent operation,
actual key custody, attestation validity or measured execution. The trust
context also carries a policy digest, validity interval and maximum envelope
lifetime, capped by source at 300 seconds.

`AuditInitializationExpectation` supplies the database identity and generation,
schema/source contract and initializer measurement digests, operation and nonce,
fence identity/generation, writer inventory and fence-evidence digests,
initialization ancestry, checkpoint sequence/predecessor and initialization
timestamp. Sequence one requires a null predecessor; subsequent sequences
require a canonical digest. This is an equality contract against independent
expected facts, not a chain validator or proof that the chosen head is current.

The eventual trusted controller must derive these contexts independently of the
request and database being examined. No loader, producer, monotonic store or
trusted time provider is implemented here. `sourceContractDigest` is the source
schema/authority-contract binding, not a measurement of these Python modules;
the actual initializer measurement and authenticated full import closure must
cover the executed code. The operation ID is an offline initialization intent,
not an admitted runtime operation/template. The initialization timestamp is
explicit committed data; it is neither sampled nor required to equal the
verification time. Zero is permitted only as an explicit value.

## Acyclic signed contract

The consumer requires this ordered dependency chain:

| Artifact | What it binds |
| --- | --- |
| Checkpoint | Expected facts, exact before-root descriptors including revision/count, source primary-key contracts, initial-install-only disposition |
| Preparation | Reverified complete inventory and absence, exact counter row, prospective mutation and recomputed after roots |
| Separate authorization | The exact signed checkpoint envelope digest, preparation digest, full counter-row digest and after roots |

Both signed payloads additionally bind source revision, preparation profile,
operation-manifest digest, trust-policy digest, authority pins and issuance /
expiry. The checkpoint contains no preparation or authorization digest, avoiding
a signature/hash cycle. The authorization repeats the complete expected-fact
binding; it cannot be transplanted to another database, generation, fence,
nonce, timestamp or initialization ancestry.

The fixed envelope schemas are
`serverware.metadataAuditInitializationCheckpoint/v1` and
`serverware.metadataAuditInitializationAuthorization/v1`. Their payload schemas
are respectively `serverware.metadataAuditInitializationCheckpointPayload/v1`
and `serverware.metadataAuditInitializationAuthorizationPayload/v1`.
Their purposes are `metadata-audit-initialization-checkpoint` and
`metadata-audit-initialization-authorization`. These are separate from migration,
artifact-generation, replay-witness and audit-inclusion purposes; none of those
existing receipts substitutes for this evidence.

Each envelope is exactly `schema`, `payload`, `signerKeyId`, `algorithm` and
`signatureBase64Url`; the algorithm is Ed25519 and the key ID is SHA-256 of the
canonical DER SPKI. Signing covers the ASCII `sha256:` digest of the canonical
payload, using the fixed role's
`serverware.metadataAuditInitializationCheckpointSignature/v1` or
`serverware.metadataAuditInitializationAuthorizationSignature/v1` domain.
The artifact hash function length-prefixes both the domain and each frame.
The exact original signed envelopes are separately committed with the matching
`CheckpointEnvelope/v1` or `AuthorizationEnvelope/v1` domain under the same
`serverware.metadataAuditInitialization` prefix. Preparation, full-row and
evidence digests retain the transition core's **different NUL-terminated domain**
framing; the two conventions must not be interchanged.

## Verification order and bounds

The helper in `authority_audit_initialization_signatures.py` accepts only exact
canonical ASCII JSON bytes, no trailing newline, at most 65,536 bytes per
envelope. It rejects duplicate keys, floats/nonfinite numbers, out-of-signed64
integers, NUL, surrogates, noncanonical escapes and base64url, and non-Ed25519 or
noncanonical DER pins. JSON depth is at most 16 and node count at most 4,096,
including dictionary keys and values. SPKI is bounded to 1,024 bytes; signatures
are canonical unpadded base64url encodings of exactly 64 bytes. The raw byte cap
bounds parsing input; graph bounds are checked on the parsed owned document.

The consumer snapshots and revalidates trust, expected facts and both roots.
Before touching the outbox iterator it verifies both actual signatures, closes
both payload schemas, compares every expected binding and the exact checkpoint
root/key contract, and links authorization to the original signed checkpoint.
Canonical-byte comparison prevents Python boolean/integer equality aliases.
For each envelope, trust-start <= issued <= now < expires <= trust-end and
expires - issued <= maximum lifetime. Authorization cannot precede checkpoint
issuance or outlive it. There is no ambient clock.

It then calls the real initialization preparation on the supplied stream and
absence proof, and joins the returned digest, full-row digest and after roots
to the independently signed authorization. A caller-constructed observation or
serialization is never substituted. Known signature/preparation errors become
`AuditInitializationAdmissionError`; arbitrary iterator interruptions propagate
without returning evidence. The preparation owns absence data before iterator
invocation, so caller buffer reuse cannot alter later root arithmetic.

The immutable result retains original signed bytes and the actual preparation,
with schema `serverware.metadataAuditInitializationEvidence/v1`, the explicit
verification time, envelope/preparation digests, and verification boundary
`pinned-signatures-and-local-recomputation`. Projections return fresh owned
graphs. Direct construction checks representation only, not signatures or
proof relationships: the class and its self-digest are not authority tokens.
The final canonical evidence shares the 64 MiB/depth-128/one-million-node
serialization bound; that is not a peak-memory or full-job resource guarantee.

## What remains necessary before installation

Valid pinned signatures authenticate issuer claims. They cannot establish
physical writer exclusion, complete writer inventory, current schema/roots,
actual attestation, administrative independence or the absence of a previous
installation. In particular, a single aggregate absence proof does not derive
aggregate cardinality: this consumer checks that the descriptor and arithmetic
match the signed checkpoint, not that the issuer's count is true. Independent
checkpoint production must supply that evidence. Complete outbox reconstruction
derives only that population's cardinality relative to its supplied root.

Time is checked at the supplied instant before potentially long offline work.
The job owner must enforce total deadlines, CPU/byte/memory limits and recheck
live authority at the actual commit. Repeating identical inputs produces the
same evidence; this component consumes no nonce or ancestry. Independent
monotonic checkpoint selection, one-use initialization authorization, reset
prevention, all-writer fencing and atomic row/tree/receipt consumption with exact
crash/retry/readback behavior remain required. No SQL permission or migration
acceptance changes here, and generic artifact key purposes are not expanded.

The isolated fixture uses real deterministic Ed25519 test keys and independent
tree/hash/row oracles. Authored controls cover transport/signature rejection,
freshly signed but crossed claims, all expected bindings, role/time separation,
pre-iterator rejection, actual preparation recomputation, invalid proofs,
owned snapshots and explicitly repeatable non-actionable results. They remain
unexecuted. A future run must satisfy the unchanged freeze, cleanroom and
sequential no-build verification prerequisites in `goal.md`; local fixtures do
not prove production services, installation or physical fencing.
