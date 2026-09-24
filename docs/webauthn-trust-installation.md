# Explicit trust verification and local installation

Status: source implementation and review only; no build, interpreter or test
has executed this revision. This is a prerequisite of authenticated trust
completion, not an activated `webauthn.trust.complete` authority path. The
[startup inventory](authority-transition-startup-blocker.md) still has six
missing registered kernels, including the two evidence-admission operations.

## Actual path and explicit inputs

`webauthn_trust_core.py` verifies a bundle using immutable public-key DER,
source-pinned schema bytes and one explicit aware UTC verification instant.
It has no database, configuration, clock, filesystem or signer-provisioning
access. The schema fingerprint is pinned to the current checked-in v1 schema;
supplying a different schema, including one with remote references, fails.
The context's public key and time are integration inputs, not bundle-selected
trust or independently attested authority.

The real `webauthn_trust.py` verification, root loading and installation paths
use the core. Signature framing, empty-root withdrawals, signed AAGUID spelling
and authenticator classes, inclusive validity endpoints and higher-epoch
rollback semantics remain. Certificate parsing and declared certificate-digest
checks occur before any checkpoint write. Root certificate validity/CA/chain
policy remains in attestation verification; parsing a root does not prove its
hardware classification.

Public-key lookup never creates a private key or rewrites the public key.
Missing/invalid provisioned public material fails closed, including status and
startup key-identity checks. Explicit local `sign_trust_bundle` still owns its
existing development key-creation behavior and signs with one loaded key. That
local signer is not an independent installation-evidence authority.

## Exact artifacts and accepted profile

The immutable verified result distinguishes four byte representations:

| Artifact | Meaning |
| --- | --- |
| Input bytes and digest | Exact bytes passed to the core. For an API dictionary, the wrapper reconstructs these; they are not original HTTP bytes. |
| Unsigned canonical bytes and bundle digest | Existing compact sorted ASCII JSON with `metadata.signature` removed; the actual Ed25519 signature preimage. |
| Canonical signed envelope and digest | The complete bundle including its signature, canonically serialized. |
| Installation bytes and digest | Exact pretty-printed bytes, including trailing newline, that the local writer must persist and read back. |

The stage's 2 MiB canonical envelope ceiling now also applies to direct local
verification/writes. Raw input and generated installation bytes have an 8 MiB
ceiling so the core can read its own pretty-printed output. The fixed schema's
nesting and entry shapes bound formatting expansion; both limits are checked.
Root limits match the supported attestation profile: 256 roots, 64 KiB DER per
root, 1024 AAGUIDs per root and 2 MiB total DER/descriptor material (also charging
root IDs). Counters are exact positive integers through `2**63 - 1`.

Duplicate JSON members, nonfinite values, boolean/fractional counters, invalid
Unicode, malformed/naive timestamps and malformed local checkpoints are denied.
These are deliberate stricter admission rules for legacy direct-call paths,
not a claim that every document allowed by the older JSON schema is accepted.
The byte bounds do not bound total RSS, parsing/cryptographic work or the
wrapper's serialization of an already-decoded API object. No numeric rounding,
Unicode normalization or certificate-policy expansion is introduced.

## Local writes, ambiguous outcomes and retry

Reconciliation obtains the pending journal after acquiring the existing
exclusive file lock. It captures one context for candidate and installed-bundle
verification. The existing journal tuple, listed-withdrawal and predecessor
checks remain. It calls the private locked installer, avoiding nested `flock`
acquisition. Direct `write_trust_bundle` obtains that lock itself.

Before either write, pure rollback planning re-verifies retained input and
compares every verified-result field and type. A constructed dataclass is not a
verification token. The installer then durably replaces state first and bundle
second, using the existing file fsync, rename and parent-directory fsync helper.
It compares both exact readbacks before returning any local observation or
calling legacy completion.

The private `_install_verified_bundle_with_readback` factor also returns the
actual bundle/state bytes from those same reads, alongside the unchanged local
result. The existing helper delegates and keeps its original return shape.
Both require the caller's exclusive lock; no second read or arbitrary target
path is introduced. These bytes can feed the source-implemented private
evidence admission/read owner; they are not an authenticated committed-stage
or current-root assertion, and legacy reconciliation does not call that owner.

State-first ordering can leave the checkpoint ahead of the bundle. The same
pending candidate can retry; an earlier generation or same-generation fork
fails. A separately authorized later generation still follows the existing
monotonicity rules. A directory-fsync error after rename is an uncertain outcome:
visible bytes are not success. Even when rollback planning returns an unchanged
checkpoint, retry durably replaces those exact checkpoint bytes again. This
preserves content/timestamp while retrying the state file and its own directory
sync, including when state and bundle have different parent directories.

Successful writes return `serverware.webauthnLocalInstallationObservation/v1`
inside `local_installation`: exact bundle/state file digests, configured paths,
bundle digest and the verification instant. This is unsigned local readback,
not durable authority evidence, an immutable target identity or a completion
capability. Two-file atomicity, arbitrary external-writer exclusion and crash
durability of underlying storage are not established by this source change.
Configured directories and their ownership remain deployment prerequisites.
The existing replace helper creates missing parents but syncs only the immediate
file parent, not every newly created ancestor entry. Successful local readback
therefore does not prove power-loss persistence of a newly provisioned directory
hierarchy; a real installation authority needs a separately admitted target and
durable directory-provisioning contract.

Other legacy verification/load/status callers can still advance local rollback
state under their existing caller lock conventions. This extraction does not
claim to serialize every local state writer. Missing local state retains legacy
bootstrap semantics; it is not independent rollback protection. Recovery still
rejects an expired predecessor. No-pending reconciliation still does not prove
that a caller's expected publication completed after a lost response.

## Purpose-specific configuration (.84)

Signed service configuration v2 now optionally carries the closed
`webauthnEvidenceAdmission` policy. Its installation slot explicitly pins the
`trust-installation` purpose, raw Ed25519 public key and matching SPKI digest,
signer identity, installation target digest and source-bounded age/skew. An
absent block or null slot leaves installation evidence admission disabled;
neither a generic verifier key nor the local bundle signer supplies a default.

The private planner service factory and measured configuration mapper construct
the actual `EvidenceAdmissionPlanner` from the same owned configuration and
launch bindings. That factory opens no connection. Its read-only acquisition
genuinely verifies selected rows and original installation evidence before
deriving proposed INSERT/no-op effects and roots, but persists nothing and
does not activate the registry or a serving route. This is unexecuted source,
not provisioned signer/target authority or completed installation admission.

## Original-input capture and historical replay (.85)

Actual evidence acquisition now encodes the held original inputs before its
root/row/proof SQL reads and returns canonical input-record bytes plus their framed
digest alongside the genuine acquisition result. The installation record
preserves the exact signed evidence, bundle and state bytes, original
observation instant and committed-stage descriptor; it does not enroll a
signer, target or policy.

The configured owner's `replay_installation` reconstructs those originals,
repeats the actual admission adapter and compares the complete mutations,
result, kernel work units and total business work units on the same remaining
allowance. The input commitment, typed request, selected rows, database cutoff
and signer/target policy require independent admission for that exact history;
neither stored descriptors nor a currently active owner establish it.

This replay opens no SQL, stores or signs no plan, and verifies no selected-row
root proofs. It establishes neither current authority nor physical installation,
durable custody or execution. Original-input capture and semantic replay are
source-implemented prerequisites, not an extension of public v3 or the
revocation-only retained protocol.

## Authored tests and remaining authority work

`test_webauthn_trust_core.py` has 22 authored methods for actual local signatures, explicit context,
artifact commitments, immutable results, validation and rollback plans.
`test_webauthn_trust_installation.py` has 17 authored methods using real temporary files, signatures,
locks, replacement, fsync and readback, with injected failures before/after
rename and a distinct-state-directory retry case. Its narrow journal recorder
only checks call order; it is not the database, registry, planner or witness.
Neither script has executed. Both enter the isolated source inventory subject
to the unchanged freeze/controller/dependency prerequisites.

The legacy completion call is still ID-only. The separate
[successor implementation](webauthn-successor-transitions.md) now provides the
v2 acyclic evidence contract, shared installation claims, genuine evidence
signing/consumption, planned high-water effects and private proof acquisition.
It is not wired into legacy reconciliation. The `.84` optional signed policy
and private configured factory supply the source configuration seam; completing
that path still needs independently provisioned signer/target authority,
authenticated committed aggregate-stage/current-root ancestry, durable receipt
admission, signed-plan custody binding the `.85` originals and semantic replay,
root-proof verification and actual producer/planner/witness/executor
integration. In particular, the post-readback
observation time must not be substituted by the earlier local `verifiedAt`, and
an error after physical installation cannot be handled as a filesystem
rollback. See the
[coordinated authority design](webauthn-authority-integration.md) and
[startup blocker](authority-transition-startup-blocker.md). Local observations
must not be relabelled as that missing signed evidence or used to register a
partial kernel.
