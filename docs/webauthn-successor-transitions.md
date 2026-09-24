# Successor WebAuthn transition implementation

Status: source-only implementation work. These helpers do not register the
missing kernels or repair service startup. They are unbuilt and unexecuted.
The existing registry, query-proof, configuration and release gates remain.

## Evidence without circular dependencies

`authority_webauthn_evidence.py` signs and verifies original canonical envelopes
for two fixed purposes: `registration-attestation` and `trust-installation`.
Both use purpose-specific v2 claims inside
`serverware.policyAuthorityWebAuthnEvidence/v1`. The envelope binds source,
purpose, signer identity and SPKI, claims and issue/expiry times. It has a
4 MiB / 4,096-node / depth-16 limit and at most a 30-second validity interval;
independently configured age/skew may be stricter.

Verification performs actual Ed25519 and SPKI checks, canonical original-byte
checks, complete expected-claim equality and freshness checks on the existing
work allowance. It takes independently supplied key, identity, claims and time
expectations and returns no proof token. Neither decoding an envelope nor
hashing it authenticates its contents. The private signer is signing mechanics,
not evidence that a ceremony, installation or authorized operation occurred.

The required dependency order is acyclic:

```text
admitted ceremony or already-committed stage
  -> semantic intent and independently verified operation facts
  -> purpose-specific signed evidence
  -> original-envelope evidence identity
  -> final typed request
  -> authenticated complete reads and deterministic row effects
  -> one authorized atomic commit and later terminal witness
```

This is the required production flow, not a claim that its integration is
finished. A statement must not bind its own future signature, evidence identity,
completion receipt, or a final request that itself contains that evidence.
Generic v1 evidence-row hash/status checks are not signature verification and
cannot substitute for independently pinned evidence authority.

## Business semantics

Registration must consume the exact live user/label-bound challenge and prove
global credential-ID nonreuse, including revoked records. OIDC first enrollment
also requires the pending session, zero all-status user credential history and
complete live sibling-registration invalidation, including approval-bound
siblings. It does not activate the OIDC session. Ordinary untrusted attestation
results remain valid where the configured enrollment policy permits them.

Trust staging is one aggregate, not a publication INSERT followed by separate
revocations. Authorization uses the prestate; approval consumption and signer
counter updates enter the working state before withdrawals. Overlapping writes
merge into one final effect per original key. The actual candidate-root
classifier selects withdrawals, and global registration invalidation occurs
once, including when no credential is withdrawn. Request hints are not complete
population evidence. The stored publication audit is emitted at completion.

Completion must bind independently admitted committed-stage/root ancestry,
configured installation target, exact installed bundle/state bytes and their
signed installation evidence. Publication, high-water, audit and one-use
evidence consumption must become one transaction; a local installed file alone
is not publication authority.

## Activation still required

Ordinary selected rows, row effects and consumption recipes are not proof
tokens or independently authenticated roots. The successor operation manifests,
complete query-role adapters, evidence custody/consumption schema, independently
configured composers, actual evidence producers and atomic execution/recovery
must be connected before registry activation. The old trust-stage one-write
manifest and reserved v1 evidence schemas cannot represent these semantics.
No manifest widening or v1 reinterpretation is implied by these source helpers.

Broad fixtures and full verification remain deferred to the consolidated frozen
build. Production acceptance additionally requires independently operated
signing, witness and measured-runtime infrastructure, which is not provisioned.
