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
tokens or independently authenticated roots. The remaining successor manifests,
trust-stage query adapters, evidence custody/consumption schema, independently
configured composers, actual evidence producers and atomic execution/recovery
must be connected before registry activation. The old trust-stage one-write
manifest and reserved v1 evidence schemas cannot represent these semantics.
No v1 evidence reinterpretation is implied by these source helpers.

## Registration query and mutation integration (`.75`)

Registration now produces actual `BoundedQuery` / `CompleteIndexQuery` objects,
including exact new-credential/audit absence and the real selected-high-water
field join to the published trust predecessor. Its mutation adapter renders
the business effects through existing source templates into `KernelTransition`.
It still requires independent evidence pins and the common audit-capacity
finalizer; it is not a keyless registered kernel.

The existing complete-query dispatcher, database acquisition and proof engines
now admit these exact source families:

| Enrollment | Complete roles | Distinct read heads | Largest result |
| --- | --- | --- | --- |
| Ordinary | Credential-ID history; pending publication absence | 2 | 1 row per role |
| OIDC first enrollment | Both ordinary roles; all-status user history; live user registration challenges | 4 | Selected challenge plus at most 32 siblings |

The role inventory follows the actual closed enrollment mode. Every query is
rebound to its actual credential/user, sibling hints and one cutoff before SQL.
Hint lengths are overflow bounds, never proof of population completeness.
Acquisition uses the real counted heads, interval frontiers and exact primary
fetches; verification reconstructs the roots and joins every returned index
member to its primary row. Empty ranges still need proofs. Shared read/write
verification also uses the exact family, without a new budget or proof token.

Source `.75` replaces registration's obsolete ordered-page manifest primitive
with the complete-index primitive and commits its conditional role definitions.
Its business bounds remain 112 rows / 40 mutations / 1,024 work units, plus the
existing exact framework capacity allowance. Revocation's six roles, five read
heads and 101 context hashes remain unchanged. Registration uses 79 ordinary or
91 OIDC context hashes for the actual constructor/anchor schedule; all consume
the same cumulative work budget. The 33-row OIDC challenge bound is role-specific,
not an increase to revocation or global resource allowances.

This is read-side and mutation-rendering integration, not operation activation.
The reserved external-evidence v1 manifest/schema is unchanged and cannot consume
the new v2 evidence. Registration's owning composer, original evidence production
and custody, authenticated complete mixed-query replay, mutation-frontier
acquisition, final capacity/root planning and atomic execution are still required.
The registry, public v3 planner and mutation-read admission remain closed.

Broad fixtures and full verification remain deferred to the consolidated frozen
build. Production acceptance additionally requires independently operated
signing, witness and measured-runtime infrastructure, which is not provisioned.
