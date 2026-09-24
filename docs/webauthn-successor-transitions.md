# Successor WebAuthn transition implementation

Status: source `.76`, implementation only. These helpers do not register the
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

`authority_webauthn_registration_production.py` now composes the genuine
ceremony parser and attestation verifier with fixed claim derivation and that
original-envelope signer. It returns the original signed bytes and final
registration arguments containing their actual digest/base64 encoding. It owns
the supplied ceremony, row and trust snapshots before callbacks and accepts no
successful-attestation DTO. Those snapshots, enrollment permission and signer
configuration still require independent admission; producing these arguments
does not grant registration or persist evidence.

The v2 custody projection uses the existing
`policy_authority_external_evidence_receipts` table's exact **17 fields**. Its
`statement_json` retains the whole original canonical signed envelope, not a
claims-only reconstruction. The row binds the original-byte evidence identity,
statement/signature/binding digests, signer identity, source, purpose-specific
type and validity interval. For v2, `verified_at_epoch_ns` is the signed issuance
instant, so repeated verification derives identical unused row material.

Consumption selects that exact evidence-digest primary key, genuinely verifies
the original signature and all independent expectations, and compares all 17
fields against the unused `verified` projection. V1, consumed, revoked or
partially matching rows fail. The held UTC database instant must match the
verification time and lie within the signed interval. The returned effect sets
`consumed`, the deterministic operation ID and consumption time; it is not a
write, receipt token or substitute for selected-row/root admission.

The required dependency order is acyclic:

```text
admitted ceremony or already-committed stage
  -> semantic intent and independently verified operation facts
  -> purpose-specific signed evidence
  -> original-envelope evidence identity and independently admitted custody
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
signed installation evidence. Its adapter now closes four exact primary-key
queries: publication, high-water, absent deterministic audit and retained v2
evidence. It renders publication, high-water, audit and consumed-evidence effects
together through the real mutation templates into `KernelTransition`. The
business limits remain four rows / four mutations / 128 work units; common
audit-capacity finalization remains separate. No unused consumption recipe is
returned, and a local installed file alone is not publication authority.

## Registration read, effect and write-proof integration

Registration now produces actual `BoundedQuery` / `CompleteIndexQuery` objects,
including exact new-credential/audit absence and the real selected-high-water
field join to the published trust predecessor, plus the exact v2 evidence PK.
Its mutation adapter renders credential creation, challenge consumption,
evidence consumption, audit insertion and any sibling invalidations through
existing templates into `KernelTransition`: four to 36 business mutations.
Independent evidence pins remain mandatory; it is not a keyless kernel.

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

The private planner acquisition now joins the actual mixed-query read path,
genuine registration kernel, common capacity query/finalizer and indexed-primary
mutation-frontier acquisition. It owns the request and independent pins/root
expectations before callbacks, compares observed primary and counted heads to
those expectations, and bounds the database cutoff against admitted time and
deadline. The counted read phase retains all source write heads, while read
verification checks its exact family; the actual write engine then reconstructs
the affected primary and counted before/after roots. Read and write acquisition
share one physical ledger and original work allowance, with a closed mutation
trace. The returned acquisition object is ordinary observations, not a signed
plan, authenticated-root token or commit authority.

Registration's business bounds remain 112 rows / 40 mutations / 1,024 work units,
plus exactly one framework capacity row, one mutation and two work units. The
ordinary/OIDC query programs have eight/eleven business query objects, with
maximum row sums eight/43. Revocation's existing family and global resource
allowances are unchanged. Both consumers now declare their purpose-specific v2
evidence types; no v1 reinterpretation is permitted.

The attestation core also has a private shared-work path for actual parsing,
hashing, canonicalization and cryptographic verification. Source inputs are
bounded and native calls guard the meter; JSON/CBOR/X.509/EC/RSA internals and native
allocations are **not** represented by invented hash/byte/node charges. These
changes do not establish whole-process CPU, memory or deadline guarantees.

## Admission and execution still required

No durable evidence producer INSERT/root-admission path or independently
configured registration acquisition owner is established by these helpers.
Caller-supplied current roots, signer pins, request authority and transaction
ownership remain explicit prerequisites, not values authenticated by copying.
Trust staging still needs its complete successor query/manifest integration;
completion needs its independently admitted committed-stage/installation owner.
Registry and public operation admission, authorized atomic execution, terminal
witnessing and recovery remain pending. The generic evidence signer and ordinary
row/acquisition results cannot fill those gaps or repair service startup.

Broad fixtures and full verification remain deferred to the consolidated frozen
build. Production acceptance additionally requires independently operated
signing, witness and measured-runtime infrastructure, which is not provisioned.
