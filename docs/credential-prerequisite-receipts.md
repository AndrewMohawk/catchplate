# Credential prerequisite receipt retention

This is an internal evidence-retention step toward the active/candidate runtime
required by `goal.md`. It is not a new selectable evidence profile, a resolved
policy plan, or production acceptance. Existing single-plan effect-intent and
requirement checks remain strict.

## Evidence and ownership

The credential helper must bind its outer work to the admitted request,
generation, policy snapshot, original active-plan digest, committed decision
time, principal, route and credential slot before preparing a custody barrier.
A subsequent binding cannot relabel work that already started. Identical
bindings are idempotent; changed bindings fail closed.

Fallback principal lookup in pure active/candidate evaluation and prerequisite
scope reconstruction uses that explicit decision time, including bearer-token
expiry. It must not call the convenience identity lookup that reads the current
clock. This does not replace live ingress or pre-dispatch identity revalidation.

Request-time and query-date window constraints in the pure evaluator also use
the supplied semantic decision time. A query date exactly at its maximum age
or allowed future-skew boundary remains eligible; crossing either boundary
denies. Unrepresentable time arithmetic fails closed. Separate live callers
retain their clock-reading wrappers; this change does not treat an old semantic
decision as proof of current trust, credential or transport freshness.

Candidate response-date checks use the explicit response capture time already
bound into the response facts, including Gmail internal-date validation. That
response observation time is distinct from the request decision time above.
This removes an implicit clock from candidate response evaluation; it does not
establish full dispatch comparability or prove that the independent live
response path uses exactly the same reference time.

The bounded receipt slots describe the existing outer generation, OAuth
rotation, lease and decryption wrappers. They do **not** prove four distinct
provider operations. A cache hit or singleflight follower can produce the same
outer result, and the lease path can internally perform a generation lookup.
Actual refresh, exchange, mint and decrypt coverage therefore remains a
separate producer-integration requirement.

Reserve the complete sibling group before any barrier or credential operation.
Retain compact references only after joining the genuine verified commit to
its exact preparation, barrier receipt, terminal state and result. The compact
form holds inline commitments, not secret material, metadata graphs, signatures
or variable-sized wire documents. The signed wire evidence remains a custody
storage responsibility; local retention is not a replacement for that store.

A successful resolution requires all required siblings to have verified
`Committed` receipts for the same result. Generation and lease observations
must agree on version and public-metadata commitment; secret availability can
legitimately change as a secret lease is obtained. A later denial retains work
that really completed without inventing a resolved credential in the denial.
An asserted resolution must match the retained result.

## Failure semantics

Every started sibling must be settled or remain an explicit reconciliation
obligation even if an earlier preparation, commit or local retention fails.
Do not retry provider work to recreate missing evidence. A failed barrier
acknowledgment is ambiguous persistence, not proof that no barrier exists.
Unknown or reconciliation outcomes are never successful credential resolution.

Durable commit can succeed before a subsequent local lock or publication fails.
Such a failure must not publish a successful local resolution or claim that
the durable effect was undone. Preserve the exact effect identity needed for
reconciliation and fail closed.

Pending and terminal ownership must preserve the exact retained evidence, and
its commitment must participate in the terminal's effect-result binding. This
binds what was retained; it does not discharge additional plan obligations or
authorize substitution of a child plan.

Taking the terminal evidence snapshot must seal further credential preparation
and successful resolution publication. Cleanup of already-started work still
has to settle or reconcile; it cannot rewrite a sealed terminal snapshot or
silently disappear because that snapshot has been taken.

The queue budget accounts for fixed inline retention and its bounded copies.
This is a modeled increment to request/response job accounting, not a proof of
total process RSS, active-admission capacity isolation, or latency bounds.

## Verification boundary and next integration

The local component fixture signs barrier and commit payloads and invokes the
existing signature, independently pinned key, time/checkpoint, persistence and
retrieval verifiers. Its exact-byte in-memory stores are not independent
production storage. It does not prove assignment-bound production authority,
real custody RPC, provider mutations, restart recovery, one-use replay/CAS
behavior, or the complete request path. Test-source presence is not evidence
that those tests have run; consult the evidence for the exact frozen commit.

The separate [custody response consumer](custody-response-verification.md)
documents ingress/terminal wire verification and retained publication context.
Its local cryptographic and state-machine tests have the same production-proof
boundary; they do not supply the missing receiving authority service.

Actual parent-to-resolved refinement must recompute the child from the same
immutable facts and committed time with both exact credential slot and version.
It must preserve each parent obligation and its verified prerequisites. The
current pure evaluator still emits `ResolveCredentialVersion` when a version
is known; its claim changes. It does not currently erase that intent.

Enabling refinement requires the coordinated versioned Rust, schema, custody
and Python producer/consumer contract, plus mandatory active admission for both
sampling outcomes, isolated candidate resources and truthful denial terminals.
Retaining receipts alone does not satisfy those requirements or make candidate
failure independent of active traffic.
