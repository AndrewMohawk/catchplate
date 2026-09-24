# Planner-only observed revocation production

Source `.56` separated the genuine read transaction from writer persistence;
`.57` adds measured-configuration construction and a private planner-service
composition. Both remain unbuilt and unexecuted. `RevocationObservedPlanner`
does not enable a service purpose or any unfinished WebAuthn registry gate.

## Credential and ownership boundaries

The new owner holds only the planner read DSN, bounded connection timeout,
seven planner database/measurement identity scalars, planner signing key,
two public keys, verifier identity and historical age/skew policy. These ten
settings are snapshotted before invocation callbacks. A constructor is not key,
configuration, database or launch admission.

Callers supply the original request, assertion evidence, nine historical
context fields and full independently obtained root inventory. They cannot
replace configured identities or age policy, inject an expected-root subset,
or supply a successful producer result. Real copies precede connection/key
callbacks. The configured fields form the fourteen-field planner context;
actual acquisition and effects determine the final independent root subset.

```mermaid
flowchart LR
    I[Independent request, history and full roots] --> P[Planner-only owner]
    C[Admitted read identity, keys and policy] --> P
    P --> R[Read-only transaction: manifests, acquisition, proof and signing]
    R --> X[Close cursor, transaction and connection]
    X --> B[Original signed plan and context bytes]
    B -. authenticated transport still required .-> W[Separate planner-writer]
```

The actual read body is shared with the previous combined coordinator. It uses
the real planner identity check, source manifests, one complete trace, genuine
observed acquisition, proof packaging and signing. It does not call the legacy
`MeasuredPlanner.derive`, create a fresh work allowance, or construct a dummy
persistence owner. The combined coordinator retains its outer input copies,
writer suffix and original exact-context branch.

## Transaction and result contract

One PostgreSQL connection owns three real context scopes: connection,
transaction and cursor. The transaction is set to `SERIALIZABLE READ ONLY
DEFERRABLE`. Inert lifecycle guards check the original raw connection identity,
idle/active transaction states and unchanged work around callbacks. The cursor
requires an already-active transaction, including during the initial `SET`;
it is not the verifier root reader's idle-to-active cursor.

The expected context is copied and checked against held independent pins before
read-scope cleanup. The owner returns the original immutable envelope bytes,
original evaluation-context bytes, acquisition cutoff and detached expected
context only after every scope closes. None is a persistence receipt or an
authority token. A cleanup failure denies the result. The old coordinator maps
only the dedicated lifecycle guard error back to its existing store error;
planner and proof exceptions retain their original types.

New owner timeouts are exact integers from 2 through 300 seconds. The previous
coordinator still accepts its historical one-second value. Assertion age is
the configured challenge policy, plan age cannot exceed thirty seconds, and
skew is the source five-second policy. Metadata admission, driver work and
fixed configuration checks are not whole-process H/B/N accounting. A hostile
driver's hidden commit-and-BEGIN is not disproved by observed status equality.

## Measured planner composition

The private `AuthorityProcess._produce_revocation_observed_plan` now captures
the request, evidence, nine-field history, full independent inventory and full
measured configuration before launch, descriptor or key callbacks. It holds the
process signer rather than reading it again after callbacks. The active planner
check precedes reading the planner-only DSN. Generation is obtained last, so no
descriptor callback interposes before the mapper owns its launch bindings.

The separate configuration mapper checks the complete configuration commitment,
source revision/query manifest, generation membership, role modes and both
response/SPKI key pins. It derives the database role/TLS/measurement tuple from
the planner configuration and the verifier session from the configuration
digest and verifier measurements. It also checks the actual held signer's public
key against the admitted planner key without signing. Configuration consistency
and ordinary constructor objects are not root-signature or launch admission;
the genuine service loader and descriptor admission remain prerequisites.

Historical policy is identical to the independently configured receiver: exact
measured WebAuthn challenge age, the lesser of the verifier's internal age and
the source thirty-second plan limit, and source five-second skew. Planner
internal-envelope age is a different policy and cannot silently replace these
retained context fields. Measured finite timeouts must be within 2..300 seconds
before flooring. All real capture and framing use the same remaining work.

## Serving and verification work still required

Authenticated original-byte serving and transport remain unfinished. The writer
socket is pinned to the planner UID/GID.
The legacy verifier's direct reservation call does not match that topology;
a successor needs a planner relay that preserves the verifier's authenticated
originals, or an explicitly reviewed endpoint design. Do not widen DSNs or
socket peers to make the old call work.

Legacy replay stores a payload and re-signs it. It cannot substitute for the
original signed-plan/context custody required here. The writer must also retain
independently authenticated request/history/root expectations; supplied context
bytes cannot authenticate themselves. Writer role/transaction checks and schema
ACL installation alone are not a per-connection TLS, PostgreSQL-version or
complete privilege-admission proof. Revision `.59` adds those checks to the
separate configured v4 writer owner; it does not upgrade the latent legacy
writer routes or establish executed database/TLS evidence. See
[writer connection admission](authority-revocation-writer-connection.md).

The successor transport's four-MiB limit covers the entire message, not each
inner value. It cannot carry every otherwise-valid 64-MiB plan plus context in a
base64 wrapper. An explicit bounded transport profile, preserved authenticated
verifier headers, writer-response key custody, and durable exact-byte retries
are still required; the legacy unsigned responses and payload re-signing cannot
supply them. A combined persist-and-reserve operation also needs one admitted
outer writer transaction, not two separately committed convenience calls.

Component fixtures cover inert ownership/accounting and explicitly synthetic
driver guards. The real planner-to-handoff tests remain in the registry-gated
startup suite, with actual proof/signature workers and no registry substitute.
Neither suite has been executed for this source. Follow the preparation and
sequential frozen no-build requirements in [goal.md](../goal.md).
