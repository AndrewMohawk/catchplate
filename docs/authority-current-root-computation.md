# Current-root computation and database observations

Source `.134` implements genuine successor-plan replay into complete root
vectors and a dedicated signed reserve control. It also supplies a
same-transaction database observer, configured read owner and protected marker
schema. This is unbuilt, unexecuted source, not a running current-root authority,
capability admission or successor SQL execution. The
[durable decision owner](authority-current-root-decisions.md) remains separate.

## Original plans to complete vectors

[`authority_current_root_plan_replay._replay_on_work`](../serverware/authority_current_root_plan_replay.py)
takes `operation`, exact `originals`, independently admitted `expectations`,
actual `planner_public_key`/`operation_public_key`, `before_vector_bytes` and
the caller's existing `work`. It accepts all six source successor operations:

| Family | Operations | Original bytes, in order |
| --- | --- | --- |
| Revocation | `webauthn.credential.revoke` | Envelope, evaluation context |
| Evidence admission | `webauthn.registration.evidence.admit`, `webauthn.trust.installation.admit` | Envelope, inputs, evaluation context |
| Transition | `webauthn.registration.finalize`, `webauthn.trust.stage`, `webauthn.trust.complete` | Envelope, proof, inputs, context |

The actual family verifier authenticates originals and recomputes semantics,
memberships, query associations, mutations and required counted projections.
Its operation-local predecessor descriptors must equal those in the complete
before-vector. Only genuine replay outputs replace descriptors; every other
table/profile retains all original fields. The actual vector codec and
per-mutation delta compatibility checks close the resulting full inventory.
Originals plus the before-vector share the existing 64-MiB aggregate ceiling;
there is no replacement work allowance or successful-result input.

The ordinary derived result retains complete before/after bytes and identities,
typed request, kernel result, original plan/retention identities and original
interval. Historical replay itself samples no clock and does not assert that
the plan is live now. Revocation's signed Snapshot/v4 and capability ID remain
separate fields, not invented identities for the other families.

## Dedicated computation snapshot and reserve producer

[`authority_current_root_computation._produce_reserve_on_work`](../serverware/authority_current_root_computation.py)
invokes that real replay itself. Additional inputs are original root enrollment,
independently admitted root/computation keys, `capability_digest`, predecessor
sequence/head, fence and absolute deadline, with an optional inherited transport
deadline. No precomputed replay carrier substitutes.

It returns `CurrentRootComputation(request_bytes, snapshot_bytes)`: a signed
reserve control plus canonical
`serverware.policyAuthorityCurrentRootComputationSnapshot/v1`. This new snapshot
is **not** the existing revocation Snapshot/v4. Its 20 fields bind enrollment,
database/generation/measurement, typed operation/request, complete vectors,
actual result, retention/plan identities, ordered original-byte hashes/counts
and original timing. Revocation's original signed snapshot/capability ID are
preserved distinctly. Snapshot limits are 16 KiB, 512 nodes and depth 4.

`capabilityDigest` is an explicit scope commitment only: the producer does not
authenticate an original capability or authorize execution. The reserve keeps
the original issue time and clips expiry to the original interval, enrolled
control lifetime and supplied deadline; the inherited monotonic deadline is
never extended. Real clock/window checks bracket signing on the same work.
The decision owner must still join the exact predecessor and retained current
vector before it can durably reserve anything.

Source `.135` adds a separate [original-grant preparation and execution
admission](authority-successor-execution.md) path. It derives the capability
digest from a genuinely verified pre-decision grant and joins that same grant
again at final pending/plan admission. The scope-only producer described above
retains its narrower contract. Protected SQL activation and postcommit ownership
remain unfinished.

## Complete SQL observation, not enrollment

[`authority_store.current_root_observation._observe_on_work(connection, *, work)`](../serverware/authority_store/current_root_observation.py)
returns canonical complete-vector bytes from the caller's already admitted raw
PostgreSQL 16 SERIALIZABLE transaction. It opens/closes one cursor, not a new
connection or transaction. Two bounded SELECTs read every source primary root
and all eleven counted profiles; no operation subset or absent-head defaults
are accepted. Actual source manifest/profile, revision, digest and count joins
feed the real vector codec.

Three bounded state SELECTs compare backend/virtual-transaction identity and
inherited transaction/timeout settings initially, between inventories and at
the end. All five reads share one physical ledger and the original work. No
timeout is reset, permanent transaction ID allocated, or transaction committed.
Normal cursor closure precedes return. Database/TLS/role/ACL and outer lifecycle
admission remain the configured caller's responsibility; hostile database/driver
behavior and independent latest-head authority are not solved by these checks.
Unsigned SQL observations do not enroll a database or prove currentness.

[`CurrentRootReader`](../serverware/authority_current_root_reader.py) is the
implemented private connection owner. Its constructor holds `dsn`,
`connect_timeout_seconds`, `database_role`, TLS client DN/serial and issuer DN,
and `query_manifest_digest`. `read(*, work)` joins the real source manifest,
opens the actual driver with the existing PostgreSQL 16 verifier TLS/role/ACL
admission, and invokes the observer in one SERIALIZABLE READ ONLY DEFERRABLE
transaction. Bytes return only after normal connection closure. These scalars
must already be independently admitted; the class supplies neither configuration
signature admission nor a cold-start/service route or currentness authority.

## Protected marker and remaining execution boundary

`policy_authority_current_root_commit_markers` is the exact 18-scalar-field
framework table defined by
[`CURRENT_ROOT_COMMIT_MARKER_CONTRACT`](../serverware/authority_contract.py).
It binds pending/predecessor/fence, database/enrollment/generation,
operation/request/capability, computation snapshot, vectors and result. Pending
decision is the primary key; pending request and enrollment-scoped fence,
operation and capability identities are unique. It is immutable and excluded
from primary/count business maintenance.

There is deliberately no writer-receipt field: a later postcommit receipt must
commit the marker, not the reverse. Runtime roles cannot insert; the executor
has SELECT only, and no insert function is installed. SQLite insertion and
automatic existing-store adoption remain denied. The schema does not establish
that any protected marker has been written.

Still missing are independently admitted cold serving/key/measurement owners,
latest-checkpoint provisioning, actual capability and pending-decision executor
admission, same-transaction maintained writes/marker insertion, assured
postcommit production, and uncertain-outcome recovery. No listener or legacy
execution gate is enabled. Signing, custody, observation and a matching digest
are not substitutes for those authorities.
