# Current-root completion from committed-state observations

Source `.136` implements a fixed read-only completion continuation. It has not
been built, tested, imported or run and is not a provisioned completion service
or production approval. It does not install or enable successor SQL execution.

The path is:

`original pending decision + plan + grant → historical authentication/replay → committed marker and complete roots → exact comparison → signed complete control`

## Original authority, fresh completion only

[`authority_current_root_completion._produce_complete_on_work`](../serverware/authority_current_root_completion.py)
accepts the original enrollment, reserve request/state receipt, computation
snapshot, execution grant/enrollment and family-specific plan originals. It
requires independently admitted history and keys, request-authorization digest,
database/generation and the still-current exact pending sequence/head/fence.
It does not accept a successful replay result, marker observation or caller SQL
adapter as authority.

The actual historical pending/plan verifier replays the original plan and
reconstructs its snapshot and expected 18-field marker. The original execution
grant is authenticated and joined to those same-call commitments, including
the reserved capability digest. Original issue/expiry relationships remain
unchanged. An independently supplied checkpoint is still required; a valid old
receipt cannot declare itself the current pending decision.

A fresh completion control may follow execution-grant expiry: this path only
reads committed state. It neither renews execution permission nor re-executes or
resets a transition; signing alone does not release pending state. Its one
current completion window is bounded by the caller deadline, enrolled completion policy and any inherited
monotonic deadline, using the caller's existing work allowance throughout.

## Fixed database read owner

[`CurrentRootCommitReader`](../serverware/authority_current_root_commit_reader.py)
holds the exact seven connection settings: DSN, connection timeout, database
role, TLS client DN/serial/issuer DN and source query-manifest digest. The role
must be the independently provisioned
`serverware_policy_authority_completion_reader`; there is no environment role
override or role creation in this slice.

`read(*, pending_decision_digest, live_window, work, transport_deadline_ns=None)`
returns the detached marker and canonical after-vector bytes. The original live
window is required and never reopened.

The actual metadata bootstrap and expected-schema ACL sealer grant schema
`USAGE` and `SELECT` on exactly:

- `policy_authority_current_root_commit_markers`
- `policy_authority_authenticated_table_roots`
- `policy_authority_counted_index_heads`

The source-fixed [privilege checker](../serverware/authority_store/completion_read_sql.py)
uses the real effective-privilege query. It rejects business-table reads, DML,
function execution, role membership, grant options, schema creation and database
CREATE/TEMPORARY privileges. Role aliases are rejected. No marker insert
permission, automatic custody migration or live privilege repair is introduced.

The reader uses actual PostgreSQL 16 role/TLS/ACL admission and a fresh physical
`SERIALIZABLE READ ONLY DEFERRABLE` transaction. The
[fixed observation](../serverware/authority_store/current_root_commit_observation.py)
performs seven observation SELECTs on that same transaction:

`transaction → marker → transaction → all primary roots → transaction → all counted heads → transaction`

All four virtual-XID/settings samples must agree. This count excludes the
reader's transaction setup and identity/ACL admission queries. The marker lookup
is bounded and rejects absence or ambiguity; the complete vector comes from the
source-owned inventory, not caller-selected tables/profiles. The actual marker
after-vector digest is checked against that canonical full observation.

Only normal cursor/connection exit and a closed-handle check release the pair.
The completion producer then requires exact equality with its genuinely derived
expected marker and complete after-vector. A separate connection cannot observe
an executor's uncommitted marker. These checks still do not establish database
authenticity, hostile-host antirollback or independent latest-root currentness.

## What is signed

After the database connection is closed, the producer encodes the exact five
fields `schema`, `sourceRevision`, `marker`, `afterVectorDigest` and
`observedAtEpochNs` under
`serverware.policyAuthorityCurrentRootCommitObservation/v1`. This bounded inner
record is **unsigned on its own**. Its original bytes, hash and byte count occupy
the complete control's existing `writerReceipt*` fields.

The already enrolled completion key signs the full purpose-bound complete
control, including those bytes and the original pending/snapshot/result/vector
joins. There is no second receipt-signing key or new enrollment. A raw record,
matching digest or standalone dictionary is not a completion proof token.
Delivery to the [durable decision owner](authority-current-root-decisions.md)
and receipt/uncertain-outcome handling remain separate operations.

## Failure and remaining boundary

The original completion window is checked across replay, database work and
signing. The reader clips libpq's per-host connection timeout to the remaining
whole seconds and refuses less than its two-second minimum. It applies positive
PostgreSQL statement/lock/idle limits, reserving time for the seven observation
reads and normal exit. These are per-host and per-statement/wait limits plus
outer epoch/monotonic checks, not a guaranteed whole-connect duration or a hard
driver/native-call watchdog. A late failure does not renew the window. Missing
markers, changed roots, timeouts and transport errors do not prove noncommit,
clear pending state or authorize retry/re-execution.

The protected SQL issuer/capability-custody bridge, source-exact function and
trigger installation, actual writer/outer-commit owner and public finalization
remain unimplemented. Cold completion-key/configuration custody, trusted
measurement, independent current checkpoint/root provenance, provisioned roles
and infrastructure, and end-to-end uncertainty orchestration are still required.
The consolidated frozen build/verification phase remains outstanding. See
[successor execution](authority-successor-execution.md) for the unchanged
execution gate.
