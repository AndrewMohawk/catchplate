# Independent revocation root observations

## Status and purpose

Source `.52` adds a private verifier-owned read path for the complete root
inventory needed by credential revocation. It is **unbuilt and unexecuted**.
Component fixtures and source inspection do not prove a live PostgreSQL
session, measured service admission, installed permissions or a completed
revocation. Public dispatch and the unfinished transition registry remain
closed.

The verifier must obtain its expectations independently of a submitted plan.
The new reader therefore accepts no proposed root values, table selection,
index selection, query text or successful-proof object. Its output is ordinary
owned database observations. It neither authenticates a malicious database nor
turns a snapshot into a witness-enrolled checkpoint.

## Exact read inventory

| Read | Source-required inventory | What is checked |
| --- | --- | --- |
| Primary descriptors | Seven business and two authorization roots | Exact ordered table set; eight scalar fields; integer/digest bounds; depth 64 and radix 16; global query-manifest binding; canonical empty/genesis rules |
| Counted heads | All nine source-required read/potential-write profiles | Existing genuine counted-head validation, including table/profile/projection/manifest bindings, revisions, counts and canonical empty roots |

One bounded primary query reads the nine descriptors. One genuine counted-head
query reads the full nine-head inventory. Each query uses a limit-plus-one
bound and owns validated scalar rows before the next driver callback. Neither
query locks, mutates or repairs metadata. An absent, malformed, reordered,
duplicated or inconsistent required observation denies the call.

Both primary root classes store the **global business query-manifest digest**.
Authorization roots must not be compared to the distinct authorization-manifest
digest. The configured query-manifest pin is compared with the real source
manifest, not a manifest claimed by the plan or learned from the same rows.
No dependency-manifest-table SELECT is needed.

## Connection and configuration ownership

The configured owner retains bounded local DSN, timeout, role, certificate and
query-manifest pins before callbacks. Its public component call does not accept
an alternate opener, a planner connection or caller-provided admission verdict.
The real connector supplies the PostgreSQL driver; deterministic fixture seams
are not live connection proof.

The first application SQL statement selects SERIALIZABLE READ ONLY DEFERRABLE. Before root
reads, admission checks the supported PostgreSQL major version, exact current
and session role, transaction mode, TLS client identity, nonprivileged role,
and the real source-owned effective-privilege query. Failure paths attempt
cleanup even after work accounting is corrupted, without suppressing the
original failure. Entry, exit or close failures can leave an indeterminate
outcome; a post-exit guard cannot undo a transaction that already completed.

The private service adapter uses the actual measured configuration and active
verifier launch guard. Scalar capture is not a replacement for the service's
root-signature, topology, runtime-closure and attestation admission chain.
Database connection timeout is an integer from 2 through 300 seconds. Measured
finite fractional values within that range are tightened by integer conversion
(for example, 2.5 becomes 2). Lower values are rejected: libpq treats 1 as 2,
while zero means no timeout. The setting applies per host/address, not as a
whole-invocation deadline. These are the documented
[PostgreSQL 16 connection timeout semantics](https://www.postgresql.org/docs/16/libpq-connect.html#LIBPQ-CONNECT-CONNECT-TIMEOUT).

The role contract is [verifier read v2](authority-verifier-read-permissions.md):
the existing four evidence tables plus the primary-root and counted-head
tables. This does not authorize business-row, tree-leaf/node, writer-capability
or legacy outcome access. No writes, function execution or alternate role are
granted. This is a source installation change, not a live grant operation.

## Accounting and lifetime

The owner supplies the same remaining invocation work to the worker. A fresh
verifier-owned physical acquisition ledger and dedicated two-step trace cover
both root SELECTs; no planner ledger or proof-close trace is reused. The prior
transaction-mode statement and two catalog-admission queries are separate from
that two-read worker scope. A single read
phase spans both acquisitions. Caught nested use poisons the acquisition.
There is no replacement JSON/hash allowance.

Returned scalar frames, owned row copies and genuine counted-head work retain
their explicit accounting. The primary empty-root calculation reserves its
conservative cold-cache hash/frame work before calling the real helper. A
successful worker reserves 84 hashes: 65 for the
primary empty-root ladder and 19 for genuine counted-head source commitments.
Fixed source manifest construction/admission, catalog SQL, driver internals and
fixed observation scaffolding are outside that JSON/hash measurement; this is
not a whole-process or PostgreSQL wire-byte claim. External callbacks may not
spend, refund, replace or retype the shared work.

The result carries no planner cutoff, trusted-clock assertion or authority to
use those values after the snapshot. The original planner cutoff must still
come from the actual planner acquisition and be retained authentically.

## Planner handoff and remaining integration

Source `.53` adds the private [observed planning and persistence handoff](authority-revocation-observed-planning.md).
It compares the complete independent inventory against genuine acquisition
before packaging, then uses actual read/write profiles to select values from
the independent inventory. The same independently projected context reaches
plan production, configured persistence and the coordinator's result.
Expectations are not recovered from signed or stored output. This subsequent
source change is also unbuilt and unexecuted; it does not enable serving.

Authenticated cutoff custody, original invocation retention, execution
reservation/order, witness binding, current-root one-use execution and atomic
terminal publication remain incomplete. The
[service integration status](authority-revocation-service-integration.md) and [goal workflow](../goal.md)
remain applicable; none of these components opens a public route.
