# Private complete-query acquisition

## Status and admission

Source `.31` connects the real typed reader to a private complete-query collector
for `webauthn.credential.revoke`. This is unbuilt, unexecuted source wiring, not
an enabled operation or independently authoritative database snapshot.

The public v3 planner does not construct or accept this collector. Its whole
query inventory still rejects complete declarations before business/proof SQL,
including when ordinary queries precede them. The earlier database-clock read
is not trusted time authority. A private caller that completes acquisition gets
raw evidence in `PlanningState`; `TypedTransitionPlanningProgram.__call__` then
rejects that state **before the kernel** because the successor retained-evidence
protocol is missing. Neither gate is replaced by a successful component result.

## Actual acquisition and proof path

[`_CompleteQueryAcquisition`](../serverware/authority_complete_acquisition.py)
requires the actual cursor, trace and caller-owned `_ValidationWork`, source
arguments, cutoff, five declarations and primary before-root vectors. The caller
must own the read-only transaction and root capture. The collector copies its
context, rebinds every declaration to the genuine source role/arguments/cutoff,
and checks the full argument bytes and ordered roles when the mixed reader begins.

1. The [head reader](../serverware/authority_index_heads.py) captures the exact
   eight-head union of complete-read and potential-write profiles in one bounded
   SQL read. It checks source profile/manifest commitments, revisions, counts and
   empty-root conventions. Four heads serve the five read roles; both session
   partitions share one head. Capturing potential-write heads is not write-proof
   reconstruction.
2. The genuine [range reader](../serverware/authority_index_reader.py) acquires
   each role's inside leaves and canonical outside frontier, then reconstructs
   that range against its captured head. Every empty role still has a frontier.
   Hint lists bound results; they do not select addresses or permit truncation.
3. Each reconstructed leaf's primary ID drives one fixed-table exact primary-key
   fetch with a two-row duplicate sentinel. Full rows are bounded and copied,
   preserving counted-leaf order. A counted ID commitment does not authenticate
   the fetched full row by itself.
4. The real mixed reader retains ordered QueryReads and the deduplicated global
   row union, including ordinary point reads and overlaps. Existing staged
   reference proofs are merged with genuinely acquired remaining primary proofs.
5. The private [complete batch worker](authority-complete-query-batch.md) captures
   raw inputs and runs the genuine global primary evaluator and all five
   range/full-row joins on the same remaining work allowance. The reader then
   revalidates observations against the engine's owned rows. Only after this
   succeeds can the collector expose its cutoff, eight heads and five frontiers.

There is no caller-provided successful proof token or substitute verifier.
Current revocation has no scalar contract selectors: global and query-local
`contractSelector` values must remain null, preserving the existing batch guard.
A future query family cannot silently discard legitimate global selector tags.

Cursor, trace and meter identities remain fixed. The collector progresses from
beginning through reads to proof completion; failure, out-of-order use or caught
reentrancy poisons it. There is no retry with a fresh allowance or publication
of partially verified evidence.

## Limits and accounting boundary

`PLANNER_COMPLETE_ACQUISITION_CONTRACT` is immutable and bound by the operation
manifest and schema-source digest. It declares private-worker-only admission and
`publicV3Enabled: false`; schema version 9 and all v3 field inventories stay unchanged.

| Resource | Source bound |
| --- | ---: |
| Shared hash / input / JSON-node work | 8,000,000 / 64 MiB / 1,000,000 |
| JSON traversal depth | 128 |
| Cumulative acquisition SQL calls | 4096 |
| Parameter / returned-frame work | 4 MiB each |
| Exact primary row | 1 MiB |
| SQL calls per range | 20 |
| Node-identity batch | 256 |
| Business trace / separate framework trace | 4096 / 69 |

Head, range and exact-row acquisition share one private acquisition budget,
cursor, trace and work object. Parameter and returned scalar frames are charged;
full-row retention additionally charges its eight-byte length frame and actual
canonical bytes. Defined UTF-8 scans, copies, encodings, source hashes, range
reconstruction, [query bookkeeping](authority-query-read-accounting.md) and
global/join verification spend the same remaining work. Repeated proof and
observation passes are not discounted. Public standalone component metrics and
return types remain unchanged; shared batch metrics report the invocation delta,
not a new allowance.

The hash-free [trace validator](../serverware/authority_index_trace.py) admits
only the exact source head, range and primary-fetch markers under the private
trace permission. It adds no trace allowance, mutation permission or generic
metadata access. Shape validation does not replace genuine profile, interval,
root, key and row association checks.

These are defined source-work limits, not whole-plan CPU, memory or deadline
accounting. SQL execution, driver/process allocation, staged proof work, primary
proof acquisition, trace serialization, fixed metadata scaffolding, kernel,
write mutations and retained-protocol work are excluded. Existing separate
bounds still apply; signed business `workUnits` is not redefined.

## Authority and retained-evidence work still missing

Same-transaction database roots and cutoff are observations, not independently
authenticated current roots or time. The collector does not provision an
independent root-vector authority, an enrolled initial checkpoint, rollback-safe
current-vector advancement, or ambiguous-commit reconciliation. The explicit
expected roots and time accepted by the [semantic composer](authority-revocation-semantics.md)
also need an actual trusted producer; equality checking does not supply one.

The private evidence must eventually survive coordinated planner, signed plan,
persisted replay, service, SQL snapshot/commit and receipt consumers. Existing
closed v3 readers, the nine-frame Snapshot/v3 and their digests are unchanged.
No successor wire schema or activation is supplied here. Installed-storage and
population admission, independent roots/time, retained read/write evidence and
the [four missing registered kernels](authority-transition-startup-blocker.md)
remain distinct production gates.

## Authored coverage, not execution evidence

The new [collector](../scripts/test_authority_complete_acquisition.py),
[head](../scripts/test_authority_index_heads.py) and
[trace](../scripts/test_authority_index_trace.py) suites contain 20, 18 and 15
authored methods respectively. They use independent trees/records and genuine proof
engines, covering ordered and empty roles, full-row corruption, context and
ownership changes, cumulative limits and poisoned lifecycles. The batch, range
and frontier suites preserve their old methods and add shared-work controls.
Startup-dependent cases retain the real registry import and both planner gates.

Existing-suite totals are now 28 batch, 30 range, 33 frontier, 20 planner/capacity
source-linkage, 20 ACL/source-contract and 38 startup methods. These are authored
inventories only; the native inventory stays at 252 methods across fourteen suites.

None has been executed. Deterministic SQL responders are not PostgreSQL
transaction evidence; source review and fixture counts establish neither service
startup nor production readiness.
