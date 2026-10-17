# Shared work accounting for audit-capacity finalization

## Scope

The private measured workers in
[`authority_audit_capacity.py`](../catchplate/authority_audit_capacity.py)
charge the actual [global capacity contract](authority-global-audit-capacity-design.md)
under an enclosing computation's remaining work allowance. They do not replace
the finalizer, reproduce its arithmetic in a parallel implementation or accept
a previously successful capacity result as authority.

This source is unbuilt and unexecuted. Accounting does not prove initialized
population, primary membership, independently current roots, trusted time,
business-kernel authorization, audit delivery or SQL commit. The public
finalizer and validator retain their existing signatures and behavior.

## One meter through the genuine repeated checks

`_finalize_capacity(context, mutations, work=work)` and
`_validate_capacity_transition(..., work=work)` accept one private exact
`_ValidationWork` object. They create no fresh ledger, reset no counters and
grant no source-sized helper allowance. The caller must already own its input
graphs; these helpers do not add a whole-input capture before their first hash.

The finalizer checks the real source mutation templates, selected identities,
full before images, original keys and compact initialized counter. It computes
the complete outbox delta and appends one framework-owned full-row counter CAS
only when outbox mutations exist. It then calls the actual validator again
with the same meter. That second inventory/state computation is genuine work
and is charged again. An empty participating transition still checks its counter
baseline; a nonparticipating operation cannot acquire that counter's authority.

Missing baselines are never initialized to zero. Capacity underflow/overflow,
terminal outbox reopening, unadmitted deletion, caller-supplied counter writes,
wrong state commitments and changed identities continue to deny. No accounting
success changes these semantic checks or grants a business mutation slot.

## Defined work units

For canonical ASCII JSON of `L` bytes and `N` nodes, nodes include object keys
and every repeated occurrence. The existing representation-validation walk is
the measured walk; it is not preceded by an unaccounted duplicate traversal.
The actual canonical encoder is reserved before producing its buffer.

| Actual operation | Byte work | Node work |
| --- | ---: | ---: |
| Validation/measurement plus canonical encoding | `2L` | `2N` |
| Canonical encode, implicit bytes-to-text decode and JSON parse for a deep copy | `4L` | `3N` |
| Conservative full-graph preparation for a shallow copy | `2L` | `2N` |
| Preparing a graph/string comparison | `2(Lleft + Lright)` | `2(Nleft + Nright)` |
| Comparing already encoded operands | Sum of both operand lengths | 0 |
| ASCII decoding already encoded canonical state | Encoded length | 0 |
| Raw UTF-8 measurement and encoding of `U` bytes | `2U` | 2 |

Projection copies use a conservative full source graph where needed; a small
resulting primary-key object does not erase the source preparation charge.
Outbox ID UTF-8 measurement and encoding are separate from JSON key encoding.
Source table names are ASCII, so their actual ASCII encoding uses the same raw
UTF-8 preparation units. Selected/mutation key digests and stored state strings
use graph/string comparison preparation; canonical byte comparisons instead
charge both already encoded operands after charging their encoders.
Fixed source metadata, bounded inventory scaffolding and scalar comparisons
are not claims to count every CPU instruction or Python allocation.

Every actual selected-key or counter-state digest receives a hash charge before
the hash. Let `S` be the selected-row count, `P` indicate a participating
operation with a valid baseline, and `O` indicate a nonempty outbox mutation set.
For successful calls:

| Invocation | Hash work |
| --- | ---: |
| Standalone validator | `S + P + O` |
| Finalizer with no outbox mutations | `S + P` |
| Participating finalizer with outbox mutations, including its real revalidation | `2S + 4` |

The two fixed module-level partition/empty commitments are import-time source
constants, not fresh per-call hashes. The existing capacity-query generator's
profile accounting is separate and is not charged a second time here.

The enclosing source ceilings remain 8,000,000 hashes, 64 MiB of defined byte
work and 1,000,000 nodes, with a fixed depth bound of 128. A caller may lower
the cumulative ceilings or arrive with work already spent; every subsequent
phase sees only the remaining allowance.
Repeated traversals can exhaust that allowance even when each individual
document is below its local cap. No rejection refunds prior work.

Shared-meter validation and exhaustion propagate as `QueryReadWorkError`.
In particular, preparation may reject a non-lossless input before the capacity
walk sees it. Failures raised by the capacity contract remain
`AuditCapacityError`; the public unmetered error route is unchanged.

The original business selected-row, total selection, compact-counter and source
mutation limits remain independent checks. Work accounting is neither an
incoming transport-byte bound nor a process-memory guarantee. Signed operation
`work_units` are also a different contract: their existing business/framework
slot arithmetic is unchanged by these hash/byte/node counters.

## Verification and next integration

The [18 authored controls](../scripts/test_authority_audit_capacity_work.py)
use real source templates and independently framed compact counter states.
They target public/private behavior parity, independent pass totals, genuine
internal validator identity, exact and one-unit-short budgets, preconsumed
allowance, repeated large values, unchanged semantic denials and preparation
before encoding/parsing. All controls are source-only; no test has run or passed.

This measured seam is a prerequisite for the next semantic revocation bridge.
The [retained proof bundle](authority-revocation-proof-bundle.md) currently proves
supplied writes but does not call this finalizer or authorize those writes.
The future composer must run the actual revoke kernel and this finalizer,
compare their finalized mutation set with the genuinely proved writes, and
charge all additional kernel/evidence work under the same budget. It must also
admit independently verified assertion evidence, request bindings and time.
No planner registration, persisted protocol change or production activation is
introduced by optional capacity accounting.
