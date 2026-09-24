# Work accounting for the actual revocation query recipe

## Source boundary

The private `_revocation_query_program` in
[`authority_transition_webauthn.py`](../serverware/authority_transition_webauthn.py)
runs the genuine cutoff-native business recipe and the genuine framework
`add_capacity_query` under one supplied internal work object. Its output is a
tuple of source declarations, not an admitted operation or successful proof.
It is unbuilt, unexecuted and not activated in a planner. The separate
[mixed proof composer](authority-revocation-read-write.md) now calls this private
entry point after owning its entire raw input graph.

The public unmeasured APIs keep their signatures and source semantics. Private
workers share the actual argument validation, business-intent normalization,
audit identity material and query recipe. There is no second implementation of
the intent schema, UUID document or query program to compare against the first.
The generic canonical encoder, source query closure and capacity API retain
their existing behavior.

This private entry point requires the real `_ValidationWork` object used by
[query-observation accounting](authority-query-read-accounting.md). Helpers
reuse it; they do not create independent 64 MiB allowances. An enclosing
composer must clamp the phase to its remaining outer budget and debit the
actual work, including earlier input capture and later proof/transport phases.
The unchanged source ceilings are 8,000,000 hashes, 64 MiB input work,
1,000,000 JSON nodes and depth 128. Individual phase ceilings are not a promise
that their independent maxima fit simultaneously.

## Charge at the actual work sites

For a canonical JSON graph, let `L` be its encoded byte length and `N` its node
count, including object keys. Incremental premeasurement itself consumes work.
The next real pass is reserved before its buffer, parser or hash is invoked.

| Work | Defined charge |
| --- | --- |
| Canonical JSON emission | Measurement plus encoding: `2L`, `2N` |
| Canonical emission, ASCII decode, JSON parse | `4L`, `3N` in total |
| Shallow copy or recursive scan | Conservative measurement plus full-graph work: `2L`, `2N` |
| Graph equality | Prepare both complete operands; no short-circuit refund |
| Raw UTF-8 | Two passes of the actual raw byte length and two scalar nodes |
| Audit subject | Raw UTF-8 preparation, then one SHA-256 |
| Deterministic audit UUID | Actual identity document encoding, then one SHA-256 |

Shallow-copy charges intentionally use the complete source graph rather than
claiming to measure Python allocation sizes. Fixed, source-bounded metadata and
scalar guards are not a count of every instruction or temporary allocation.
These units must not be presented as a network-byte, external-parser or
whole-process memory limit.

The optional audit-event encoding and final prepared-argument encoding are
separate from business-intent normalization. The latter charges its actual
recursive forbidden-field scan, source copies, filtered canonical document,
ASCII decoding and JSON parsing. Comparing the supplied intent with that
genuinely normalized result is additional work. A previous copy or encoding
does not make a later traversal free.

Audit identity derivation retains the real UTF-8 subject and actual canonical
UUID material. It does not ask a meter to recompute the hashes or duplicate the
identity document. Hash reservations precede the genuine SHA calls.
The UUID purpose's text-validation encoding is charged separately from its
subject and canonical document, as are the source input's actual text guards.

## Complete-profile work

The full program performs six binding-constructor profile hashes, six
business-closure profile hashes, and twelve more across capacity composition's
snapshot and closure. With `J` actual audit subjects:

`successful_generation_hashes = 24 + 2J`

Each profile call also performs its real fixed-descriptor UTF-8 JSON encoding.
Known hidden constructor work is reserved before calling the genuine binder,
closure or capacity function; cached or repeated inputs earn no refund.
This formula excludes later `contract_value` serialization, which performs
additional complete-profile hashes and must be charged by its own consumer.
Failed batched preparation may reserve work that never executes; it never
authorizes an unreserved hash or returns a successful generation result.
Any inspectable counters after failure describe partial or reserved work only.

The input preparer spends five `2L/2N` passes per hint list: set and sorted-list
copies, both equality operands and the final list copy. Each of the six actual
binders repeats its own validation, spending six such passes per hint list for
the owned tuple, set, sorted list, final tuple and two comparison operands.
Their actual record/hint text encodings are additional raw UTF-8 work. No
unrelated audit-event graph is used as a surrogate for these small inventories.

Each of the 20 constructor preparations uses the actual selector-pair graph to
conservatively bound two selector-dictionary copies. Text values have their real
codec encoding, with a second encoding for the stricter source-ID guard; the
fixed status enum has only the codec encoding. These generation-only charges
do not change the separately defined measured QueryRead metric schedule.

## Required caller and remaining integration

The enclosing composer must own the complete raw graph before the first hash.
This private generation helper is not an independent ownership boundary and
does not snapshot all caller rows, proofs, arguments and evidence for it.
Repeated calls with the same work object accumulate work instead of resetting
its counters. Result declarations and work observations are not input
capabilities for a later proof verifier.

The [shared source recipe](authority-complete-query-contract.md) preserves its
existing input-claim boundaries: supplied assertion IDs are not signed evidence,
the cutoff is not a trusted clock, and the no-audit case does not consume the
request digest. Full operation admission must validate and bind those values,
even where the query recipe itself does not use them.

The mixed composer regenerates the exact source program from owned context,
validates retained observations under the same remaining budget, binds full
point keys in both presence and absence, and compares complete observations
with actual joined-leaf order. This composition is still unexecuted source.
Raw retained transport,
kernel/audit-capacity admission, coordinated SQL/executor protocol and current
root authority remain separate requirements. Snapshot/v3 and all four startup
blockers are unchanged.

## Verification boundary

The independent source-work fixture is
[`test_authority_revocation_query_work.py`](../scripts/test_authority_revocation_query_work.py).
Its expected programs reuse independent literal query and identity documents;
work totals must independently enumerate the actual copy/encoding/hash schedule,
not derive expected limits from the production metrics being checked.
Its 18 authored methods cover exact and one-unit-short limits, genuine worker
invocation, Unicode normalization, reservation-before-hash behavior and repeated
generations exhausting the unchanged 64 MiB work ceiling.

All authored tests are unrun. Source inspection and isolated-script registration
do not prove runtime, SQL or production readiness. Native-suite inventory,
deadlines, exclusions and the required immutable verification prerequisites are
unchanged.
