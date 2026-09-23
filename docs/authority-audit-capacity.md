# Policy audit-capacity admission

Status: implemented source component, unbuilt and unexecuted. This is not an
authenticated global outbox count, a startup repair or production acceptance.

`serverware.audit_outbox_contract.MAX_PENDING` owns the existing 100,000-record
limit. The legacy DB admission constant and the policy transition helper import
that same value. A self-consistent aggregate row cannot choose another limit:
after the existing aggregate commitment/source validation, the policy helper
requires an exact integer equal to the source constant. Generic aggregates keep
their own capacity semantics, including quota/JIT limits and negative deltas.

The four policy writers have these fixed fresh-operation costs:

| Operation | Fresh audit INSERTs |
| --- | ---: |
| `policy.activation.prepare` | 7 |
| `policy.genesis.prepare` | 1 |
| `rbac.binding.mutate` | 1 |
| `policy.activation.abort` | 1 |

`_aggregate_mutation` requires the exact integer charge for that operation and
the existing framed operation/request identity. It rejects reused reservation
or commitment identities and retains the generic capacity, revision, sequence,
state-digest and source-revision checks.

The actual writers call `_audit_capacity_mutations` with their computed stage
outbox rows. It requires the exact bounded tuple size, distinct bounded ASCII
string identities and pending status. Each identity must have exactly one
selected row with `present: false` and an explicit `row: null`. The helper
returns the aggregate UPDATE together with the exact INSERTs it counts. The
writers no longer construct those outbox mutations separately. Any failure
returns no transition; constructing these mutation dictionaries has no DB
effects.

Previously, fresh activation preparation could charge seven while skipping
identical pre-existing outbox rows, and the other three writers could charge
one while updating an existing row. Partial/orphan audit reuse now fails
closed, including an identical pending row or a previously audited identity.
It is not silently converted to a fresh pending event or a smaller charge.
Existing whole-operation replay branches return before this helper and remain
unchanged. Query-time absence is deliberately not required: replay still needs
to read its previously committed rows.

## Evidence boundary

`scripts/test_authority_audit_capacity.py` contains authored real
`KernelContext` component cases with independently framed selected-row/state
fixtures. They cover fixed limits, exact capacity edges, operation-bound cost
and identity, one/seven returned INSERTs, existing/malformed/missing/duplicate
audit identities, unchanged inputs and generic non-audit capacity controls.
Supplemental source checks are linkage evidence only. The script is in the
isolated test inventory; none of it has run.

These are helper tests, not full executions of the four kernels. Their
self-consistent aggregate rows do not prove correspondence to 100,000 actual
pending/claimed records, independent root authenticity or all-writer count
maintenance. Bounded commitment maps and whole-operation row/work/byte limits
can reject earlier than the nominal capacity; no sustained 100,000-operation
workload has been demonstrated.

## Remaining integration

- Policy writers use aggregate kind `metadata-audit-outbox-capacity` and a
  one-frame partition commitment. Quota writers use a different row: kind
  `metadata-audit-outbox`, partition `global`, with a two-frame commitment.
  Legacy DB writers count actual pending/claimed rows instead. These are not
  one maintained global capacity authority.
- Audit inclusion/delivery does not maintain the policy count. All writers
  need one reviewed identity/profile and exact OLD/NEW membership deltas:
  pending insertion +1, pending/claimed movement 0, counted-to-audited -1,
  deletion -1 only for counted rows, and exact replay 0. Authenticated
  genesis/backfill and independently current roots are still required.
- Activation preparation already returns an empty exact replay but declares
  `permits_empty_mutation=False`; planner admission rejects that replay. This
  separate pre-existing inconsistency is not changed by the capacity repair.
- No operation bounds, wire schema, primary-tree framing, source revision or
  installed function manifest is reinterpreted here. Before execution, freeze
  the exact clean commit/tree and regenerate measured artifacts. In particular,
  the new module must enter the independently authenticated v9 Python import
  closure; copying it into an image alone is insufficient.

The [WebAuthn integration design](webauthn-authority-integration.md) still needs
global authenticated capacity before signed installation completion. The four
missing kernels and [startup blocker](authority-transition-startup-blocker.md)
remain unresolved. Verification must follow `goal.md`'s complete-source,
freeze, externally controlled preparation and sequential no-build gates.
