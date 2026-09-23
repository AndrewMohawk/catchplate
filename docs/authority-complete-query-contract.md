# Source-bound complete index queries

## Status

This is unexecuted source implementation, not installed indexes or a working
WebAuthn operation. It gives the unregistered explicit-revocation candidate a
distinct complete-query declaration and removes its reliance on ordinary page
metadata. The planner rejects this query kind before any business or proof read
until actual frontier acquisition and evidence admission are implemented.
The earlier database-clock read still occurs; it is not trusted time authority.

## Distinct query kind

`authority_complete_query.CompleteIndexQuery` is not a `BoundedQuery`. Its
`serverware.policyAuthorityCompleteIndexQuery/v1` projection uses the distinct
`authenticated-complete-index-range` primitive. The legacy
`serverware.policyAuthorityQueryProgram/v1` projection is unchanged, and its
constructor and query-program closure reject the new primitive on an old query
object, including a constructor-bypassed object.

The new value stores only operation, role, immutable selector pairs and the
derived row allowance. Table, index identity, projection digest, query identity,
fixed index ordering and shared-budget group come from source definitions.
There are no caller SQL predicates, `ORDER BY`, absence keys, page fields,
continuations, arbitrary index names, supplied intervals or proof-result flags.
Fresh snapshots revalidate exact types and source constraints; even a frozen
object is not a verification token. Returned selector/contract dictionaries are
detached copies.

## Five explicit-revocation roles

| Role | Fixed index | Selector source | Row-bound hint |
| --- | --- | --- | --- |
| `sessions_pending_webauthn` | `webauthn_session_credential_status` | `record_id`; fixed pending status | `oidc_session_ids` |
| `sessions_active` | `webauthn_session_credential_status` | `record_id`; fixed active status | `oidc_session_ids` |
| `grants` | `webauthn_grant_approver_active` | `record_id` | `approval_grant_ids` |
| `approvals` | `webauthn_control_approval_approved` | `record_id` | `control_plane_approval_ids` |
| `global_registration_challenges` | `webauthn_registration_unused_global` | Supplied cutoff microseconds | `registration_challenge_ids` |

The binder requires explicit revocation, a bounded exact argument dictionary,
the source record ID and all four sorted unique hint lists. Source IDs retain
the candidate's 1,024-byte, nonempty, trimmed, control-free UTF-8 admission.
Hint lists have at most 32 entries each; their addresses never become index
selectors. Each role's fail-closed allowance is `max(1, len(hint))`. Empty hints
therefore still require a complete query and cannot assert an empty result.

The two session partitions share one distinct-primary-address union ceiling of
32, not 32 independently permitted sessions per status. The pure candidate's
exact hint-set comparison and existing whole-operation mutation limits remain.
The declaration records the shared group; a later complete evidence consumer
must enforce it on actual verified members. Individual declaration bounds do
not prove whole-program row/work admission or any result's completeness.
The declaration's one work unit preserves the existing query-program ledger;
it is not a claim that range acquisition or reconstruction costs one unit.
Those phases still need their own cumulative source limits before activation.

Expiry uses exact signed 64-bit microseconds. Conversion of a supplied aware
datetime uses integer UTC timedelta arithmetic, never a floating timestamp or
a sampled clock. Binding a cutoff to the source program does not authenticate
that cutoff. The [fixed projection contract](authority-index-primary-join.md)
still governs strict-after semantics, canonical stored expiry and full-row
membership. Existing unrestricted timestamp TEXT has not been migrated here.

## Source and planner integration

Source revision `.28` commits the five role descriptors, selector sources,
projection digests, bounds and groups in both the operation manifest and handler
digest. Only revocation currently admits this new primitive. All seventeen
pinned v9 schema-source revision checks move together to `.28`; no installed
database, recorded contract or accepted root is automatically upgraded.
The exact schema/migration admission still has to succeed before use.

The candidate emits all five new declarations alongside unchanged exact-primary
credential, assertion and audit queries. Query closure and shared audit-capacity
composition accept only the two explicit query kinds, retain the original
business/framework ceilings, and reject duplicate identities. The planner
rebinds all five roles to its actual arguments and supplied database time, then
uses the returned owned snapshots. Cheap tuple/count checks precede processing.

The reader rejects a complete declaration anywhere in the entire inventory
before starting its loop. Even a complete query placed after ordinary exact
queries cannot cause those earlier business/proof reads. There is no fallback
to `LIMIT + 1`, no constructed successful receipt, and no registry activation.

Query-read bookkeeping can snapshot, retain and compare the distinct closed
declaration without synthesizing legacy primary-key ordering. These first five
roles have no deferred selected-row references. Empty observations remain empty,
not invented absent primary addresses. Retained records still do not establish
predicate satisfaction, index membership, completeness, currentness or intent
admission; real proof reconstruction and source rebinding are separate duties.

## Remaining implementation and verification

The [storage integration contract](authority-index-storage-integration.md)
defines the next coordinated work: fixed storage/hash/projection admission,
bounded inside-leaf/outside-frontier acquisition, real joined verification,
all-writer full-row maintenance, exactly-once primary effects of index heads,
and authenticated bidirectional initial population. Independent root pairs,
trusted time, witness/fence authority and receipt reconciliation remain required.

Registration's conditional first-enrollment history and trust staging's replay,
generation and aggregate-withdrawal semantics need their own source roles and
reviewed whole-operation contracts. They are not enabled by borrowing these
revocation declarations. All four WebAuthn startup gaps remain visible.
Versioned closed query evidence and coordinated Python/SQL consumers are also
missing: the exactly nine-frame Snapshot/v3 is unchanged.

Twenty new methods cover the actual declaration/binder, independent profile and
interval encodings, source/handler commitments, immutable snapshots, mixed
closure/capacity and retained observations; one of those methods is supplemental
planner source inspection. All twenty existing candidate method identities are
preserved, with its query-selection assertions updated for the new type. These
tests are authored but unrun. No database, service or production verification is
claimed by this source checkpoint.
