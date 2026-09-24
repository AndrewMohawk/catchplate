# Source-bound complete index queries

## Status

This is unexecuted source implementation, not installed indexes or a working
WebAuthn operation. It gives the unregistered explicit-revocation candidate a
distinct complete-query declaration and removes its reliance on ordinary page
metadata. The public v3 planner rejects this query kind before any business or
proof read. A [private acquisition path](authority-complete-acquisition.md) now
connects head/range/full-row reads to genuine joined verification on one shared
meter, but stops before the kernel without the successor evidence protocol.
Admitted roots and coordinated versioned consumers remain required.
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

## Six explicit-revocation roles

| Role | Fixed index | Selector source | Row-bound hint |
| --- | --- | --- | --- |
| `sessions_pending_webauthn` | `webauthn_session_credential_status` | `record_id`; fixed pending status | `oidc_session_ids` |
| `sessions_active` | `webauthn_session_credential_status` | `record_id`; fixed active status | `oidc_session_ids` |
| `grants` | `webauthn_grant_approver_active` | `record_id` | `approval_grant_ids` |
| `approvals` | `webauthn_control_approval_approved` | `record_id` | `control_plane_approval_ids` |
| `global_registration_challenges` | `webauthn_registration_unused_global` | Supplied cutoff microseconds | `registration_challenge_ids` |
| `pending_trust_publications` | `webauthn_publication_status` | Constant status `pending` | None; fixed bound one, must be empty for semantic admission |

The binder requires explicit revocation, a bounded exact argument dictionary,
the source record ID and all four sorted unique hint lists. Source IDs retain
the candidate's 1,024-byte, nonempty, trimmed, control-free UTF-8 admission.
Hint lists have at most 32 entries each; their addresses never become index
selectors. Each cascade role's fail-closed allowance is `max(1, len(hint))`. Empty hints
therefore still require a complete query and cannot assert an empty result.

The two session partitions share one distinct-primary-address union ceiling of
32, not 32 independently permitted sessions per status. The pure candidate's
exact hint-set comparison and existing whole-operation mutation limits remain.
The declaration records the shared group; a later complete evidence consumer
must enforce it on actual verified members. Individual declaration bounds do
not prove whole-program row/work admission or any result's completeness.
The declaration's one work unit preserves the existing query-program ledger;
it is not a claim that range acquisition or reconstruction costs one unit.
The private acquisition path now shares defined cumulative source-work limits;
those limits are not whole-operation admission or public activation.

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

Source `.32` adds the sixth, constant pending-trust role; all seventeen pinned
DDL revision checks now match `.32`. The full evidence-bound candidate emits
those declarations alongside exact-primary credential, assertion, high-water
and audit queries, plus a staged published-bundle lookup. Query closure and shared audit-capacity
composition accept only the two explicit query kinds, retain the original
business/framework ceilings, and reject duplicate identities. The planner
rebinds all six roles to its actual arguments and supplied database time, then
uses the returned owned snapshots. Cheap tuple/count checks precede processing.

Without the exact private collector, the reader rejects a complete declaration
anywhere in the inventory before starting its loop. Public v3 supplies no such
collector: even a complete query after ordinary exact queries cannot cause those
earlier business/proof reads. The private branch uses real range reconstruction,
not a `LIMIT + 1` completeness substitute. There is no constructed successful
receipt or registry activation.

Query-read bookkeeping can snapshot, retain and compare the distinct closed
declaration without synthesizing legacy primary-key ordering. These six
roles have no deferred selected-row references. Empty observations remain empty,
not invented absent primary addresses. Retained records still do not establish
predicate satisfaction, index membership, completeness, currentness or intent
admission; real proof reconstruction and source rebinding are separate duties.

## Shared cutoff-native source recipe

The actual candidate in
[`authority_transition_webauthn.py`](../serverware/authority_transition_webauthn.py)
now exposes `cascade_queries_at_cutoff` and
`WebAuthnCredentialRevokeKernel.queries_with_evidence_at_cutoff`. The existing
datetime entry points delegate through the same source recipe after exact
microsecond conversion. There is no second, independently handwritten query
program for a future proof consumer to keep in sync.

The full business recipe validates its arguments once and retains the existing
assertion-query, business-row/work and source-closure checks. In order it emits
the target credential, all five complete roles, one exact audit query per
control-plane approval hint and optional credential audit, an assertion
credential query only when the signer differs from the target, and the
assertion challenge, the fixed trust high-water lookup, the publication lookup
resolved from that proved row, and the constant pending-publication range.
The lower cascade-only helper still emits five cascade roles. The full
evidence-bound recipe requires all six. The common framework separately calls the genuine
`add_capacity_query` to append its exact global counter query last. This is at
most 45 declarations including the framework query; the original operation
bounds still decide whether a concrete program is admitted.

The native-cutoff entry point uses the same signed-int64 selector domain as the
complete declaration. It reads no clock and does not infer a datetime from a
floating-point timestamp. Supplied cutoff, request digest, arguments and
assertion identities remain input claims, not authenticated time or intent.
When there are no audit subjects, this legacy recipe does not consume or
validate the request digest. The future operation admission must validate and
bind it even in that case; successful query generation is not sufficient.
The lower cascade helper retains its existing prepared-values precondition;
callers needing the full business validation must use the full recipe.

The public cutoff-native APIs remain unmetered. A separate private
[measured generator](authority-revocation-query-work.md) now charges the genuine
source workers and is called by the unexecuted
[mixed proof composer](authority-revocation-read-write.md). A full recipe
followed by the actual capacity composition performs 24 profile hashes plus two hashes per
audit subject. Argument canonicalization, business-intent normalization and
JSON decoding, copies, comparisons, profile descriptor encodings and audit-ID
encodings are additional real work. A composer must charge those
passes as well as [measured observation validation](authority-query-read-accounting.md)
against its one remaining budget; neither the hash formula nor independently
successful generation supplies that composition.

Every consumer must own all inputs before generating this program, compare
every ordered observation with the generated declaration, enforce full-key
binding for present and absent point reads, require the single published-bundle
selection to satisfy its genuinely resolved predicates, and compare complete observations
with the genuine joined-leaf order. Empty roles cannot be omitted and an extra
source-shaped ordinary query cannot substitute for an actual source query.
This shared recipe does not activate that consumer, the planner or a kernel.

## Remaining implementation and verification

The [storage integration contract](authority-index-storage-integration.md)
records fixed storage/hash/projection admission and source all-writer maintenance.
The private acquisition path now joins the real readers and proof engines;
installed execution, authenticated bidirectional initial population and
coordinated retained evidence remain unestablished.
Independent root pairs, trusted time, witness/fence authority and receipt
reconciliation remain required.

Registration's conditional first-enrollment history and trust staging's replay,
generation and aggregate-withdrawal semantics need their own source roles and
reviewed whole-operation contracts. They are not enabled by borrowing these
revocation declarations. All four WebAuthn startup gaps remain visible.
Versioned closed query evidence and coordinated Python/SQL consumers are also
missing: the exactly nine-frame Snapshot/v3 is unchanged.

The original declaration slice's twenty methods cover the actual binder,
independent profile and interval encodings, source/handler commitments, immutable snapshots, mixed
closure/capacity and retained observations; one of those methods is supplemental
planner source inspection. All twenty existing candidate method identities are
preserved, with its query-selection assertions updated for the new type. These
tests are authored but unrun. No database, service or production verification is
claimed by this source checkpoint.

The separate
[`test_authority_revocation_query_program.py`](../scripts/test_authority_revocation_query_program.py)
adds 18 authored, unexecuted methods for the shared recipe. Independent query
documents, audit identities and framework-key derivation check bytes and order;
real call observations cover one argument-validation pass and actual hash work.
Other cases cover signer overlap, empty roles, hint and aggregate bounds, exact
datetime/int64 cutoffs and the explicitly limited authority of supplied inputs.
No existing method identity, native-suite count or verification prerequisite is
changed by this refactor.
