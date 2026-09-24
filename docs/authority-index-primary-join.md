# Fixed index projections and primary-proof joins

## Status and claim

This is an unactivated source component. The current source is unbuilt and
unexecuted. It does not install an index, register a WebAuthn transition, or
resolve the [authority startup blocker](authority-transition-startup-blocker.md).
The implementation consists of:

- [`authority_index_projection.py`](../serverware/authority_index_projection.py):
  eleven fixed selectors and row-to-index codecs;
- [`authority_index_join.py`](../serverware/authority_index_join.py): complete
  range reconstruction joined to actual primary-row membership verification;
- [`authority_radix_mutation.py`](../serverware/authority_radix_mutation.py): the
  shared, bounded primary evaluator and its read-only membership entry point.

Given a supplied index/primary root pair, a successful join establishes that
every returned index leaf has one corresponding present primary row, that its
full-row commitment matches, and that the fixed projection of that row produces
exactly that leaf. The index frontier must reconstruct the complete requested
interval under its supplied root, including an empty interval result.

It does **not** establish that the index contains every primary row that should
have been indexed. An incomplete index can still have a self-consistent root.
Independent initial population, all-writer maintenance, and an authenticated
root-pair relationship remain required. Nor does this component establish root
currentness, checkpoint signatures, an admitted clock, operation authorization,
or a transaction's effects. The supplied `IndexPrimaryAnchor` is declared data,
not an independently witnessed checkpoint.

## Closed projection API

`profile_for(index_id)` returns a fresh source-owned `IndexProfile`.
`snapshot_selector(index_id, selector)` returns a new exact dictionary of
validated primitive fields without hashing. `query_interval(index_id, selector)`
derives one half-open interval. Callers cannot supply a profile, predicate,
projection callback, ordering expression, or arbitrary interval to the joined
API.

`project_row(index_id, row, primary_key_digest=..., primary_row_digest=...)`
returns one `IndexLeaf` or `None` for a valid nonmember. It validates all referenced
fields before making the membership decision. Missing or malformed referenced
fields are errors, not an excuse to omit a row. The standalone function checks
the supplied commitments' syntax only; it is not a proof verifier. Other full-row
fields are deliberately left to the actual primary evaluator.

Each profile commits a fixed descriptor, including table, referenced column
types, selector fields, membership rule, partition fields, order codec, interval
rule, numeric bounds, enum values and text/time encoding. An explicit
`projection_manifest_digest()` call hashes the eleven descriptors together.
That digest is not an installed operation manifest or an authorization token.

The eleven source identities and closed selector fields are:

| Index ID | Selector | Population / order |
| --- | --- | --- |
| `webauthn_credential_id` | `credential_id: str` | All credential history, including revoked rows; zero order component |
| `webauthn_credential_user_history` | `user_id: str` | All of that user's credential history; zero order component |
| `webauthn_credential_live_trust` | `{}` | `revoked_at IS NULL` and nonzero `attestation_trusted`; zero order component |
| `webauthn_registration_unused_global` | `expires_after_us: int` | Registration challenges with null `used_at`, strictly after the cutoff; expiry order |
| `webauthn_registration_unused_user` | `user_id: str`, `expires_after_us: int` | Same per user, with no approval-request filter; expiry order |
| `webauthn_session_credential_status` | `credential_record_id: str`, `status: str` | Nonnull credential binding and requested `pending_webauthn` or `active` status; no expiry filter |
| `webauthn_grant_approver_active` | `credential_record_id: str` | Nonnull approver binding and `active` state; no expiry, use-count or reservation filter |
| `webauthn_control_approval_approved` | `credential_record_id: str` | Nonnull approver binding and `approved` status; no expiry filter |
| `webauthn_publication_bundle_digest` | `bundle_digest: str` | Global pending or published publications matching the exact text |
| `webauthn_publication_status` | `status: str` | Global publications with requested `pending` or `published` status |
| `webauthn_publication_generation` | `minimum_rollback_epoch: int`, `minimum_sequence: int` | Global pending or published publications at or above that generation pair, inclusive |

The generation interval does not itself prove that its lower bound is the
accepted predecessor or current maximum. Likewise, a supplied expiry cutoff is
not an authenticated current time. The future operation consumer must bind
those inputs to its own admitted intent and evidence.

The live-trust index selects the complete candidate population, not just rows
whose stored root ID appears in a withdrawal list. Full joined rows still need
the actual credential-trust classifier. Its root ordering, development exception
and AAGUID rules are not replaced by an index predicate. The projection does not
copy private-key contents; the primary full-row commitment still binds them.

## Key, equality and time encoding

Each 160-nibble key has a 64-nibble partition hash, a 32-nibble order component
and a 64-nibble primary-key commitment suffix. The suffix and the leaf's
`primary_key_digest` are the actual **BusinessKey/v1** digest. They are not the
different **AuthenticatedKey/v1** digest used as the persisted primary-tree
path. The leaf's `primary_row_digest` is the actual SQL-framed
**AuthenticatedRow/v1** commitment from the checked primary proof. Projection
does not rehash the row using a different JSON convention.

The partition hash uses `serverware.policyAuthorityIndexPartition/v1`. Every
frame, including the domain, receives an unsigned eight-byte big-endian length.
The remaining frames are the counted-index profile, index ID, table, projection
digest and sorted compact UTF-8 JSON of the fixed typed partition fields.
Descriptor and manifest domains are respectively
`serverware.policyAuthorityIndexProjectionDescriptor/v1` and
`serverware.policyAuthorityIndexProjectionManifest/v1`.

Referenced text fields and selector strings must be exact strings, NUL-free,
valid UTF-8, and at most **4,096 UTF-8 bytes** each. Partition JSON is bounded to
**32,768 bytes** before hashing. There is no Unicode normalization, case folding,
locale-dependent comparison, or equivalence between null and empty text.
`attestation_trusted` is an exact signed 32-bit integer, preserving the source
INTEGER column's nonzero test; a Python boolean is not accepted as an integer.
Publication generation values and cutoff microseconds are exact signed 64-bit
integers. Source-nullable bindings and timestamps retain explicit null handling.

An equality index uses sixteen zero order bytes. An expiry index uses its signed
64-bit microsecond value, biased by `2^63` and encoded as eight big-endian bytes,
followed by eight zero bytes. A generation index concatenates that signed
encoding for rollback epoch and sequence. The resulting order is numerical,
not SQL text collation order. Within equal values, the primary-key digest is the
tie-breaker; it does not preserve legacy ID or creation-time ordering.

Expiry TEXT must have exactly one canonical UTC spelling:
`YYYY-MM-DDTHH:MM:SS+00:00`, or the same with a nonzero six-digit fractional
component before `+00:00`. The parser validates the date and requires exact
`datetime.isoformat()` round-trip equality. It rejects `Z`, alternate offsets,
spaces, shortened fractions and redundant `.000000`. Conversion uses integer
timedelta arithmetic from the Unix epoch, never floating-point timestamps.
The strict-after interval begins at cutoff plus one microsecond. A cutoff of
signed 64-bit maximum produces an empty interval at the partition start.

These are **new admission requirements**. Existing TEXT columns neither enforce
this timestamp spelling nor guarantee the new equality/ordering contract. An
explicit migration must validate existing rows and the future SQL codec under
the admitted schema/collation profile. Oversized or noncanonical legacy values
are rejected here, not silently rewritten, truncated, or claimed equivalent.

## Actual joined verification

`join_index_range` accepts an `IndexPrimaryAnchor`, closed selector, counted
frontier, selected primary rows, original primary proofs and `IndexJoinLimits`.
The anchor names a fixed index ID, index revision/root and matching table's
primary root. Its contexts are freshly revalidated even if a frozen dataclass
constructor was bypassed.

The join derives and reconstructs the complete index interval, then requires
exactly one selected row and primary proof per returned leaf. It invokes
`evaluate_primary_radix_memberships`, which runs the same real evaluator as
primary mutation verification with an empty mutation tuple. The engine creates
one bounded, detached JSON snapshot; the join projects those **same verified
owned rows** and consumes their associated verified proof commitments, not the
caller's original dictionaries. Proof and row tuple order need not match: their
verified business addresses identify the association.

Every member must be present, have null `contractSelector`, and match exactly
one index leaf. The source primary-key columns are fixed, the table is treated
as read-only business state, and the evaluator's after-root must equal the
supplied before-root. Missing, extra, duplicate, absent or differently projected
members reject the whole join. A caller-created successful observation or
membership result cannot substitute for proof inputs.

The returned frozen observation contains the owned root pair, interval, leaves,
context digest and metrics. It does not expose the mutable nested dictionaries
used internally by the membership engine. Its context commitment binds the
fixed projection profile, both supplied root descriptors, index revision and
owned selector using the existing canonical wire/domain-plus-NUL framing. This
is distinct from counted-index length-prefixed tree framing and grants no
authority by itself.

## Combined budgets and remaining integration

`IndexJoinLimits` retains separate primary and range limits, plus hard ceilings
of **1,100,000 charged hashes** and **71,565,312 combined input bytes**. Callers
may tighten these limits. Context wire bytes have a separate 262,144-byte ceiling.
The selected population is clamped to at most 256 and to both component limits;
the global audit-counter framework slot is not additional range capacity.

Before each reconstruction phase, effective hash and byte limits are clamped to
the remaining combined budget. The join reserves all row-projection hash work
before primary verification. The context charge is conservatively **69**:
66 cold empty-root allowance, two source profile hashes and one context hash.
The primary engine retains its own conservative cold allowance; warmed caches
do not discount either charge. Query projection costs at most two hashes and
each row projection at most two. A standalone valid nonmember can return before
hashing, but the join does not refund reserved row work. These charges are not
a claim of exactly that many SHA-256 calls in every execution.

Combined byte metrics add context wire bytes, range scalar-frame bytes and the
primary engine's canonical input bytes. The latter are checked after the bounded
snapshot; this is not an external JSON parser or exact preallocation guarantee.
The component also does not bound a future SQL producer's sort, network transfer,
process memory or deadline by itself.

The joined fixture has 27 authored methods using independent primary/index
trees and commitment encodings; four additional primary-engine methods cover
owned snapshots and context revalidation. They remain unrun and are not native
SQL, schema-admission, checkpoint or transaction evidence. Existing operation
query/mutation/work limits are not expanded by these component budgets. Large
complete populations can still be rejected; no count-only shortcut or pagination
contract is introduced.

Before activation, the implementation still needs the fixed SQL projection and
storage profile, authenticated initial primary/index population, atomic OLD/NEW
maintenance for every writer, retained per-query evidence including empty
queries, root-pair checkpoint/admission and time semantics, and complete bounded
business kernels. The [range design](authority-index-range.md) records the
additional primary-root effect of writing existing secondary-head rows: future
maintenance must predict that effect without applying the head change twice.
No registry entry, source-activation flag, baseline waiver or relaxed startup
guard is supplied by this slice.

The [planner retention and pre-kernel verification](authority-query-read-retention.md)
now preserves query IDs, ordered member addresses and empty observations, and
verifies actual primary membership before invoking an admitted transition. The
[private complete-acquisition path](authority-complete-acquisition.md) now acquires
indexed frontiers and runs genuine joined verification, but its retained-evidence
gate still stops before kernel execution. The typed reader also
[stages primary proofs for deferred sources](authority-query-proof-staging.md)
before dependent SQL; independently admitted roots remain required. Query-local null
`contractSelector` metadata must remain
distinct from legitimate selector metadata on the global selected-row union;
both views must agree on the exact key and full row. The closed transport and
SQL snapshot consumers must commit that evidence under an explicitly versioned
contract, not silently add a frame to the existing nine-frame Snapshot/v3.
The outer 64 MiB plan ceiling still applies across all queries; the larger
combined component byte allowance does not raise it.

The [source-bound complete-query contract](authority-complete-query-contract.md)
now fixes the explicit-revocation candidate's five index roles under a distinct
query kind. Public v3 deliberately retains its pre-SQL rejection despite the
private producer. The [storage integration contract](authority-index-storage-integration.md)
records the source producer and all-writer/head-effect requirements; neither
source wiring nor supplied roots establishes an installed, admitted checkpoint.
