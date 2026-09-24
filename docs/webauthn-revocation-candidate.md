# Unactivated bounded self-revocation candidate

Status: partial source implementation, not registered or activated, not an
available API. All four missing-kernel closure failures remain intentional.
This work does not repair control-plane startup, the legacy revoke endpoint,
trust publication, or production authority acceptance.

## Implemented source boundary

`authority_transition_webauthn.py` contains deterministic cascade planning and
an unregistered `WebAuthnCredentialRevokeKernel`. Its standalone semantic input
accepts only `source="explicit"` and an actor who owns the revoked credential.
An independently verified assertion must belong to that same actor. Signing
with the revoked credential merges its counter update and revocation into one
full-row CAS mutation; a different credential belonging to the actor is also
supported. Admin revocation of another user, trust-root withdrawal, offline
last-key decommission, and the existing two-person aggregate route are not
admitted by this candidate. They require their own complete authority contract.

Signed sorted address lists, at most 32 each, are hints. Fixed index roles declare
all live credential-bound OIDC sessions (`pending_webauthn` and `active`), active
grants, approved control-plane approvals, and **all users'** live registration
challenges. The two session roles retain one combined 32-address ceiling.
The [distinct complete-query contract](authority-complete-query-contract.md)
binds selectors to source intent/time, but the reader rejects these declarations
until actual proof acquisition is available. Exact set comparison in the pure
candidate rejects missing, extra, duplicate or stale
hints. Every invalidated approval emits its own audit; the credential audit is
emitted only when `audit_event` was supplied, matching the legacy distinction.
Every audit key is deterministic and requires an absent row. A used key or
already-revoked credential is denied; transport replay belongs to the existing
execution-envelope machinery, not a new business replay that rewrites audits.

The business limits remain 192 query rows, 136 mutations and 2048 work units.
The common planner separately reserves one global counter row/mutation and two
framework work units: total ceilings are 193 / 137 / 2050, not extra business
allowance. The candidate conservatively reserves both assertion CAS writes even
when they merge. No partial mutation plan is returned on overflow or a dependency
failure. Per-list limits are not substituted for the total mutation limit.

Audit capacity uses the [shared global accounting contract](authority-global-audit-capacity-design.md).
The candidate no longer scans pending/claimed outbox populations or counts
selected outbox rows locally. Its only outbox queries are exact planned audit
identities. `add_capacity_query` appends the source-owned global counter query;
`finalize_capacity` validates the initialized compact row and derives one counter
CAS from the complete actual outbox mutations before root derivation. The kernel
never supplies that counter mutation or spends its framework budget. This also
fixes the candidate's old query sizing, which consumed the new 193-row total
before the framework could reserve its own row.

Every invalidated approval still charges one fresh pending audit, plus the
optional credential audit. A no-audit cascade still requires the valid selected
counter baseline, but emits no counter write and may proceed at capacity.
Missing, malformed or inconsistent counters fail closed; no zero bootstrap or
local COUNT substitutes for them. The full outbox no longer needs to fit the
candidate's business row budget. This does not establish independently admitted
initialization, maintained population correctness, current roots, delivery, or
full legacy feature equivalence. Those prerequisites remain mandatory.

`authority_webauthn_assertion.py` authenticates the verifier's exact receipt with
an independently configured Ed25519 public key and independently configured
verifier identity. It validates operation/request/capability, raw-byte digests,
counter, ceremony, identity, and lifetime before returning an immutable evidence
snapshot. Planner/service wiring verifies it before database reads or persisted
plan replay. The verified snapshot is passed separately from business arguments;
caller-supplied counters, CAS state, receipts or business intent are not accepted.
This proves a pinned verifier receipt, not physical-authenticator provenance.
Existing executor trust-generation, full-row CAS, witness and capability checks
remain unchanged and must still succeed.

The [shared receipt-work seam](authority-assertion-receipt-work.md) adds private
accounting around those actual checks for a future bounded semantic composer.
Its separate one-attempt Ed25519 limit is not a SHA-equivalent allowance, and
it does not make the retained proof or the unregistered kernel authoritative.

`webauthn_revocation_admission.py` defines the exact raw-assertion challenge and
execute client shapes. It does not call the obsolete `transactionResult` /
`queryMultiproofs` client, and does not remove `_connection` from any old caller.
Registry closure and the service's enabled-operation checks prevent activation.

## Why registration is withheld

The ordinary `_read_bounded_transition_rows` path executes bounded SQL
predicates with `ORDER BY` and `LIMIT maximum_rows + 1`; overflow is denied.
It does not enforce `BoundedQuery.exact_page` through a reconstructed range proof.
The candidate no longer uses that page declaration for its complete populations:
it emits the distinct source-bound complete-index type, which the reader
explicitly rejects before business/proof SQL. `_derive_multiproofs` still proves
membership or exact-key absence, not that no matching row was omitted. Neither
an ordinary page flag nor a new declaration alone is a completeness proof.

The source must not convert this assumption into an enabled signed operation.
The next prerequisite is actual producer/consumer integration for the new
primitive, binding each source selector, index ordering, complete terminal range,
source relation root/revision, returned rows and absence/overflow boundary. It
must be maintained by every writer of each indexed relation and verified before
mutation derivation. Existing `KernelContext.exact_page_receipt` describes an
authenticated receipt shape, but does not reconstruct a range root from its
proof nodes. The candidate manifest does not authorize its receipt table, and
no complete bridge is implemented here. Adding that bridge
requires reviewed relation/proof manifests and matching producer, planner and
executor tests; do not fabricate receipts or relax the current registry guard.
An independently retained, monotonic root checkpoint is also required for the
malicious-database threat boundary; the current same-database root comparison
and operation/result witness do not establish it. See
[the storage prerequisites](authority-transition-startup-blocker.md#authenticated-storage-prerequisites).

The small `_exact_empty_page_query` repair removes `page_size=1`, which the
`BoundedQuery` constructor forbids for `ordered-exact-page`. It fixes the shape
contradiction; it does not implement the missing completeness proof.

## Verification after source preparation and freeze

Run the new authorization and transition fixture scripts sequentially in the
prepared runtime. The authorization fixtures exercise real locally generated
Ed25519 verifier signatures; they make no physical-authenticator claim. The
transition fixtures use explicit selected-row/evidence projections to exercise
pure business logic. They now also compose the actual shared query, finalization,
work and validation helpers using independently hashed synthetic compact counter
rows. Exact full-capacity/overflow, one-versus-two audits, no-audit baseline,
missing/malformed/stale-CAS state and business-budget controls do not prove the
counter was authentically initialized or kept current. The tests make no
PostgreSQL, real planner execution or hostile-database proof claim.
Neither fixture replaces registry entries or creates fake successful startup.

Before activation, additionally require authenticated completeness negative
cases (omitted matching rows, false terminal ranges, stale/wrong relation roots,
changed predicates and overflow), real planner/witness/executor integration,
all-or-nothing database rollback and exact audit counts, current trust/counter
CAS races, and durable exact-request replay. The real source-root startup test
must continue failing until all four operation gaps are genuinely resolved.
