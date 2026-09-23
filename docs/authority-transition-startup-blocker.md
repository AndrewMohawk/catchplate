# Authority transition startup blocker

Status: unresolved implementation gap; control-plane startup remains blocked.
The frozen `f16da11` source-root run of `scripts/test_control_plane_startup.py`
failed while importing `authority_transition_registry`, before service startup.
The diagnostic-only change described here does not make that runtime healthy.

`authority_contract.OPERATION_REGISTRY` declares four typed pure transitions
that have no kernels in the policy, quota, or release registries:

- `webauthn.trust.stage`
- `webauthn.trust.complete`
- `webauthn.registration.finalize`
- `webauthn.credential.revoke`

Their argument and evidence field sets are already reserved in
`serverware/authority_transition_policy.py`, but no complete implementations are
registered. An unregistered explicit self-revocation candidate now exists in
`serverware/authority_transition_webauthn.py`; its deliberately limited source
boundary and outstanding activation requirements are documented in
[webauthn-revocation-candidate.md](webauthn-revocation-candidate.md). It is not a
repair of the legacy aggregate endpoint or any of the other three operations.
The registry now names missing kernels, unexpected
kernels, overlapping registries, and mismatched identity or planning fields.
All prior closure conditions remain enforced. No operation was removed from
the contract, marked disabled, given a placeholder kernel, or delegated back to
legacy mutation code. Changing the database backend cannot repair this
unconditional import-time failure.

The coordinated implementation direction is documented in
[WebAuthn authority integration](webauthn-authority-integration.md), including
aggregate staging, authenticated predicate/capacity proofs, independent roots
and time, and non-circular evidence production. It does not change the current
contract or waive any startup gate.

The [explicit-context attestation core](webauthn-attestation-core.md) prepares
shared registration cryptography for an eventual measured evidence producer.
It does not itself produce signed authority evidence or fill a missing kernel.

## Implementation contracts still needed

The following bounds are the existing contract, not permission to truncate a
larger mutation or omit dependent rows. If complete evidence cannot fit the
declared bound, admission must fail closed. Changing these bounds or the
transaction composition requires an explicit contract design and review.

| Operation | Existing row / mutation / work bounds | Missing typed inputs and preserved behavior |
| --- | --- | --- |
| `webauthn.trust.stage` | 4 / 1 / 64 | Exact bundle, predecessor, sequence, rollback epoch, signer, actor, withdrawal IDs, and audit event. Preserve digest-reuse checks, single pending publication, monotonicity, and publication/withdrawal atomicity. |
| `webauthn.trust.complete` | 4 / 4 / 128 | `publication_id` plus `verification_evidence_digest`. Bind a durably verified signed publication receipt to the stored bundle and signer; consume it atomically with publication, witness/high-water advancement, and the audit record. |
| `webauthn.registration.finalize` | 112 / 40 / 1024 | In addition to legacy registration arguments: `challenge_id`, `attestation_evidence_digest`, `oidc_session_id`, `sibling_challenge_ids`. Bind fresh registration attestation and trust generation, exact unexpired unused challenge, user and label; preserve credential-ID non-reuse, pending OIDC session authorization, zero historical credentials for first enrollment, sibling invalidation, and audit. |
| `webauthn.credential.revoke` | 192 / 136 / 2048 | In addition to legacy revocation arguments: `approval_grant_ids`, `control_plane_approval_ids`, `oidc_session_ids`, `registration_challenge_ids`. Preserve the bound verified assertion and atomic credential/session/grant/approval revocation, explicit-source global live-registration invalidation, and per-approval audit events. |

Exact implementation references:

- `serverware/authority_contract.py`: four operation declarations; proof
  primitives, evidence types, relation permissions, and bounds are authoritative.
- `serverware/authority_transition_policy.py`:
  `_WEBAUTHN_TRUST_STAGE_FIELDS`, `_WEBAUTHN_TRUST_COMPLETE_FIELDS`,
  `_WEBAUTHN_TRUST_VERIFICATION_FIELDS`,
  `_WEBAUTHN_REGISTRATION_FINALIZE_FIELDS`,
  `_WEBAUTHN_REGISTRATION_VERIFICATION_FIELDS`, `_WEBAUTHN_REVOKE_FIELDS`,
  `_WEBAUTHN_EXACT_CASCADE_MAX`, and `_KERNEL_VALUES`.
- `serverware/db.py`: `stage_webauthn_trust_publication`,
  `complete_webauthn_trust_publication`, `finalize_webauthn_registration`,
  `revoke_webauthn_credential`, and
  `_invalidate_live_webauthn_registration_challenges` document legacy behavior.
  They are not implementations of the typed authority protocol.

## Why registering the legacy functions is not a repair

`authority_store/authority_dispatch.py` binds the original database handler
signature, rejects injected `_connection` and other internal arguments, and
marshals the remaining arguments. `authority_service._synthesize_business_arguments`
adds `businessIntent`; it does not discover challenge IDs, cascade rows, or
produce verification receipts. Merely adding kernel objects would leave these
new inputs absent, or incorrectly trust caller-selected subsets.

The trust-publication API currently performs dependent credential withdrawals,
global live-registration challenge invalidation, and publication staging inside
one `db.connect()` transaction in `app.py:webauthn_trust_publish`. Its staging
handler requires `_connection`; the controlled-writer wrapper rejects that
argument. The stage contract permits only a publication-row mutation, not all
those dependent withdrawals. A reviewed admission/transaction design must
preserve the aggregate atomicity; it cannot be replaced with independent
commits to get past startup.

The legacy completion handler takes only a publication ID.
`webauthn_trust.reconcile_trust_publications` verifies and installs the bundle
locally, then passes that ID. It does not create the typed
`webauthn-trust-publication-verification/v1` receipt. Likewise, the reserved
registration contract requires a `webauthn-registration-attestation/v1`
receipt; no operation-specific producer or admission adapter for that type is
present in the reviewed source. Local verification results and caller-supplied
JSON must not be promoted into signed external evidence.

The existing `authority_transition_core.KernelContext` receipt machinery
validates evidence type, binding, canonical statement and signature digests,
verifier identity/measurement/attestation, current source revision, validity
window, and one-time consumption state. New producers and kernels must agree
on the complete authenticated binding and use those checks. The unused field
sets alone do not establish a producer protocol.

For finalization and revocation, legacy SQL derives complete sets inside a
transaction. New bounded queries need ordered exact-page/completeness proofs,
not only existence checks for a caller-provided list. In particular, revocation
invalidates all live registration challenges for `source="explicit"`, not
merely those for the revoked credential's user. It also emits one audit record
per invalidated control-plane approval. The existing 32-item cascade hint and
136-mutation contract must be reconciled with those audit costs; silent
truncation or dropping audits is not acceptable.

## Locked trust projection repair

The v9 executor's trust query previously referenced publication columns that
exist only in the high-water table. The shared
`authority_store/webauthn_trust_sql.py` projection joins one published row to its
locked high-water record by rollback epoch, sequence, bundle/publication digest
and payload/metadata digest. Witness and revocation fields come from that same
high-water row and remain inputs to the existing signed-evidence digest check.
High-water-first locking and both row locks are retained.

`scripts/test_webauthn_trust_projection_postgres.py` executes that exact block
against the actual two table declarations in a disposable PostgreSQL database.
The prepared external runner owns engine startup/shutdown; the script accepts
only a local Unix socket and creates/drops one random test schema. It checks
projection, missing/mismatched rows, cross-row mixing and lock contention. This
is not a full v9 dispatcher/planner/witness/executor or migration test, nor proof
of independently authenticated database state.

The rendered query remains part of the exact installed-function definition
checked by the schema manifest. Existing v9 databases with the old function
definition remain fail-closed and require a separately reviewed repair contract;
the code change does not authorize silently replacing their functions. It also
does not supply any missing kernel or remove the startup blocker.

## Authenticated storage prerequisites

### Persisted PostgreSQL trigger modes

Both per-table and schema-wide structural trigger inventories commit the exact
`pg_trigger.tgenabled` code as `enabledMode`. `O`, `A`, `R`, and `D` remain
distinct; missing or unknown codes are rejected, never defaulted. Source-created
ordinary triggers use `O`, so all other modes differ from that exact expected
manifest even when their definitions are unchanged. SQLite inventories are
unchanged. Existing v9 manifest records lacking this field require a separately
reviewed repair contract; there is no automatic rewrite or startup bypass.

`scripts/test_postgres_trigger_manifest.py` exercises the same native catalog
readers and production definition normalization in an externally prepared,
disposable Unix-socket cluster. It checks mode-only drift, unchanged definitions,
namespace isolation, ordinary enablement restoration and legacy/malformed mode
controls. This is component coverage, not full schema admission or startup.
Stored mode `O` alone does not prove firing under another
`session_replication_role`, independent database authority, or predicate
completeness; those enforcement requirements remain separate.

Source review identified additional prerequisites below the missing kernels.
These are separate from provisioning the production services:

- Business-row identity and authenticated-tree addressing use different digest
  domains. `db.py`'s `serverware_policy_authority_authenticated_apply` stores
  leaves under `serverware.policyAuthorityAuthenticatedKey/v1`; transport and
  mutation plans identify rows with `serverware.policyAuthorityBusinessKey/v1`.
  Proof production and reconstruction must derive the former from the exact
  table/key while preserving the latter in the closed transport schema. They
  cannot use the business digest as a database leaf lookup or radix path.
  The SQL tree additionally length-prefixes the digest domain; the business
  transport prefixes the domain followed by a NUL byte. Empty, key, row, leaf
  and node hashes must match the SQL framing exactly without silently changing
  persisted roots or the transport protocol.
- The narrow tree-proof repair supports losslessly decoded strings, integers,
  booleans, null, lists and objects, with UTF-8 tree serialization; it rejects
  floats and decimal values instead of approximating PostgreSQL numeric scale.
  The SQL business-address and whole-plan serialization contract still needs
  reconciliation with ASCII-escaped Python transport for non-ASCII values.
  Tree-only Unicode fixtures do not prove end-to-end executor compatibility.
- `BoundedQuery.exact_page` is not enforced by the current SQL reader.
  `KernelContext.exact_page_receipt` checks receipt structure and digests, but
  does not reconstruct a predicate/range root from its `proofNodes`. There is
  no complete, maintained secondary-index producer/consumer path. A receipt
  with internally consistent hashes is not proof that matching rows were not
  omitted. The candidate remains unregistered for this reason.
- The planner reads root revisions and digests from PostgreSQL; the executor
  locks and compares those database roots. This establishes a same-database
  compare-and-swap boundary, not an independently retained current-root
  checkpoint against malicious database rollback or substitution. The current
  external witness binds operation, request, capability, result and generation,
  but does not advance the executor's before/after root set or commit receipt.
  An authenticated root transition and independent monotonic checkpoint must
  be integrated before claiming that stronger database threat boundary.
- Each current single-row proof costs 65 recorded tree reads, in addition to
  manifest, root and business reads. The 4096-entry planner trace cap can
  therefore reject a cascade below its declared 192-row maximum. Shared proof
  and trace budgeting must be reconciled before treating that maximum as
  executable capacity; raising a bound alone does not solve completeness.

Focused proof tests must distinguish an independent expected-root pin from a
root supplied by the same database. Neither an in-memory tree fixture nor a
passing PostgreSQL transaction test establishes the independent witness
property. Keep those evidence scopes separate during subsequent integration.

## Verification after implementation preparation and freeze

Run these sequentially using the prepared Python runtime; do not build from
either test:

1. `python3 scripts/test_authority_transition_registry.py` checks the guard with
   synthetic metadata only: the exact partition, missing/extra/overlapping
   entries, operation/handler/program identity, strict boolean empty-mutation
   policy, and challenge/disabled planning modes. It cannot prove real kernel
   availability or execution.
2. `python3 scripts/test_control_plane_startup.py` remains the source-root
   integration gate. With only this diagnostic change it is expected to fail,
   now naming the four missing kernels. That failure must remain visible.
3. Before treating eventual kernel implementations as complete, add operation
   fixtures for success, idempotent replay, conflicting replay, stale trust and
   predecessor, expired/consumed/wrong-binding evidence, duplicate credential
   history, expired or cross-user OIDC authorization, omitted cascade rows,
   overflow, concurrent row changes, exact audit counts, and full rollback on
   any failed dependency. Then prove the real dispatcher/producer/planner/
   witness/executor path, not just isolated kernel output.

The diagnostic and its unit fixtures do not authorize production authority
deployment, relax the custody boundary, or establish development proxy health.
