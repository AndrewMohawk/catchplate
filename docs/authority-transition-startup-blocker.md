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
`serverware/authority_transition_policy.py`, but no corresponding classes are
implemented or registered. The registry now names missing kernels, unexpected
kernels, overlapping registries, and mismatched identity or planning fields.
All prior closure conditions remain enforced. No operation was removed from
the contract, marked disabled, given a placeholder kernel, or delegated back to
legacy mutation code. Changing the database backend cannot repair this
unconditional import-time failure.

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
