# Preserved workspace adoption into protected authority

Status: source architecture and implementation plan, reviewed at
`c23b63f813cecc56c1c0996c77f72d60fef96626`. This document is not a migration,
deployment receipt, current authority admission, or end-to-end acceptance result.
No live state or private configuration was read for this review.

## Product outcome and invariants

Keep the same workspace, UI and public hostname, with Credentials, Clients,
Permissions, Approvals, Proxy and Notifications backed by their actual owners.
The useful workspace must not remain exclusive to the development profile.

- Do not broaden `operator_demo.activate()`, disable a guard, or treat a profile
  flag as native authority. Preserve the existing development boundary.
- Protected metadata, grants and their atomic transitions belong to the same
  PostgreSQL authority; metadata/audit backend admission must remain coherent.
  A separate approval database attached to unrelated catalog/policy state is not
  adoption.
- Preserve resource identities, client bindings, policy ancestry, audit history,
  keys and custody. Do not reset state or require users to recreate credentials.
- Preserve the distinction between ordinary host-trusted history and newly
  admitted protected authority. Copying or signing a digest of old records does
  not make their original events native, measured or independently witnessed.
- A visible record, prepared candidate, successful database commit or loaded
  policy is not by itself proof that the requested protected action works.

## Existing owners and integration blockers

The [completion review](project-completion.md) identifies the topology gap.
These are source-backed blockers, not missing configuration values:

| Area | Existing owner and boundary | Required integration |
| --- | --- | --- |
| Startup | `operator_demo_runner.main` / `operator_demo.activate` require SQLite, development quotes and atomic release disabled; authority/native/OIDC settings are refused. `control_plane_runner.main` already admits actual cold custody and other protected owners before importing the app. | An independently admitted workspace owner using the existing cold-start path; leave development admission unchanged. |
| UI/API | `app._portal_document` and `operator_catalog_api._profile` select the useful workspace only through `operator_demo.active()`. | Reuse the same workspace with capabilities derived from actual admitted owners and resource state. |
| Catalog | `operator_demo_store._require`, `operator_catalog_schema.active/initialize` and `operator_catalog_mutations._mutate` depend on the development owner, SQLite discovery, publication-file locking and `BEGIN IMMEDIATE`. | Explicit PostgreSQL catalog schema/transaction ownership; separate descriptive metadata changes from authority-changing operations. Preserve revision/hash compare-and-swap and uncertain outcomes. |
| Policy | `operator_catalog_policy.render` reuses the development renderer/settings. `publish` signs locally and updates `operator_demo_policy`; `operator_demo_store.materialize` exports after commit. | Make rendering deterministic from admitted inputs, then connect protected candidate/approval/finalization owners. Reuse `control_plane_policy_file_publication` and `CurrentPolicyAuthority` for the authorized file effect. |
| Approval storage | `db._require_postgres_jit_authority` requires grants on the exact metadata DSN. `db.init_db` refuses mixed metadata/audit backends. Approval, grant, policy-head and audit authority tables are not ordinary runtime-writable tables. | Shared authoritative state and genuine external writer dispatch; never grant the app broad direct writes. |
| Static credentials | `control_plane_static_credential` accepts native-sealed onboarding, not portal plaintext. The protected page requires an OIDC session and the selected owner. | Route protected creation, adoption and rotation through actual custody/approval owners; do not reuse ordinary secret forms as a bypass. |
| Providers | `db._operator_github_app_transaction` and `_operator_aws_transaction` explicitly reject PostgreSQL. `operator_github_app.require_runtime` requires the development profile. Google `operator_provider_custody` uses `DevelopmentOwner` and SQLite transactions; managed Google/X admission and lifecycle consumers also depend on this profile. | Provider-specific owner adapters and preservation contracts for GitHub App/PAT, npm/API keys, AWS, Google OAuth and X OAuth. A generic SQL placeholder conversion does not supply these owners. |
| Notifications | `operator_notification_store.enabled` requires SQLite, development quotes, atomic disabled and no enrolled OAuth application owner. Its source snapshots and writer are SQLite-specific. | Protected source/outbox/custody adapters, preserving four independent destinations, revisions, delivery attempts and uncertainty. Receiver acknowledgement must never become approval. |

The existing [ordinary contract migration](operator-authority-contract-migration.md)
changes a specific SQLite contract cell; it explicitly excludes PostgreSQL and
native authority adoption. `scripts/bootstrap_metadata_store.py` is an explicit
offline PostgreSQL bootstrap, not a retained-workspace importer or runtime
fallback. Neither closes this gap.

Compatibility names such as `operator_demo_policy`, existing resource IDs and
API paths need not be renamed to fix their ownership. Avoid cosmetic identity
changes during the authority transition.

## Incremental adoption is possible, but is not implemented

There is no need to force every retained credential into native custody in one
operation. Separate **record preservation**, **resource adoption** and **active
dispatch authority**:

1. Preserve the complete stopped-consistent source and its custody roots. Import
   or expose an explicitly read-only historical projection in the same workspace,
   including ordinary resource records and their original assurance. This does
   not activate those records under protected authority.
2. Adopt a bounded resource graph at a time: credential identity/generation,
   client identity, permission, policy transition and required provider custody.
   The target must bind the exact source record/version and the actual target
   owner. A credential need not change identity merely because custody changes.
3. Move that graph to protected dispatch only after its real owners, policy and
   request path have passed acceptance. Unadopted records remain visible with
   their accurate ordinary/historical state; visibility grants no dispatch.

Historical rows can live in a target archive namespace or an immutable retained
snapshot with a versioned reader. In either design they must never serve as the
protected planner's current policy, credential authority, grant or audit head.
The authoritative target must retain a durable adoption link and reject duplicate,
stale or conflicting adoption. An independent read-only history source is not a
second active approval authority.

Keeping unadopted credentials **actively usable** as ordinary resources after
cutover is a separate compatibility requirement, not a free consequence of
read-only import. It needs explicitly admitted ordinary custody/dispatch owners,
resource-level policy binding, non-overlapping routing and unambiguous audit
provenance. A failed protected request must never fall back to ordinary dispatch.
The source does not currently implement that mixed-owner workspace:
`runtime.atomic_release_authorization_enabled` is process configuration, and
`policy_uses_atomic_release_authorization` detects JIT/shared-quota routes but
does not itself select or validate independent resource custody owners.

Therefore the viable first increment is a unified owner-backed workspace with
accurate read-only history plus explicitly adopted protected resources. It is
**not** the completed product if it strands existing ordinary jobs. Before the
live cutover, either implement and verify the explicit ordinary compatibility
owner for resources that remain active, or finish adopting every active resource
needed by the retained jobs. Do not silently disable those jobs or infer consent
to do so. Do not create simultaneous uncoordinated writers to the same resource.

## Staged implementation and acceptance

1. **Workspace ownership and catalog contract.** Add real capability/read owners,
   the target catalog schema and mutation adapters. Keep existing API authentication,
   same-origin checks and bounded readers. Extract deterministic policy rendering
   without changing existing ordinary signed output. Verify unavailable owners,
   incompatible backends and wrong profiles fail closed before effects.
2. **Preservation and adoption contract.** Implement an explicit offline plan/apply
   path binding source snapshot, source contract, target database identity, target
   schema and exact inventory. Refuse unknown tables/state, incomplete captures,
   conflicting target rows, stale plans and ambiguous partial application. No
   automatic startup migration or retry after an uncertain commit.
3. **Custody and provider adapters.** Preserve original encrypted material as
   historical custody. Where protected use requires rewrapping/import, use a
   genuine authorized custody operation with bound source and target identities;
   never relabel a copied envelope as native-origin material. Cover GitHub App
   renewal/replacement, AWS signing, Google/X consent and refresh/revocation,
   ordinary API keys, and notification destination custody. Missing adapters
   remain visible incomplete capabilities, not generic fallback paths.
4. **Policy and protected request integration.** Adopt policy ancestry through
   the real authority, then materialize committed originals. Complete reachable
   compound `release.reserve`: native admission, atomic parent/child retention,
   authenticated private review, approve/deny/expiry and exact one-use continuation.
   The standalone JIT branch is not a substitute for the real proxy path.
5. **Notifications and ordinary-client compatibility.** Add authoritative action
   events and audit events as separately configurable sources. Verify the saved
   destination/outbox lifecycle and no approval on receiver acknowledgement.
   Exercise retained SDK jobs, token identities, revocations and quotas through
   the selected owner for each resource, including any ordinary compatibility path.
6. **Retained-copy rehearsal and cutover.** Test real stopped-consistent copies,
   repeated startup, interrupted adoption, uncertain outcomes and stale-source
   controls. Compare the conservation inventory below. Only then perform a
   coordinated same-hostname cutover with a public proxy fence and exact readback.
   Retain source backups and failed attempts. Rollback must not replay consumed
   authority, reset quotas or resend uncertain notifications.

Acceptance must include an actual client request becoming pending, authenticated
review of that exact request, separate approve/deny/expire outcomes, one-use
continuation, durable audit, notification delivery and the corresponding negative
controls. Green component tests, health endpoints and policy loading are narrower
evidence and must remain labelled as such.

## Conservation inventory

- Resource IDs, ordering, versions, statuses, revocation tombstones and credential
  generation floors; client token hashes/expiry and principal/permission bindings.
- Provider subjects, GitHub installation/repository bindings, OAuth application
  and account bindings, refresh/revocation uncertainty and configuration versions.
- Policy ID, sequence, rollback epoch, exact previous signed bytes and ancestry;
  do not manufacture a protected high-water mark from an ordinary local record.
- Ordered historical audit events/hashes with their original trust classification;
  new adoption evidence commits their digest without upgrading historical claims.
- Quota charges, replay/nonces, pending and uncertain operation identities; an
  expired or consumed authorization must not become usable through migration.
- CA/key bytes and custody ownership, or an explicitly authorized transfer record
  where the target requires different custody. Preserving client CA trust alone
  is not evidence of protected credential custody.
- Four notification slots, encrypted destination bindings, configuration revisions,
  operation/delivery IDs, cursor continuity and possibly-sent delivery outcomes.

## External prerequisites versus unfinished code

The owner integrations, adoption contract, provider/notification adapters and
preservation tests are implementable code work. They are not blocked merely by
the absence of a new pilot.

Actual protected deployment later needs current genuine authority/custody
configuration, the narrowly privileged PostgreSQL identities and shared-store
configuration, a verified operator OIDC session and required hardware interaction.
Real provider jobs and notifications additionally need privately supplied provider
inputs, consent and destinations. Existing client configuration, historical pilot
material or synthetic test receipts do not prove these prerequisites are current.
