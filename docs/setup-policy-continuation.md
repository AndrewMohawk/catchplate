# Protected Setup policy continuation — implementation boundary

The required source order is candidate intake, then Setup association. The
measured OAuth Setup profile ends at `credential_activated`, revision 3. Its
four-event observation and OAuth mutation profiles are not widened here.

The existing portal hands a signed candidate to the native generation owner,
collects candidate-bound shadow evidence, executes authority preparation/audit
inclusion/finalization, and then calls legacy Setup row mutations. Generation
claim/publication and the twelve-kind canary intake still used ordinary database
writers at the start of this slice. Those are source dependencies, not external
provisioning requirements. They must receive closed typed controlled-writer
owners before the protected Setup continuation can be called complete.

The intake retains actual signed originals, current pinned key/head/revocation
state, assigned member and runtime attestation, original generation deadlines,
current policy predecessor, immutable replay identities and atomic audit/state
effects. A calculated verification row, HTTP success, or copied receipt digest
is not permission. No generic privileged callback or runtime DML grant replaces
the controlled writer. Partial source checkpoints do not close candidate or
Setup readiness.

The continuation will bind the exact Setup owner/revision/expiry, candidate
artifact and assignment, current credential version and exact reviewed route.
Policy activation uses the existing independently authorized authority flow.
Filesystem publication remains the existing separately approved fixed-path
materializer; a metadata commit cannot stand in for its actual terminal journal
and loader identity. No automatic retry or uncertainty-clearing transition is
introduced.

This scope does not claim proxy readiness, enrollment completion, onboarding
allow/deny canaries, measured JIT verification, independent hardware acceptance
or a final Setup receipt. Those are separate required successor connections.
Ordinary credentialless behavior, configured JIT, older explicit profiles and
the concurrent reconnect implementation remain unchanged. No build, test,
provider action, deployment or runtime acceptance is claimed.

## First finite source slice: controlled generation

The new entrypoint is explicitly `/api/policy/authority/candidates/controlled-generation`:

- `/draft` accepts `policyCandidateIntakeRequest/v1` and the existing closed handoff **data**, reopens actual protected predecessors and compiles the independently signed candidate. Its canonical `argumentsOriginal` string preserves nanosecond integers. It creates no claim or native effect.
- `/options` binds that exact original to a fresh real publisher WebAuthn challenge. `/publish` takes the same string and `policyCandidateProfile` assertion, then invokes the actual cold custody owner. Literal current `policy_publisher`, active OIDC/CSRF, hardware trust, UP and UV are mandatory; an administrator-only override is not accepted by this new caller.
- `/lookup` reads the exact request ID and returns `okForAction: false` and `automaticRetryAllowed: false`. A retained claim without a publication is unresolved; even an absent claim is not permission to repeat an uncertain contact.

The source-selected controlled operations are exactly `policy.candidate.generation-claim` and `policy.candidate.generation-publish`. Claim atomically consumes the actual assertion, writes the fourteen-column `policy_shadow_generation_claims` original and stages audit. Only a definite signed controlled response plus exact SELECT readback allows the retained HTTP owner to make one call to the existing fixed native generation route. The original deadline is passed to its actual HTTP transport; neither a new HTTP request nor custody processing renews it. Native transport errors, lost responses and failed publication intake leave the claim consumed.

Publication rechecks the same claim, actor, configuration, assignment/member/load/native handoff and current active tuple inside the real controlled transaction. It verifies the actual independently admitted native verifier and shadow publication signatures. It commits both verification rows, the existing immutable generation publication, its existing policy transition/outbox and the claim's sole terminal publication digest atomically. It does not advance policy high-water or produce filesystem evidence. Ordinary legacy endpoints remain distinct; the new owner does not fall back to their runtime SQL.

`policyCandidateIntakePolicy` is an explicit purpose block in the existing independently signed authority configuration. Both verifier and planner enforce its control-plane configuration and exact instance/boot/shadow-SPKI/runtime-configuration assignments. Old publication, refresh or Setup admission is not interchangeable. Current key heads and revocations are proved against protected roots; historical receipt time selects an actual historical head from the authenticated complete history, then original signatures and receipts are recomputed. The public key prestates used to address fresh receipt queries are public inputs only: all fields and the complete revocation sequence must equal actual transaction rows.

This first profile has explicit capacity limits: one MiB management original, three MiB controlled arguments, at most thirty seconds total, and at most thirty-two rows in each required complete history/population. Before contact, each outstanding claim accounts for one publication and two verification originals; expiry never releases an uncertain claim's capacity. Publication rechecks actual room in its transaction. This does not grant other intake writers permission to overrun the limit. Complete-root reconstruction refuses overflow or incomplete inventory; it never truncates history, prunes, retires keys or resets replay identities. Capacity lifecycle/scaling remains required work. The source adds the new primary-root/ACL inventory and removes one duplicate `created_transition_digest` declaration in the existing assignment DDL; it does not migrate/backfill existing databases or grant runtime DML.

The dedicated portal section performs the same explicit draft/options/passkey/publish calls and retains only the nonsecret request ID for lookup. It does not invoke legacy Setup `/canary` or `/policy`, does not retry `428` or another failed submission, and does not interpret a publication as canary readiness. The existing legacy portal behavior remains available under its old profile.

Still required after this slice: controlled production intake for the twelve canary evidence kinds (including assignment/load/attestation prerequisites), protected Setup candidate/current-policy association and actual materializer/loader continuation. Those missing producers are source work, not deployment provisioning. Fresh recovery of a native publication lost before controlled persistence also remains separate: this slice offers known stored-outcome inspection only and never repeats the native POST. Independently enrolled authority configuration, original trust material, native custody and actual runtime acceptance remain external gates; none was provisioned or exercised here.
