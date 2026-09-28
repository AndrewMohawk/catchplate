# Original-only recovery staging admission

`oidc_session_activation_release_recovery_delivery_admission._verify_on_work`
accepts the incoming `server_bootstrap_bytes` and four separate, independently
provisioned originals: `issuer_policy_bytes`, `release_custody_bytes`,
`proof_enrollment_bytes`, and `intent_enrollment_bytes`. Its other mandatory
keywords are the actual `root_public_key`, original `live_window`,
`transport_deadline_ns`, and `work`; optional `_continuity` propagates only
restrictive original epoch/monotonic floors. There is no material/DTO, target,
old token, outcome record, private key, path or client-authorization ingress.

The private immutable result has seven fields: `server_bootstrap_bytes`, actual
`server_material`, actual `issuer_policy_material`, `bootstrap_identity`,
`live_window`, `deadline_ns`, and `live`. No verifier accepts that result as a
replacement for originals. The identity is ASCII71 bytes in the existing client
server-bootstrap identity domain, matching the dedicated recovery staging
transport; it identifies exact bytes and is not permission or worker readiness.

## Independent admission before resource access

The genuine separate recovery-policy verifier first authenticates the root
policy, historical custody and both independent enrollments. Its actual scope
and forbidden-key checks remain authoritative. From those admitted originals,
the receiving code derives the exact directory, delivery identity, custody
digest, checkpoint `{recordCount: 1, outcomeDigest: expectedOutcomeDigest}` and
fresh recovery scope, including caller and delivery-key digest. Nothing is
learned from the candidate's own storage or recovery claims.

The existing server verifier then authenticates the incoming root signature,
historical custody, storage authorization and recovery authorization. Admission
requires RECOVERY, never LIVE/checkpoint zero, and compares exact custody bytes,
launch resources, both scopes, complete expected release, configuration,
database, generation, runtime closure, receiver, producer, caller, completion
receipt and delivery key against the independent policy. The server interval
must be contained in the current policy interval; its nested current root
authorizations are also genuinely admitted by the server verifier.

Historical execution, custody, intent and proof do not become fresh execution
authority. Fresh recovery need not fit an expired historical attestation
interval, but cannot extend the original delivery expiry. Returned policy and
server guards remain attached to the same work/window with only narrower
deadlines. Child continuity calls the upstream lifetime's base, not an
aggregator that calls the child again; no cyclic guard or allowance renewal is
introduced.

## Capacity and evidence limits

Before either admission parses nested originals, known lengths reserve eight
historical-custody byte footprints and four footprints for the server, policy
and enrollment originals, plus both bounded nested planner/vector/enrollment
paths and candidate custody/storage/recovery originals. Per-source caps and the
combined 64 MiB ceiling remain unchanged; larger combinations are refused.
Fixed independent comparison graphs are measured before capture/canonical
comparison, and the actual decoded-original inventory is checked afterward.
The original cumulative work ledger is charged separately. This is conservative
representation accounting, not a Python process-heap guarantee.

The receiver must additionally reserve its already-held cold/prewait material,
resource and wire state before receiving the body. It must genuinely open and
check the independently pinned existing checkpoint-one slot and delivery key
only after this admission, and preserve the original guards through delivery
and startup. This module reads no store, checks no private key bytes, creates
or appends no outcome, and proves neither storage existence nor unchanged
private contents. A later `staged` acknowledgement identifies staged originals;
it is not recovery, successful token exchange, cookie delivery or permission
to retry. Actual historical request/old-token/proof/outcome admission remains
the recovery worker's responsibility. The LIVE admission path is unchanged;
deployment and independent production acceptance remain open.
