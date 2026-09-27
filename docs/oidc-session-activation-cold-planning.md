# Root-original-bound activation planning

[`authority_oidc_session_activation_cold_planning.py`](../serverware/authority_oidc_session_activation_cold_planning.py)
connects an independently root-authenticated launch snapshot to the actual
[activation plan owner](oidc-session-activation-plan.md). This is source-only,
unbuilt and unexecuted. A signed launch vector is **not** an off-host latest-state
observation, and no root-state service peer or currentness bypass is added.

## Complete-vector projection

`_project_on_work(*, vector_bytes, expected_vector_digest, work)` accepts exact
original bytes, not an alleged validated vector. The real complete-vector
decoder checks canonical encoding, schema/source revision, every source
manifest, the complete primary/counted inventory, projection identities, and
revision/count/empty-root relationships. The actual domain-framed digest must
match the independently supplied pin. The vector has the existing 64 KiB cap.

Only then does the fixed `oidc.session.activate` source contract select its
business and authorization primary roots and the exact sorted thirteen-head
read/write union. Each projected head contains `indexId`, `indexRevision`,
`rootDigest` and `leafCount`. No missing descriptor is filled or inferred.
The ordinary private result retains `vector_bytes`, `vector_digest`,
`business_before_roots`, `authorization_before_roots` and
`expected_counted_heads`; no preparation API accepts this result as authority.

The actual [read/write acquisition](oidc-session-activation-planning.md)
compares its database observations against those independently derived roots
and heads in the same read-only transaction that acquires rows and proofs.
A matching database snapshot does not establish off-host action-time currentness.

## Cold composition

The fixed interface is:

```text
_prepare_on_work(owner, *, bootstrap_bytes, root_public_key,
    assertion_bytes, old_token_bytes,
    expected_user_id, expected_session_id, expected_credential_id,
    expected_credential_record_id, expected_challenge_id,
    live_window, transport_deadline_ns, work)
```

`owner` must be the actual process-bound `OidcSessionActivationPlanOwner`.
Startup constructs its real reader and encrypted journal once; this helper
does not make duplicate owners, copy private keys or accept injected callbacks.
Before the first signature/clock/readiness callback it captures request
selectors, immutable assertion/pending-token/bootstrap originals, the supplied
window, inherited deadline and actual owner configuration identity.

The genuine `oidc_session_activation_planner_bootstrap._verify_on_work` then
authenticates the **original bootstrap again in this invocation**, with the
independently held root key and unchanged processing window/work. No externally
constructed bootstrap material or prior success carrier is accepted.

Its authenticated configuration is joined to the actual owner: reader DSN,
role/TLS/runtime identity, planner identity/SPKI, configuration digest, RP and
origin, authentication/trust policies, plan age/skew and delivery TTL. Actual
held delivery/journal keys are checked against the signed SHA-256 pins, and
the actual journal's directory device/inode/UID/GID, record limit and byte
quota must match the launch. The actual owner performs the private/public
planner key-pair check during genuine plan production.

The complete original vector and digest come only from that authenticated
bootstrap. The request supplies neither roots, keys nor policy. Its subject
selectors and original pending token/assertion still undergo the real row,
fresh-key, trust and RBAC proof replay; selection alone is not permission.

The helper calls the real class `prepare` with the projected expectations.
It returns only the actual token-free `PreparedActivationPlan`: request,
scope and signed-envelope originals plus plan and local journal locators.
The genuine owner performs same-snapshot acquisition, indexed replay,
signing and [encrypted private-original retention](oidc-session-activation-journal.md).
No successful transition carrier is accepted in place of any original.

## Lifetime and remaining boundaries

The request window must fit the original signed launch interval and configured
plan policy. The inherited monotonic deadline can only narrow; the helper
opens no replacement work allowance or live window. Original bootstrap
brackets, sticky epoch/monotonic checks, owner-configuration continuity and
the actual signed plan expiry remain enforced through the final return.
Failure after retention does not prove that no record exists and never grants
automatic retry permission.

The cold owner must retain the actual bootstrap/root-key originals; bootstrap
material also preserves the complete-vector bytes and digest. Projected roots
and encrypted plan storage are not substitutes for those launch originals or
automatic archival of independent historical authority.

Root-provisioned launch authority is local-snapshot authority only. Independent
latest-state/currentness and index-population admission, provisioning and host
isolation, activation reservation/protected execution, completion, token
delivery/recovery and public/portal orchestration remain distinct requirements.
Sampled local clocks and successful cleanup are not watchdog or malicious-host
guarantees. No build, test, database call or runtime verification was performed.
