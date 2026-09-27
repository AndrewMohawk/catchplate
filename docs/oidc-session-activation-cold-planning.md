# Root-original-bound activation planning

[`authority_oidc_session_activation_cold_planning.py`](../serverware/authority_oidc_session_activation_cold_planning.py)
connects independently root-authenticated launch originals and a fresh signed
no-pending head to the actual [activation plan owner](oidc-session-activation-plan.md)
and separate first-ciphertext execution-bundle store.
This is source-only, unbuilt and unexecuted. A launch vector alone is **not** a
latest-state observation; the separate head exchange is mandatory.

## Complete-vector projection

`_project_on_work(*, vector_bytes, expected_vector_digest, work)` accepts exact
original bytes, not an alleged validated vector. It delegates to the fixed
`authority_oidc_session_activation_state` projection. The real complete-vector
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
_prepare_on_work(owner, *, execution_store, bundle_key, bootstrap_bytes, root_public_key,
    assertion_bytes, old_token_bytes,
    expected_user_id, expected_session_id, expected_credential_id,
    expected_credential_record_id, expected_challenge_id,
    live_window, transport_deadline_ns, work)
```

`owner` must be the actual process-bound `OidcSessionActivationPlanOwner`.
`execution_store` must be the actual process-bound `ActivationExecutionBundleStore`.
Startup constructs the real reader, encrypted journal and separate store once;
this helper does not make duplicate owners, copy private keys or accept injected
callbacks.
Before the first signature/clock/readiness callback it captures request
selectors, immutable assertion/pending-token/bootstrap originals, the supplied
window, inherited deadline, independent exact 32-byte bundle key and actual owner/store
configuration identities.

The genuine `oidc_session_activation_planner_bootstrap._verify_on_work` then
authenticates the **original bootstrap again in this invocation**, with the
independently held root key and unchanged processing window/work. No externally
constructed bootstrap material or prior success carrier is accepted.

Its authenticated configuration is joined to the actual owner: reader DSN,
role/TLS/runtime identity, planner identity/SPKI, configuration digest, RP and
origin, authentication/trust policies, plan age/skew and delivery TTL. Actual
held delivery/journal/bundle keys are checked against the signed SHA-256 pins
and must differ pairwise. The actual journal and execution store's directory
device/inode/UID/GID, record limit and byte quota must each match the launch;
their directories must be distinct. No response supplies a store or key pin.
The actual owner performs the private/public planner key-pair check during
genuine plan production.

The owner's mandatory 21-field configuration also retains the exact enrolled
state original, independent state root key and complete-vector original. These
must match this invocation's genuine v3 bootstrap admission. The added signed
bundle-key/store scope is mandatory; no v1/v2 bootstrap, material object or
18-field owner is a fallback.

The complete original vector and digest come only from that authenticated
bootstrap. The request supplies neither roots, keys nor policy. Its subject
selectors and original pending token/assertion still undergo the real row,
fresh-key, trust and RBAC proof replay; selection alone is not permission.

Before planning, the helper constructs the same exact fifteen-field subject,
policy and deadline scope as the owner. A domain-framed context binds that scope,
original assertion, pending token and complete vector. A charged callback obtains
a new 32-byte random challenge; the fixed query also binds the actual enrollment
identity and expected vector digest. One exchange with the root-pinned state
endpoint uses the inherited monotonic deadline, peer admission, half-close and
exact EOF; query and observation caps are 4 KiB and 8 KiB.

The actual [head verifier](authority-current-root-head.md) authenticates the
original state signature and query joins. Activation admission additionally
requires the exact vector, live original interval and null pending request/
decision pair. No response field supplies an independent expected head or vector.
State v4 grants planner UID 65507 only this head-observation operation, not reserve,
completion or historical lookup. Access to the state socket still needs separately
provisioned DAC/ACL permission.

The helper calls the real class `prepare` with the projected expectations and
unchanged `head_query_bytes`/`head_observation_bytes` originals.
That call produces the actual `PreparedActivationPlan`: token-free request,
scope and signed-envelope originals plus plan and local journal locators. The
genuine owner performs same-snapshot acquisition, indexed replay,
signing and [encrypted private-original retention](oidc-session-activation-journal.md),
including the enrolled state/vector/query/observation originals. Producer and
retained-original verification repeat genuine head admission.
No successful transition carrier is accepted in place of any original.

The helper then invokes the actual
[private execution export](oidc-session-activation-execution-export.md) with
the same originals, independently projected roots/heads and bound journal
digest. Under the real owner lock, export verifies the known plan before reading
the journal, genuinely replays bound original bytes, and reads the separate
store before considering a new randomized candidate. Existing first ciphertext
is genuinely reopened and joined to the exact retained originals; otherwise
the new bundle is sealed and appended with no replacement. Only after durable
retention and final checks against the unchanged original expiry does the
cold helper return `PreparedActivationExport` with fields `plan` (the actual
`PreparedActivationPlan`), `encrypted_originals_bytes` (exact ciphertext) and
`expires_at_epoch_ns` (genuine original expiry). This is ordinary private
same-call output; no receiving API admits the result object as proof.

The service sends the unchanged request/scope/plan originals and locators plus
only the ciphertext bundle in its fixed raw7 response. Plaintext journal bytes,
old/new tokens and keys never become a response body. The
[wire guide](oidc-session-activation-planner-service.md) specifies the distinct
v2 framing and unchanged 64 MiB whole-exchange bound.

## Lifetime and remaining boundaries

The request window must fit the original signed launch interval and configured
plan policy. The inherited monotonic deadline can only narrow; the helper
opens no replacement work allowance or live window. Original bootstrap
brackets, sticky epoch/monotonic checks, owner-configuration continuity and
the actual signed plan expiry remain enforced through the final return. The
plan expiry cannot exceed the original observation expiry, which is rechecked
after durable retention; neither a query nor a signature renews the window.
The service also clips its send deadline to the actual result's original expiry.
Failure after either retention does not prove that no record exists and never
grants automatic retry permission. Original plans are not retimed when storage
recovers across a cold start.

The cold owner must retain the actual bootstrap/root-key originals; bootstrap
material also preserves complete-vector and state-enrollment bytes and digests.
Projected roots and encrypted plan storage are not substitutes for those launch originals or
automatic archival of independent historical authority.

The fresh signed head is a bounded sampled observation, not a linearizable
reservation, malicious-host rollback defense or action-time execution guarantee.
Actual database proof acquisition must still match the independent complete
vector. Store recovery preserves exact ciphertext, but no public or automatic
lost-response recovery/retry endpoint exists. Generic execution remains closed,
and independently admitted receiving execution custody is still unfinished.
Provisioning and host isolation, activation reservation/protected execution,
completion, token delivery/recovery and public/portal orchestration remain distinct requirements.
Sampled local clocks and successful cleanup are not watchdog or malicious-host
guarantees. No build, test, database call or runtime verification was performed.
