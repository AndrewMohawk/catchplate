# Google account integration into the operator workspace

## Status and objective

Design checkpoint against workspace commit `10879772`; not implemented or
deployed. Read with `operator-workspace-requirements.md` and the OAuth onboarding
section of `goal.md`. R96 remains terminal: no restart, new enrollment, provider
contact, configuration change or native authority is authorized by this plan.

The journey is connect Google once, choose an application, allow its operations,
then use the ordinary proxy client. Serverware refreshes access automatically.
Applications never receive provider tokens. Account consent, application-token
rotation and access-rule publication remain separate operations.

## Explicit development boundary

Add an opt-in `operator-google-v1` capability to the operator-development profile,
not a blanket removal of the `SERVERWARE_GOOGLE_*` prohibition. Admit only a
configured Google client, private client-secret file, exact HTTPS callback,
fixed provider endpoints, bounded permission presets and pinned API origins.
Persist the client/callback binding; reject silent application changes on restart.
Keep existing static workspaces and their policy bytes unchanged when disabled.

Preserve `oauth_application_owner` selection and `_require_application_lifecycle`
unchanged. A configured enrolled owner cannot fall back to development OAuth.
Native, broker, currentness, policy-aware and controlled release paths retain
their existing ownership, approval, lifetime and execution requirements.
Do not disable configured mutation MFA or two-person activation. Unsupported
protected combinations fail closed before provider contact, not by silently
switching to immediate development activation.

## Implementation slices

1. **Cold profile admission:** `operator_demo.py`, `config.py`, and a focused
   `operator_catalog_oauth_profile.py`. Validate the complete capability and
   file/callback bindings before exposing consent. Admit exact required routes,
   not the entire legacy OAuth mutation namespace. Use existing configuration
   names for the client ID, secret file and redirect URI; no secret chat input.
2. **Consent intent:** add `operator_catalog_oauth.py` and bounded routes in
   `operator_catalog_api.py`. Retain metadata-only actor/provider/permission,
   reviewed catalog and state-digest bindings. No token, authorization code or
   PKCE verifier belongs in catalog metadata. Saving a connection grants no rule.
3. **Existing OAuth lifecycle:** connect existing `oauth.py` and `app.py` start,
   callback and activation paths to that intent. Reuse S256 PKCE, one-use state,
   browser-bound Secure/HttpOnly cookie, verified Google subject and granted
   scopes. Validate intent after state consumption but before exchange. Preserve
   retained issuance/cleanup work, duplicate-account checks and configured MFA.
   Harden state-file durability; current atomic replacement lacks fsync and its
   private-file PKCE verifier must not be described as encrypted storage.
4. **Atomic registration:** retain `db.credentials` as the only token store.
   `db.create_credential(..., _connection=conn)` permits active credential,
   catalog registration, intent completion, revision and audit to commit together.
   For protected pending activation, extract a transaction-owned primitive from
   existing DB activation without removing requester, approval, identity, expiry,
   collision or ownership checks. Join catalog registration to the same commit;
   do not insert an active credential through a generic substitute. Pending
   accounts remain unassignable and cancellation retains existing cleanup.
5. **Catalog and rules:** extend `operator_catalog_schema.py`, mutations and
   policy compilation with a managed-Google variant. Bind immutable verified
   subject, OAuth client ID and canonical scopes; derive current generation and
   expiry from the core credential. Compile `credentialType: oauth2`, exact route
   binding and `Authorization: Bearer` injection from `access_token` only. Reuse
   the Gmail read-only example; optional age restrictions retain the Gmail
   adapter's response evidence. Never accept pasted refresh-token JSON.
6. **Usable UI:** extend operator portal assets with Connect Google, verified
   account/permissions, pending approval and affected applications. Distinguish
   account health, client-token validity and loaded rule activation. Derive
   reauthorization-required from bounded provider evidence, not every 503 or
   timeout. Temporary and uncertain refresh outcomes must remain distinct.

## Generation reconciliation: a separate correctness prerequisite

The current legacy lease path refreshes in `_credential_for_lease`, then checks
the resulting generation against the caller's earlier metadata pin. A changed
generation returns 409 before secret-envelope creation. Rust's
`fetch_scoped_credential_lease_on_deadline` and
`ensure_scoped_credential_lease_on_deadline` propagate the failure rather than
reconcile it. Direct refresh tests therefore do not prove unattended proxy use.
Do not move refresh into the authority-free `generationMetadata` read.

An ordinary or even signed **409 is not retry authority**. Current source:

- `data_plane_credential_leases` durably reserves the recipient nonce before
  refresh; the operator replay cache commits that reservation separately.
- `_claim_credential_lease_release_authorization` may also claim controlled
  issuance before refresh. Error handling audits and rethrows; it does not undo
  nonce reservation or a claim. Other 409 branches occur after encryption.
- The response signature binds method/path/query, status, response body and
  response nonce. It does not independently bind the complete lease request body.

A candidate reconciliation protocol is acceptable only with all these checks:

1. Emit a new closed, versioned **no-secret-envelope-issued-for-this-attempt**
   outcome only at the definite pre-encryption generation-conflict branch.
   Provider refresh may already have committed; this is not a claim that no
   provider request occurred or that no secret was handled internally.
2. Before emission, prove explicit development capability, unchanged active
   policy, exact Google binding, definite current committed generation, no
   controlled dispatch, no request/release authorization, and no issuance claim.
   Exclude native/enrolled/broker/currentness/policy-aware paths entirely.
3. Put the exact lease request-binding digest, policy hash, scope/principal/route/
   credential IDs, binary digest, recipient key/nonce binding and expected
   generation/metadata digest in the signed response body. Strictly verify this
   outcome against the original request and existing trusted response context;
   neither status text nor a client-supplied retry flag is sufficient.
4. Keep the original nonce spent. Never release, reset or prune replay state to
   facilitate retry. Obtain fresh metadata and fresh recipient material/nonces
   for subsequent lease requests. Replay-cache capacity failure remains a failure.
5. Invalidate only the matching stale cache entry without lowering generation
   floors or deleting a concurrently installed newer generation. Do not broadcast
   a request-bound outcome as permission for different single-flight waiters.
6. Permit at most one reconciliation before upstream dispatch. Establish a finite
   absolute operation deadline before the first acquisition; an absent deadline
   is not a valid bound. Preserve it through metadata reread, single-flight waits
   and reacquisition. Recheck policy/application authorization before sending.
7. Never replay an upstream API operation, a controlled claim or an ambiguous
   provider exchange. Missing/malformed signatures, mismatched bindings, timeout,
   interrupted response, post-encryption errors or a second conflict fail closed.

This protocol requires implementation and deterministic evidence; the existing
409 branch alone cannot safely enable it. Keep native behavior unchanged.

## Disconnect and reconnect

Application/rule revocation removes only that application's access. A shared
Google credential must not enter the static credential-delete path. Explicit
disconnect first requires an affected-assignment workflow, then uses the
existing provider-aware pending/failed/retry lifecycle. Google reconnection
remains disconnect then connect again because revocation is grant-wide.
Do not bypass duplicate-account guards; prefer reuse of an already connected
account. Local removal is not forensic erasure or provider-side revocation.

## Verification and remaining user actions

Buildable without real consent: profile refusal tests; HTTPS provider-simulator
consent, browser/state, identity, duplicate-account, pending approval and rollback
tests; actual isolated Rust proxy use after token expiry; concurrent refresh and
generation-race controls; no-envelope proof and negative retry controls; shared
account revocation; restart recovery; and token non-disclosure in UI/logs/leases.
Assert the failed attempt's nonce stays reserved, a fresh nonce succeeds once,
controlled claims are never retried, and an ambiguous outcome sends no retry.

Real Google proof still requires administrator provisioning of the OAuth Web
application, enabled intended API, exact registered HTTPS callback and private
client-secret file; a choice of least permissions and authorized test account;
account-owner consent in Google; and separately authorized deployment/routing.
Then prove consent -> proxy request -> expired-token refresh with the real
account. No pasted refresh token or secret in chat is required. Source/simulator
success is not deployed provider integration or production/native acceptance.
