> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Portal OAuth And Agent Guide

This guide covers the operator path for connecting OAuth-backed services in the Serverware portal and the agent path for using those credentials without direct credential delivery. Serverware still handles plaintext transiently in its trusted injection path; current development Docker does not prove enclave-only custody or complete zeroization of every HTTP allocation.

[Private deployment screenshot omitted from public source.]

The screenshots in this guide are rendered from the real portal UI by the deterministic HTTPS browser journey in `scripts/test_portal_browser_oauth.py`. The desktop view above shows the empty operator-passkey inventory, pending configuration/runtime/hardware statuses, handoff field, and assignment controls after the demo state is seeded. The approval views below open a real pending request through its exact deep link. The OAuth and policy screenshots exercise real portal redirects and callback handling against a bounded local provider simulator. They are not evidence of a live Google/X tenant, production WebAuthn enrollment, or completed production Setup run. The SVG diagrams remain architecture references, not screenshots.

## Authenticate The Operator

Development accepts the `dev-admin-token` through the portal token field. Production also supports bearer JWTs for automation and requires the built-in browser OIDC flow. Configure `SERVERWARE_OIDC_ENABLED=1`, `SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED=1`, `SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED=1`, bounded pending/challenge/session TTLs, the issuer, audience, pinned JWKS, role claim, HTTPS authorization and token endpoints on the issuer origin, client ID, owner-only client-secret file, scopes including `openid`, and the exact `${SERVERWARE_PUBLIC_URL}/api/auth/oidc/callback` redirect. `ops/production-readiness.env.example` contains the complete variable set.

The portal **Sign in** button calls `GET /api/auth/oidc/start`. Serverware creates one-use state, a separate browser nonce, an OIDC nonce, and an S256 PKCE verifier/challenge. The encrypted verifier, OIDC nonce, and only the browser nonce digest are stored in the metadata store; the raw browser nonce is an `HttpOnly`/`SameSite=Lax` callback cookie. The callback consumes the state once, exchanges the code with the verifier, validates the ID token against the pinned issuer/audience/JWKS/algorithm set and OIDC nonce, applies the configured subject and RBAC role claims, discards the raw token after hashing it, and sets a random opaque `HttpOnly`/`SameSite=Strict` cookie. In production this cookie is nonprivileged and expires within `SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS` unless the operator proves a currently trusted passkey.

The session challenge binds the OIDC subject, server-side session ID, pending expiry, final expiry, and a fresh nonce. Signature verification, challenge claim, authenticator-counter update, credential binding, trust-generation capture, token rotation, and activation commit atomically. The pending token is invalid after activation. Every privileged request rechecks session expiry, exact credential ownership/revocation, the current trust bundle digest/sequence and authenticator class, and authoritative RBAC. Passkey revocation atomically terminates all sessions bound to that credential. Unsafe API calls through pending or active cookies require the double-submit CSRF cookie and `X-Serverware-CSRF-Token` header. **Sign out** durably revokes the server-side session before clearing both cookies.

## Manage Operator Passkeys

The first portal band lists the current operator's active and revoked passkeys, effective authenticator class under the current trust bundle, attestation-root digest, last-use time, and retained revocation source. The API and bootstrap payload omit COSE public keys, development private material, and raw credential IDs. A pending OIDC subject with zero retained credential history can perform first enrollment using the production bootstrap token; sibling registration challenges are invalidated when the first key commits, and the new key must immediately prove possession before the session activates. **Register passkey** for every later key is a digest-bound control-plane mutation and can require a different operator's approval.

**Revoke** requires a non-empty reason, a fresh assertion over the exact credential record and reason, and the configured two-person approval. The row is soft-revoked rather than deleted; assertion lookup and sign-counter CAS exclude it, credential-ID reuse is rejected, and unconsumed JIT grants plus bound browser sessions are revoked in the same metadata transaction. Revoking the last active passkey intentionally does not reopen bootstrap. A pending OIDC login instead offers offline recovery. The portal creates the replacement credential locally, verifies its attestation, copies a canonical subject/session/history/trust/candidate-bound statement for an offline Ed25519 root to sign, and accepts only the signed exact statement. If the lost key remains active, the portal first requires a separate signed decommission statement for that exact active credential; the decommission signature cannot be reused for registration. Both ceremonies are short-lived, sequence/replay protected, atomically audited, and retain evidence. Recovery still leaves the session pending until the new key completes an ordinary assertion. Only the offline public key is mounted into Serverware; keep the private root on a separately operated signer. Production also requires the recovery witness PostgreSQL DSN to reach a different server address or port from metadata. A witnessed signature is burned even when the later metadata transaction fails, so the operator must sign a new statement rather than replaying old authority.

Production additionally requires different PostgreSQL `system_identifier` values and distinct operator-pinned metadata/witness fault-domain IDs; separate aliases or listeners on one cluster do not count as independence. Both database roles need permission to execute `pg_control_system()`. The witness claim occurs under the serialized metadata authority transaction before credential or sequence mutation, so parallel finalization has exactly one winner; a witness commit followed by metadata failure still burns the authorization and requires a fresh ceremony.

Publishing a signed trust bundle re-evaluates every active attested credential against the candidate roots, AAGUID restrictions, and class. Removed trust soft-revokes affected rows with source `trust-root-withdrawal`; an empty `roots` array withdraws all roots. That revocation also terminates bound browser sessions. Even without publication, privileged session lookup rechecks the current trust generation and fails closed on mismatch or trust-store failure. A later bundle may restore a root for new registrations, but it cannot reactivate historical rows. Production protects `webauthn.credential.revoke` and `webauthn.trust.publish` with hardware WebAuthn and two-person approval.

## Configure OAuth Providers

Serverware currently has first-class portal OAuth setup for Google and X/Twitter.

[Private deployment screenshot omitted from public source.]

The provider screenshot is captured after Chromium follows the portal's Google authorization redirect, returns through the real callback endpoint, verifies `operator@example.test` through the local HTTPS simulator, creates the encrypted OAuth credential, and makes it selectable for the Gmail 30-day template. The simulator validates the exact redirect URI, client authentication, PKCE, one-use code, scopes, and identity lookup. This proves the browser/portal contract without claiming live Google consent or production identity evidence.

Google:

```bash
export SERVERWARE_PUBLIC_URL=https://serverware.example.com
export SERVERWARE_GOOGLE_OAUTH_CLIENT_ID=...
export SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE=/etc/serverware/secrets/google-oauth-client-secret
export SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI=https://serverware.example.com/api/oauth/callback/google
```

X/Twitter:

```bash
export SERVERWARE_PUBLIC_URL=https://serverware.example.com
export SERVERWARE_X_OAUTH_CLIENT_ID=...
export SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE=/etc/serverware/secrets/x-oauth-client-secret
export SERVERWARE_X_OAUTH_REDIRECT_URI=https://serverware.example.com/api/oauth/callback/x
```

Production secret files must be regular non-symlink files owned by the distroless control-plane UID `65532`, use mode `0400` or `0600`, and be readable to the privileged host preflight. Plaintext `SERVERWARE_*_OAUTH_CLIENT_SECRET` variables remain a local-development convenience and are rejected by production readiness.

The portal uses OAuth 2.0 Authorization Code with PKCE. The start endpoint requires an authenticated Serverware operator and runs credential-create WebAuthn mutation MFA before redirect when that control is enabled. Two-person authorization is deliberately deferred because the account does not exist in the provider response yet. OAuth state is server-side, one-use, TTL-bound, and size-bounded before it is written to disk. Each state stores only the SHA-256 digest of a separate browser nonce; the raw nonce is held in a state-specific `__Host-serverware-oauth-<state>` `Secure`, `HttpOnly`, `SameSite=Lax` cookie and must match at callback. Multiple provider flows can therefore finish out of order without overwriting each other's browser binding. A callback from another browser fails without consuming the legitimate state, while a matching provider-denial callback consumes it. When the caller supplies a durable `setupSessionId` and its current `setupRevision`, only that session's owner may start consent. Serverware stores the canonical setup ID in the one-use state, stores only the OAuth state digest in the setup ledger, and validates the owner, provider, phase, and state digest before accepting the callback. The setup ID is not sent to the provider and is not added to credential metadata.

The successful callback exchanges the code, fetches the account from Google's user-info endpoint or X's `/2/users/me`, and refuses to stage a credential when that identity lookup cannot be verified. If production two-person controls cover `credential.oauth.activate`, the callback envelope-encrypts the token as a pending credential instead of inserting it into the active credential table. Its bounded review binds the exact provider subject, display account, canonical granted scopes, credential name/type, expiry, metadata keys, X app ID when applicable, and a payload digest that also commits to the encrypted token source. No lease can reference this pending row. For a durable Setup flow, only this successful path binds the unique pending row or newly created credential generation to the same setup session, renders a success page, and returns the browser to `/?setup=<id>`. Provider denial and callback validation, exchange, or persistence failure are terminal for that callback and render a non-redirecting error page; they do not provide return-to-portal continuity.

Back in **Verified accounts awaiting activation**, only the original OAuth requester can select **Request approval and activate**. WebAuthn mutation MFA runs for the exact activation payload, a different authorized operator decides the `credential.oauth.activate` request in the control-plane approval queue, and the original requester retries with that approval ID. Activation atomically consumes the approval, moves the same encrypted envelope into the active credential table without rewriting token material, deletes the pending row, invalidates leases, and audits the exact-account evidence. A Setup-bound activation additionally requires the same setup ID and current CAS revision, then records the resulting credential ID and generation in that session. Self-approval, account/digest/resource/setup mismatch, expiry, replay, stale revision, or any changed state fails closed. When two-person activation is not configured, callback activation remains immediate for local development.

If the initial token response omits `scope`, Serverware follows OAuth semantics and binds the requested scopes; an explicit response may narrow but never expand them. A v2 lease is issued later, on data-plane demand.

`provider_identity_verified` means the provider account lookup succeeded. Google's `provider_email_verified` and X's `provider_profile_verified` are separate facts; do not conflate an identified account with a provider-verified email or X profile badge.

Refresh does not repeat the provider identity lookup. It preserves the callback-verified subject/account metadata and requires the refreshed scope set to equal the stored canonical set; an explicit expansion or reduction fails closed, while an omitted refresh `scope` retains the existing binding. Provider account reassignment or identity drift therefore still requires reconnecting and re-verifying the account.

Before every authorization-code or refresh exchange, Serverware durably changes its reserved revocation row to `exchange_in_flight`. A transport timeout, undecodable success response, or process interruption can leave the provider's issuance result unknowable. The row is retained as `issuance_uncertain_unreported`, reported once to the audit chain as `credential.oauth_issuance_uncertain`, then remains visible under **Provider issuance requires review**. It contains provider, requester, source, timestamps, and the bounded error, but no token response. It is not retried as a token revocation because Serverware has no token to present.

Do not clear that warning merely because a retry succeeded. The requester or an admin must first revoke the Serverware app grant in the provider account, record an evidence note, and explicitly confirm provider-side revocation. `POST /api/oauth/issuance-uncertainties/{id}/resolve` is protected by the `credential.oauth.uncertain.resolve` WebAuthn mutation and production two-person action, atomically consumes the matching approval when required, deletes only an uncertainty-state row, and audits the resolution. Until then, the row consumes bounded revocation-work capacity so an unresolved provider-side grant cannot disappear silently.

Pending activation has an explicit provider-revocation lifecycle. Cancelling a pending connection, letting it expire, or denying its exact-account approval changes its terminal status to `cancelled`, `expired`, or `rejected` and marks revocation `pending`. Serverware then calls the configured Google or X revocation endpoint with the refresh token when present, otherwise the access token. Success audits `credential.oauth_pending.revoked` and deletes the staged token material. Failure audits `credential.oauth_pending.revocation_failed`, retains only the terminal encrypted row plus bounded `revocation_status: failed`/`revocation_error` metadata, and exposes **Retry provider revocation** to the requester or an admin. A terminal row cannot be activated while revocation is pending or failed.

Provider-aware revocation also applies after activation. `DELETE /api/credentials/{id}` takes the cross-process credential lock, marks a managed OAuth credential `revocation_pending`, and immediately excludes it from normal reads, token refresh, injection, and lease snapshots. Serverware deletes local encrypted material only after Google or X confirms revocation; failure leaves a visible `revocation_failed` record and **Retry disconnect** action. **Reconnect** binds the existing credential ID and version into OAuth state, requires the callback to prove the same provider subject and account, revokes mismatched or stale newly issued material, and rotates the existing record in place so route and policy references do not change.

For X, the callback also stores the OAuth client ID as `x_app_id`. X route assignment requires that binding and replaces the template's `adapter.config.appIds` with the selected credential's stored app ID. Typed templates declare required OAuth scopes. The one-post-per-day template requires `tweet.write` in addition to its read/user/offline scopes, so a default read-only X credential is disabled in the selector until the operator reconnects with write consent. A credential from another provider, an X credential without an app ID, a scope-incomplete OAuth credential, or an incompatible injection shape is rejected before candidate creation.

The current credential inventory assumes one administrative trust domain. Operators with the relevant credential-management roles can act on the shared credential set; credentials are not tenant-owned, and the API does not isolate credential visibility or mutation by tenant. Treat one deployment as one administrative security boundary until explicit tenant and credential-ownership enforcement exists.

## Setup And Verify

The first portal section consolidates the common operator path without weakening the underlying controls:

1. Select a restriction template, principal, compatible credential, route ID, and any JIT approvers.
2. Use **Connect credential** when the provider account is not connected. OAuth and exact-account activation still run through their dedicated, audited controls.
3. **Preview assignment**, inspect every signed diff and allow/deny dry-run, then **Stage** and explicitly **Activate** the exact candidate.
4. **Generate enrollment** only after the selected principal is assigned to the active route and that route references the selected credential. The packet pins the current active policy hash; **Verify server evidence** records the current credential version and requires matching post-enrollment runtime evidence.
5. Download the signed packet, copy the verifier command, run it on the agent host, exercise the allowed route, complete JIT when required, and select **Verify server evidence**.

The Setup ledger's table and storage operations support both SQLite and PostgreSQL; that backend-neutral statement applies to the ledger, not to every service involved in the workflow. `POST /api/setup/sessions` creates a bounded, expiring session owned by the authenticated operator. `GET /api/setup/sessions` returns resumable session summaries without evidence or transition events. `GET /api/setup/sessions/{id}` returns the selected session with its evidence and transition events. The claim, handoff, cancel, credential, canary, policy, enrollment, and verify endpoints advance only named phases and require the caller's current `expectedRevision`; a stale writer receives a conflict with the current revision. Handoff by the owner or an admin records a bounded current-assignee subject string. It does not verify at handoff that the subject exists, grant that subject a role, reserve the run exclusively, or transfer OAuth ownership. When that subject later calls the API, normal authentication, role checks, participant checks, phase checks, and revision checks are enforced then.

Backend Setup binding fields are immutable once written: the assignment commits to the principal, route ID, canonical SHA-256 digest of the exact reviewed route policy, credential ID and generation, signed policy hash, and assignment digest. The current-assignee field changes only through claim or handoff. While a run is still in `created`, the portal leaves form controls editable; if the edited template, principal, or route no longer matches that run, the next action may create a replacement run instead of rebinding the existing backend record. Candidate binding re-compiles and verifies the signed staged bundle. Activation re-reads the active policy and rejects route, credential, policy, or assignment drift. Enrollment binding checks the exact packet digest and hashes the verifier nonce before storage; raw OAuth tokens, PKCE verifiers, enrollment capabilities, WebAuthn assertions, credential values, and verifier nonces are not setup-ledger fields.

Each transition and its evidence digests is written to a bounded audit outbox in the same metadata transaction as the session update. The consumer uses the stable transition-event ID as the audit idempotency key, supports stale-claim takeover, and leaves terminal records unprunable until their transition events have reached the hash-chained audit log. Capacity exhaustion fails closed.

The three status pills are intentionally independent:

- **Configuration ready** means the active signed policy, principal, route, credential, verified OAuth subject/scopes, and access-token-only injection agree.
- **Runtime exercised** additionally requires the signed enrollment packet's exact one-use CA capability to have been consumed and complete post-enrollment audit evidence for the exact policy/principal/route/credential/version. The server derives enrollment consumption, activated-canary monitoring, and the validated upstream response release from authoritative session, policy, canary, grant, and audit state; it does not accept browser claims for those facts. JIT routes require both the authoritative grant-store consumption record and the matching data-plane response record to agree on request, operation, flow, grant, and approval bindings.
- **Hardware unverified** remains pending until an independently signed hardware receipt is submitted. Server self-claims are not independent attestation verification. The portal and Setup API now issue the session-bound challenge, validate and store the exact signed hardware-assurance/proxy-statement bytes, enforce fresh challenge and cross-session replay checks, and retain the accepted evidence through completion. The separately trusted hardware verifier and off-host final authority must use distinct configured keys and bind the exact assignment, session, challenge, artifacts, release identity, and current host. Fixture authorities exercise this contract locally; no real production hardware receipt or independently operated authority exists for this checkout.

The durable ledger, control-plane endpoints, receipt APIs, and inline first-screen workflow are implemented, including successful OAuth callback/pending-activation continuity and server-derived canary/runtime reconciliation. The portal creates and selects durable runs, includes the selected run in `?setup=<id>`, resumes it after the operator reauthenticates, records a bounded handoff subject, keeps committed backend bindings immutable, and advances preview, stage, activation, enrollment, verification, hardware evidence, and final receipt through revision-checked endpoints. A claim sets the current-assignee string to the authenticated caller but is not an exclusive work lock. The portal can reach hardware-verified and audit-gated complete states with valid independently signed receipts. Production acceptance remains open until independently operated enrollment, hardware, and final authorities produce a real EIF/PCR/current-host/proxy-bound receipt chain on the target TEE deployment.

## Connect A Provider Credential

1. Open `http://localhost:3000` for local Docker or the production control-plane URL.
2. Use **Sign in** for production browser OIDC, or enter the local admin token/a bearer JWT when that authentication path is intended.
3. In **Connect Provider Credential**, choose `Google` or `X / Twitter`.
4. Keep the default scopes for common read-only use or enter stricter provider scopes.
5. Click **Connect with OAuth** and finish the provider consent screen.
6. When exact-account two-person controls are enabled, inspect the verified account in **Verified accounts awaiting activation**, request activation, have a different authorized operator approve the `credential.oauth.activate` item, then complete activation as the original requester.
7. Confirm that the active credential appears as `kind: oauth2`, shows the expected provider account, and reports a verified identity. Treat `identity unverified` as unusable and reconnect it.
8. If **Provider issuance requires review** appears, revoke Serverware in the provider's app/security console before using the confirmation control. Record evidence, complete the passkey and second-operator workflow, and verify the uncertainty leaves the queue.

OAuth credentials store token material as encrypted JSON in the control plane. Managed Google/X policies must use the canonical access-token injection:

```json
{"type": "bearer", "header": "Authorization", "field": "access_token"}
```

The broker and Python prototype project the secret to a new JSON object containing only `access_token` before any lease/cache handoff. The refresh token remains in the control-plane refresh path and cannot be selected by policy. Fieldless OAuth injection, `refresh_token`, another header/query target, a non-bearer type, malformed or duplicate JSON fields, an empty/non-string access token, and oversized token material all fail closed.

## Assign The Credential

Production policy should be published as a signed `PolicyBundle`, not as ad hoc route state. The portal templates are a convenience authoring layer for candidate bundles; the enforced production contract is the signed, activated bundle.

[Private deployment screenshot omitted from public source.]

The screenshot is captured after the deterministic browser journey connects both Google and X accounts and drives signed preview, two required dry-runs, staging, and explicit activation. It shows the X seven-day search assignment and callback-derived credential metadata; the test independently reads the active policy API and requires both the Gmail 30-day and X seven-day routes to reference the exact created credential IDs, provider subjects, scope sets, and X OAuth app ID.

Run the browser proof independently with:

```bash
make verify-portal-browser-oauth
```

The target installs the pinned Chromium revision through Playwright, trusts only the simulator certificate's SPKI, checks desktop and mobile overflow, confirms OAuth state-cookie cleanup, and scans browser/API/disk evidence for simulator token values. Use `--screenshots-dir docs/images` with the underlying script only when intentionally refreshing these canonical screenshots.

The canonical, schema-valid examples live in [credential-limits.examples.json](../policies/credential-limits.examples.json). Extract one without copying a potentially stale fragment:

```bash
jq '.routes[] | select(.id == "example.gmail.last_30_days")' \
  policies/credential-limits.examples.json
```

The canonical example bundle currently contains 10 credential definitions and 14 routes. The portal selector exposes nine fixed templates plus **Custom typed route policy**. Routes absent from that selector, including X full read, GitHub, Basic, query-token, and cookie examples, must be extracted from the bundle and submitted through the complete candidate-bundle path. Gmail, X, and npm selector entries are maintained portal variants; Slack and the Stripe/object-store entries are synchronized with their canonical examples.

The canonical routes are:

| Template route | Enforced capability |
| --- | --- |
| `example.gmail.last_30_days` | Gmail list/get only, a forced 30-day query, page cap 10, prior-search proof for direct reads, response `internalDate` validation, projected fields, only `From`/`Subject`/`Date` message headers, and bounded projected provider errors. |
| `example.x.search.seven_days` | Exact X recent-search read operation, app-ID binding, seven-day request and response windows, page cap 100, and bounded JSON projection. |
| `example.x.full_bounded_read` | Every currently cataloged X read family under `GET /2/**`, with write blocking and a bounded projection. This deliberately includes sensitive reads such as DMs and bookmarks; prefer a narrower route when possible. |
| `example.x.tweet.one_per_day` | Exact `POST /2/tweets`, app-ID and callback-verified provider-account binding, one shared use per provider account and operation every 86,400 seconds across principal or credential rotation, a 280-character body allowlist, and bounded JSON projection. |
| `example.npm.publish.yubikey_jit` | Publish, unpublish, dist-tag, token, and metadata write families, each behind a one-use 30-second operation-bound grant and WebAuthn user verification with trusted YubiKey or hardware attestation. Narrow the operation list when an agent needs fewer write families. The public npmjs template intentionally omits response-body identity binding because the official client ignores ordinary publish bodies; a compatible registry can enable the stricter `200`/`201` JSON package/version plus `published: true` invariant. |
| `example.slack.chat_post.hourly` | Exact `chat.postMessage`, a bounded channel/text request, five shared posts per principal/credential/route assignment per hour, and a success response whose channel must equal the requested channel. Message text is projected but not echoed as a security assertion because Slack may normalize it. |
| `example.github.issues_since_30_days` | Read-only issue listing with a 30-day `since` window, page cap 50, projected fields, and bounded provider errors. |
| `example.stripe.customers.list` | Only `GET /v1/customers`, page cap 25, and bounded list/customer projections including the provider's optional deleted marker. |
| `example.stripe.customers.get` | Only `GET /v1/customers/{customer_id}`, with the returned customer ID bound exactly to the matched path parameter and an optional deleted marker. |
| `example.stripe.payment_intent.tokenized_jit` | Only tokenized `pm_...` PaymentIntent creation, a required bounded `Idempotency-Key`, USD 50-50,000 minor-unit amount bounds, five shared attempts per principal/credential/route assignment per day, raw card/source fields denied, one-use hardware-backed JIT, an admitted PaymentIntent status, and response binding for `amount`, `currency`, and `payment_method`. Denied request bytes are handled transiently by the proxy; this is not card tokenization or PCI certification. |
| `example.object_store.small_puts` | Exact bounded JSON PUT, ten shared writes per principal/credential/route assignment per hour, and response binding for the path artifact ID plus provider-echoed caller-declared digest metadata. It does not hash the uploaded content. |
| `example.basic.structured_secret_read` | Read-only Basic authentication using a fixed username and a password selected from a structured secret field. |
| `example.query.structured_secret_read` | Read-only query-token injection selected from a nested secret field; the caller can supply `city` but cannot override the injected `api_key`. |
| `example.cookie.structured_secret_read` | Read-only cookie injection selected from a nested secret field; ambient caller cookies remain outside the admitted request contract. |

Every template is an ordinary signed route: operators can narrow it further, but unknown fields, operations, hosts, paths, content types, policy extensions, and unsupported response modes fail admission or execution closed.

The Stripe PaymentIntent template applies its `responseBinding` constraint only to `stripe.payment_intents.create`. A missing `amount`, `currency`, or `payment_method` request source is denied before credential release. The response must be an exact admitted `200 application/json` envelope, identify itself as a PaymentIntent with a bounded `pi_...` ID, and match the captured amount, currency, and payment-method token. Response paths traverse objects only, never arrays. A missing or mismatched field, wrong success status/media type, or wrong object identity becomes a synthetic `502` before any upstream response bytes are released to the agent. This describes Serverware's policy contract and local verification boundary. It does not claim validation against live Stripe or PCI validation or certification.

Stripe uses a manually stored API credential in this release, not the Google/X OAuth connector. Choose **Tokenized PaymentIntent create + hardware JIT**, use **Connect credential**, and store a bearer credential whose metadata contains `{"provider":"stripe"}`; the Setup workflow prefills that metadata. The signed-template selector rejects unbound or differently labeled bearer credentials, and the weaker local-prototype editor intentionally does not offer Stripe shortcuts. This provider label is an operator assertion for a static secret, not provider-verified OAuth identity.

The portal supports template-based production authoring. For arbitrary production constraints, select **Custom typed route policy** or submit a complete bundle to `POST /api/policy/candidate`; do not use the **Local prototype route** editor as a production policy source.

When the portal inserts a newly connected OAuth credential into `PolicyBundle.credentials[]`, it copies the exact verified provider subject and canonical provider-granted scopes along with the ID, provider, and injection shape. Malformed, duplicate, missing, unverified, or inconsistent account/scope claims fail closed, and lease authorization requires exact provider, subject, and scope equality with the signed policy.

After selecting a template, principal, and compatible credential:

1. Click **Preview candidate** and inspect the signed candidate hash, human-readable diff, every allow/deny dry-run result, and the selected credential's provider, injection, and scopes.
2. Click **Stage candidate**. This writes a signed candidate bundle and staged state but does not change the active policy.
3. Use **Refresh status** while the configured observation gate counts post-stage audit, denial, and latency evidence for affected route IDs.
4. Click **Activate** only when the monitoring thresholds pass. WebAuthn and two-person mutation controls still apply when configured.
5. Click **Cancel** with a reason if the candidate should not become active.

The assignment is complete only after a scope-correct candidate activates and changes the active policy hash. A staged candidate is not an active credential assignment and receives no proxy traffic. The observation gate reports baseline post-stage events for affected route IDs; candidate behavior is proven by schema/semantic validation and explicit allow/deny dry-runs before the operator performs an all-at-once activation. Serverware deliberately exposes no traffic-percentage control until dual-snapshot routing, candidate-aware leases/JIT/quotas, and tunnel-stable selection exist in Rust.

Each accepted activation persists a policy high-water record containing the policy ID, sequence, rollback epoch, and hash. Python, Rust startup, hot reload, attestation, and production verification reject a signed snapshot below that high-water mark, including after restart; rollback is a new, higher signed revision rather than replay of an old bundle.

## Review JIT Approvals

When an agent's first real proxied request hits a route that requires human approval, the release authority validates its full canonical request, leaves no quota or grant reservation behind, atomically creates or reuses the exact pending approval, and returns `428 serverware_approval_required` with `approval_id`, `approval_url`, and retry timing. The non-mutating `/v1/decide` preview never creates approvals. The agent gives the operator the exact URL, waits, and retries only the identical request after approval. It never receives a grant token or credential.

[Private deployment screenshot omitted from public source.]

The approval URL is an application path such as `/approvals/apr_...`; deployments resolve it against the configured Serverware public origin before showing it to the operator. Opening that URL authenticates the operator, loads only the named review document, focuses the review panel, and preserves the exact route in browser history. The deterministic browser test verifies the approval ID, route, package, request digest, operation digest, focus, and absence of horizontal overflow before capturing this view.

In the portal **Approvals** table, open **Review** before approving. The review panel is populated from `GET /api/approvals/{id}/review` and shows:

- principal and source identity;
- route, credential reference, credential version, and policy hash;
- method, stored target-URL commitment, normalized operation fields, and request body hash; the raw URL is not recoverable from durable approval storage;
- redacted payload summary and risk flags such as WebAuthn requirement, hardware attestation requirement, current policy hash, credential-version binding, and one-use grant;
- previous similar approvals or denials;
- exact retry semantics, including the request digest, operation digest, grant TTL, max uses, and the fact that the agent receives no secret or token.

Opening review now issues a short-lived, one-use server-side receipt bound to the approver and SHA-256 digest of that exact redacted review document. WebAuthn options include the receipt ID, review digest, and receipt expiry in the signed challenge. The approval transaction requires and atomically consumes the same live receipt while creating the grant, so a direct API caller cannot approve without first retrieving the matching review and cannot replay a reviewed document after approval. Opening review is itself audited.

The portal keeps **Approve** disabled until the matching review has been opened. If the active policy changed after the approval request was created, the review shows `policy_hash_not_current`, the portal keeps approval disabled, and the approval API returns `409` so the agent must issue a new request under the current policy. Approval still runs through the configured WebAuthn/YubiKey policy and creates a server-side one-use grant. The identical retry atomically reserves that grant together with every shared quota, advances the exact attempt to `dispatching` immediately before upstream contact, and commits or refunds it according to the bounded completion state. Denial can include an operator reason through the API, and denial records are searchable in audit.

[Private deployment screenshot omitted from public source.]

The narrow-viewport capture exercises the same canonical review document and bindings. It is not evidence of a physical YubiKey ceremony or independent production approval authority.

[Private deployment screenshot omitted from public source.]

The mobile screenshot shows the responsive operator-passkey and Setup and Verify workflows: the empty passkey state, pending configuration/runtime/hardware status pills, next-operator subject field, and assignment controls stacked for a narrow viewport. The seeded state demonstrates rendered workflow behavior, not a live provider login, production WebAuthn ceremony, physical YubiKey use, independent enrollment verification, or hardware attestation.

## Teach Agents To Use Serverware

Agents do not need provider tokens, OAuth refresh tokens, npm tokens, or API keys. Give them only the proxy/CA setup and the upstream API task.

![Serverware agent enrollment flow](images/agent-enrollment-flow.svg)

Generate an enrollment packet from the portal:

1. Open `http://localhost:3000` or the production control-plane URL.
2. In **Agent Enrollment**, choose the policy principal that will run the agent.
3. Enter the Serverware proxy URL, proxy egress CIDR, namespace, CA mount path, and optional pod selector JSON. The control-plane origin is read-only and derived from `SERVERWARE_PUBLIC_URL`; a submitted mismatch is rejected.
4. Click **Generate enrollment**, then **Download + copy verifier command**. The portal downloads the exact signed packet and copies a fail-closed command that verifies that file before any CA installation step.

The same packet can be generated from the CLI for automation:

```bash
python3 scripts/generate_agent_enrollment.py \
  --principal-id agent:mail-reader \
  --proxy-url http://serverware-proxy.internal:8080 \
  --proxy-egress-cidr 10.42.0.10/32 \
  --selector app=mail-reader
```

The portal generates a fresh 32-byte browser challenge and requests a five-minute packet. The server signs the packet digest, principal, challenge, validity window, policy hash, and runtime-manifest digest with the response key named by the packet's attestation pins. Do not use a packet after `expiresAtEpochMs` or if its `nonce` is not the challenge you requested.

The portal returns a signed packet but does not independently verify it or add `verificationReceipt`. Verify the downloaded file itself; do not run generation mode again and treat the newly generated packet as proof of the portal packet:

```bash
ENROLLMENT_PACKET=serverware-enrollment-agent-mail-reader.json
VERIFIED_ENROLLMENT_PACKET=serverware-enrollment-agent-mail-reader.verified.json
EXPECTED_PACKET_SHA256=sha256:<value-copied-from-the-portal-command>
EXPECTED_PRINCIPAL=agent:mail-reader
EXPECTED_NONCE=<value-copied-from-the-portal-command>
python3 scripts/generate_agent_enrollment.py \
  --base https://serverware.example.com \
  --verify-packet "$ENROLLMENT_PACKET" \
  --expected-packet-sha256 "$EXPECTED_PACKET_SHA256" \
  --expected-principal "$EXPECTED_PRINCIPAL" \
  --expected-nonce "$EXPECTED_NONCE" \
  > "$VERIFIED_ENROLLMENT_PACKET"
```

Use the digest, principal, and nonce from the separately copied portal command; do not recompute the expected digest from a file you are trying to authenticate. This mode first checks the exact raw downloaded bytes against that precommit. The digest covers principal, proxy/control-plane URLs, egress CIDRs, selectors, CA location, and every attestation pin. It then reads the bounded JSON object with duplicate-key rejection, rejects any preexisting untrusted receipt, obtains `/attestation` using the expected packet nonce, verifies the nonce-bound quote and runtime digest, compares every measurement pin, checks packet validity and expiry, and verifies the Ed25519 packet signature. Only then does it emit the same packet fields with a new `verificationReceipt`. A substituted file, unexpected principal or nonce, failed check, stale packet, altered egress rule, duplicate key, oversized input, or existing receipt is a hard failure.

After exact packet verification succeeds, install the CA through the scoped enrollment verifier:

```bash
python3 scripts/verify_attestation.py \
  --base https://serverware.example.com \
  --enrollment-packet "$VERIFIED_ENROLLMENT_PACKET" \
  --ca-out .tmp/serverware-ca.pem
install -D -m 0644 .tmp/serverware-ca.pem /etc/serverware/serverware-ca.pem
```

The copied portal command performs these steps in this order with shell error handling and defaults to the downloaded packet under `$HOME/Downloads`. It never requests, embeds, or transmits the Serverware admin token or any receipt-signing private key. The signed packet carries a policy-hash-bound, principal-bound, short-lived, one-use verifier capability whose URLs are relative to the configured control-plane origin; it can read only the pinned policy and download the CA once. Set `SERVERWARE_ENROLLMENT_PACKET` first when the browser saves downloads elsewhere. The verifier writes `.tmp/serverware-ca.pem`. The enrollment packet's `agentHandoff.caInstall.command` installs that verified file at the packet's configured `ca.installPath`; run it in the agent image or VM before starting the agent. The packet enumerates every allowed route URL, not just the first path, and exposes the exact proxy environment, required CONNECT/provider headers, and machine-readable `requestHandling` rules for approval and terminal errors. Proxy-authorization secret material is deliberately absent and must be provisioned separately when `agentHandoff.proxyAuthorization.required` is true.

Setup enrollment-receipt signing is a separate trust-domain operation. Run `scripts/generate_agent_enrollment.py --sign-setup-receipt` only on the independently controlled verifier, after transferring the precommitted packet and live nonce-bound attestation evidence to that verifier. Its owner-only Ed25519 key must never be mounted in, copied to, or referenced by the agent image, VM, portal handoff command, or Serverware workload. Transfer only the signed receipt back to the operator for upload through the Setup workflow.

Run the agent with only proxy configuration:

```bash
export HTTPS_PROXY=http://serverware-proxy.internal:8080
export HTTP_PROXY=http://serverware-proxy.internal:8080
export SSL_CERT_FILE=/etc/serverware/serverware-ca.pem
export REQUESTS_CA_BUNDLE=/etc/serverware/serverware-ca.pem
```

For a principal that uses top-level `principals[].requiredHeaders`, HTTPS clients must send those identity headers on the proxy `CONNECT` request as well as the provider request. For example, curl uses `--proxy-header 'X-Serverware-Agent: mail-reader'` for the tunnel and `-H 'X-Serverware-Agent: mail-reader'` inside it. The enrollment packet exposes these as both `agentHandoff.requiredProxyHeaders` and `agentHandoff.requiredProviderHeaders`; the former also contains the per-enrollment `X-Serverware-Enrollment-Session` value, which is sent on `CONNECT` but not repeated inside that tunnel. The packet separately exposes any `identity.proxyAuthorization` requirements. Production deployments should prefer source-bound proxy authorization or isolated source CIDRs when the agent SDK cannot set custom proxy headers.

Do not confuse principal identity headers with `generic.rest` `adapter.config.request.requiredHeaders`. Adapter-required headers are ordinary provider request fields that must also appear in `request.allowedHeaders`; they are checked after route/principal matching for bounded UTF-8 byte length and an optional safe anchored pattern, then forwarded upstream. They do not authenticate the `CONNECT` tunnel. The Stripe template uses this second mechanism for `Idempotency-Key`, so the agent must provide a fresh policy-conforming key on the provider request while separately satisfying its principal identity requirements.

Agent instruction block:

```text
Use the normal provider SDKs and upstream URLs.
Do not ask for, store, print, or cache provider credentials.
All HTTP and HTTPS traffic must use the configured Serverware proxy.
Apply the enrollment packet's proxy identity requirements to the proxy connection, including CONNECT.
If Serverware returns 428, give approval_url to the operator, honor retry_after_seconds, wait for human approval, and retry only the identical request.
If Serverware returns 403 or 5xx, stop and report the route/error; do not bypass the proxy.
```

Enforce egress so the agent cannot bypass Serverware. The enrollment packet includes a Kubernetes `NetworkPolicy` and iptables rules that only allow outbound traffic to the configured Serverware proxy CIDRs.

## Exact Credential Lease Flow

An enrolled agent never calls the secret broker. The Rust data plane requests a lease only after a signed route has matched an exact `(policy hash, principal, route, credential)` scope:

1. Rust creates an ephemeral X25519 recipient key and one-use 32-byte nonce, then sends `serverware.credentialLeaseRequest/v2` with the scoped IDs, measured binary digest, requested TTL, and recipient-attestation evidence.
2. The control plane rechecks the active policy, principal-to-route assignment, route-to-credential assignment, provider/scopes, measured binary, nonce replay state, and recipient evidence.
3. It refreshes a managed OAuth access token when it is near expiry under a cross-process single-flight lock. A successful refresh rotates the credential version; a failed or scope-changing refresh returns `503` and requires reconnection.
4. It projects managed Google/X material to canonical JSON containing only `access_token`, then returns `serverware.credentialLeaseEnvelope/v2`, encrypted with X25519/HKDF-SHA256/AES-256-GCM and signed by the attested response key. The decrypted `serverware.credentialLeaseSet/v2` must contain exactly one credential matching the requested scope and can never contain the OAuth refresh token.
5. Rust verifies every cleartext and encrypted binding, enforces the short lease expiry, and caches by exact scope, policy snapshot epoch/hash, trust generation, credential ID, and version. Rotation is monotonic: an older or same-version changed secret cannot replace a newer lease.
6. Warm leases renew in the background. A cold or expired lease can synchronously wait for the broker; if no current lease is available, the request fails closed before forwarding.

No plaintext lease file or plaintext credential-delivery response is part of v2. Development still uses a software recipient, so host root can inspect Rust memory; moving that recipient and unwrap boundary into a real enclave is production-host work.

## Response Release And Audit

Credential injection does not imply that the upstream response is safe to return. Credential-bearing routes must use a bounded, projecting response mode; opaque `any`, non-redacting `stream`, and credential-bearing mutating request streams are rejected at policy admission.

- Success and error statuses use separate bounded profiles. Redirects are blocked, and a provider `4xx`/`5xx` without an explicit error profile is blocked.
- Only policy-selected safe semantic headers can be released. `Set-Cookie`, `Location`, authentication/session state, hop-by-hop headers, content encoding, and upstream content length are stripped and rebuilt.
- JSON fields, Gmail message-header names, body size, status, content type, and response date windows are validated before release.
- Before every credential-bearing upstream send, Rust synchronously submits `data_plane.credential.release_started` and requires the control plane to acknowledge its durable hash-chain append. Missing delivery configuration, transport failure, or ingest failure produces a local `503` and no upstream send.
- Immediately before send, Rust rechecks the active snapshot and exact lease version/expiry. Released body and safe-header values are scanned for configured credential representations; a match is blocked as `response_credential_reflection`.

The reflection guard is defense in depth, not general information-flow proof. A deliberately malicious approved provider could transform a secret into a value that also satisfies an allowed semantic field. Keep response projections narrow and do not treat an upstream service as trustworthy merely because its hostname is allowlisted.

## Attestation Checks

Before installing the CA or enabling production credentials, verify:

```bash
python3 scripts/verify_codebase_attestation.py \
  --base https://serverware.example.com \
  --admin-token "$SERVERWARE_ADMIN_TOKEN"
```

In development this verifier checks internal consistency among the signed quote, runtime manifest, policy signature, policy high-water record, `serverware.sourceTree/v2` digest, release provenance, image-signature digest, CA SPKI, and a nonce-bound **control-plane** response signature. Source manifest v2 commits to path, type, normalized mode, file bytes, symlink targets, tracked deletions, all tracked inputs, and relevant untracked source/build/config inputs. It does not prove that the Rust proxy ran in a hardware TEE.

For a safe, buffered `GET`, `serverware-proof-client` can send a fresh proof nonce through the CONNECT TLS tunnel and write `serverware.proxyResponseProof/v3`; `HEAD` is rejected. The proof pairs a v2 external client capture with the Rust `serverware.proxyResponseStatement/v2`. Both bind the exact atomic authorization historically observed at upstream dispatch, including observation time and reservation expiry, grant/approval identity when present, credential version, request/operation/attempt/consumption identity, raw upstream status/body/policy-header digests, exact projected status/body/selected headers, policy, runtime manifest, measured binary, release, server instance, and TLS exporter. The gate sends a fresh nonce in the actual dispatch call and embeds its canonical request plus the signed control-plane response as `serverware.controlPlaneAuthorizationReceipt/v1`. Production verification independently pins that response-signing key and requires the embedded receipt to match the complete authority tuple and timing; no separately supplied receipt artifact is accepted. The inline statement makes no current-authorization or downstream-completion claim; the client demonstrates receipt by possessing the response and valid proof. This is a real end-to-end byte binding in the development stack, but its `vendor_tee` is explicitly `none-dev`/`development-fixture`.

`make production-release-proof` binds the real Linux/Nitro/AppArmor/KMS/Sigstore/registry readiness artifacts, but that alone is not final hardware proof. `serverware.completionProof/v3` reports `ServerwarePreEnclaveReadiness`, `completion_status: pre-enclave-readiness`, `final_completion: false`, and `hardware_proof: false` unless the verifier also receives a separately trusted, fresh `serverware.hardwareAssurance/v1` statement and an unbypassed current-host binding. That independent statement must bind EIF/PCR measurements, enclave and parent CIDs, a verified vsock handshake, KMS Recipient enclave key custody, evidence that parent processes did not hold key material, the exact Nitro evidence, host preflight, and attested release. No such real hardware artifact exists for this checkout. Streaming `GET` routes have a local domain-separated v1 end-of-stream proof; production completion still consumes buffered v3 until custody and release-verifier integration.

## Current Local Evidence

The canonical current local measurement and measured executable digest are recorded in [README.md](../README.md#runtime-and-performance) and the regenerated `.tmp/decision-gate-rs-bench.json` artifact. The benchmark covers the authenticated, non-mutating `/v1/decide` management endpoint; it does not measure release-authority calls, CONNECT, TLS interception, full proxy, streaming, provider, or production-host latency. Regenerate it from the exact release candidate instead of copying volatile timings into this guide.

The local provenance and image-signature records are explicitly development fixtures, and no current hardware-bound production image/quote set exists for this checkout. They cannot be combined with this benchmark as production release evidence; rebuild every source-, image-, binary-, signature-, benchmark-, and quote-bound artifact from one exact checkout on the target host.

## Current Operational Limits

- Managed OAuth credentials refresh on lease demand shortly before access-token expiry, with strict token-type parsing, scope non-expansion, refresh-token rotation handling, version rotation, audit, and cross-process single flight. A missing/expired refresh token or provider failure fails closed. X refresh always retires the superseded access token and retires the old refresh token only when the provider actually rotates it; a non-rotating refresh token remains usable. X reconnect replaces the grant and therefore queues both superseded tokens. Google credentials must be disconnected and revoked before the account is connected again because Google revocation applies to the account/project grant.
- Exact-account two-person activation is implemented for OAuth callbacks when `credential.oauth.activate` is protected. Terminal pending connections and post-exchange failures retain encrypted provider-revocation work for bounded automatic retry. Active managed OAuth disconnect fails closed through `revocation_pending`/`revocation_failed`; exact-account in-place reconnect is available only for X after version and identity validation.
- Do not create sibling logical credentials for the same Google account under one OAuth project until Serverware has a first-class grant-family model; Google can revoke all project grants for that account together.
- A host/process failure in the narrow interval after provider issuance and before encrypted revocation material is attached cannot be made atomic with an external OAuth server. Production acceptance still needs measured exchange custody and explicit uncertain-issuance recovery.
- Staged candidates receive no traffic before activation. The observation gate measures active-policy baseline events for affected route IDs, while schema/semantic checks and explicit dry-runs evaluate the candidate. The local workflow test injects observation records; production acceptance still requires real deployment traffic and denial canaries before activation.
- Source CIDRs, headers, and proxy tokens are implemented, but non-spoofable mTLS/SPIFFE workload identity remains future work.
- An approved agent can still misuse data that policy legitimately allows, and an approver can approve the wrong operation. Least-privilege provider scopes and careful review remain necessary.
- The proxy and host can observe destination and timing metadata. A compromised host can deny service even when a TEE protects keys.
- Streaming response proofs, real hardware quote/KMS Recipient execution, parent-host observation evidence, TEE vendor bugs, side channels, and incorrect PCR/release mappings remain part of the deployment threat model.
