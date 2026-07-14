> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Portal OAuth And Agent Guide

This guide covers the operator path for connecting OAuth-backed services in the Serverware portal and the agent path for using those credentials without ever receiving them.

[Private deployment screenshot omitted from public source.]

The screenshots in this guide are rendered from the Docker portal. The desktop view above shows live pending npm JIT requests beside the credential and OAuth controls. Seeded provider records and callback fixtures exercise UI and policy bindings but are not evidence of a live provider login. The SVG diagrams remain architecture references, not screenshots.

## Authenticate The Operator

Development accepts the `dev-admin-token` through the portal token field. Production also supports bearer JWTs for automation and requires the built-in browser OIDC flow. Configure `SERVERWARE_OIDC_ENABLED=1`, `SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED=1`, the issuer, audience, pinned JWKS, role claim, HTTPS authorization and token endpoints on the issuer origin, client ID, owner-only client-secret file, scopes including `openid`, and the exact `${SERVERWARE_PUBLIC_URL}/api/auth/oidc/callback` redirect. `ops/production-readiness.env.example` contains the complete variable set.

The portal **Sign in** button calls `GET /api/auth/oidc/start`. Serverware creates one-use state, a separate browser nonce, an OIDC nonce, and an S256 PKCE verifier/challenge. The encrypted verifier, OIDC nonce, and only the browser nonce digest are stored in the metadata store; the raw browser nonce is an `HttpOnly`/`SameSite=Lax` callback cookie. The callback consumes the state once, exchanges the code with the verifier, validates the ID token against the pinned issuer/audience/JWKS/algorithm set and OIDC nonce, applies the configured subject and RBAC role claims, and sets an `HttpOnly` session cookie. Its lifetime cannot exceed either the ID token expiry or `SERVERWARE_OIDC_SESSION_TTL_SECONDS`.

Unsafe API calls made through that cookie require Serverware's double-submit CSRF cookie and `X-Serverware-CSRF-Token` header. The portal obtains and sends the CSRF token automatically. Authorization remains live: role-gated requests re-read the authoritative role binding, so a deprovisioned production subject is denied even while its ID token has time remaining. **Sign out** removes the OIDC session and CSRF cookies and records an audit event.

## Configure OAuth Providers

Serverware currently has first-class portal OAuth setup for Google and X/Twitter.

[Private deployment screenshot omitted from public source.]

The provider screenshot deliberately captures the disabled state before Google client environment variables are configured. Once configured, the same panel enables **Connect with OAuth**.

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

The portal uses OAuth 2.0 Authorization Code with PKCE. The start endpoint requires an authenticated Serverware operator and runs credential-create WebAuthn mutation MFA before redirect when that control is enabled. Two-person authorization is deliberately deferred because the account does not exist in the provider response yet. OAuth state is server-side, one-use, TTL-bound, and size-bounded before it is written to disk. Each state stores only the SHA-256 digest of a separate browser nonce; the raw nonce is held in a state-specific `__Host-serverware-oauth-<state>` `Secure`, `HttpOnly`, `SameSite=Lax` cookie and must match at callback. Multiple provider flows can therefore finish out of order without overwriting each other's browser binding. A callback from another browser fails without consuming the legitimate state, while a matching provider-denial callback consumes it.

The successful callback exchanges the code, fetches the account from Google's user-info endpoint or X's `/2/users/me`, and refuses to stage a credential when that identity lookup cannot be verified. If production two-person controls cover `credential.oauth.activate`, the callback envelope-encrypts the token as a pending credential instead of inserting it into the active credential table. Its bounded review binds the exact provider subject, display account, canonical granted scopes, credential name/type, expiry, metadata keys, X app ID when applicable, and a payload digest that also commits to the encrypted token source. No lease can reference this pending row.

Back in **Verified accounts awaiting activation**, only the original OAuth requester can select **Request approval and activate**. WebAuthn mutation MFA runs for the exact activation payload, a different authorized operator decides the `credential.oauth.activate` request in the control-plane approval queue, and the original requester retries with that approval ID. Activation atomically consumes the approval, moves the same encrypted envelope into the active credential table without rewriting token material, deletes the pending row, invalidates leases, and audits the exact-account evidence. Self-approval, account/digest/resource mismatch, expiry, replay, or any changed state fails closed. When two-person activation is not configured, callback activation remains immediate for local development.

If the initial token response omits `scope`, Serverware follows OAuth semantics and binds the requested scopes; an explicit response may narrow but never expand them. A v2 lease is issued later, on data-plane demand.

`provider_identity_verified` means the provider account lookup succeeded. Google's `provider_email_verified` and X's `provider_profile_verified` are separate facts; do not conflate an identified account with a provider-verified email or X profile badge.

Refresh does not repeat the provider identity lookup. It preserves the callback-verified subject/account metadata and requires the refreshed scope set to equal the stored canonical set; an explicit expansion or reduction fails closed, while an omitted refresh `scope` retains the existing binding. Provider account reassignment or identity drift therefore still requires reconnecting and re-verifying the account.

Pending activation has an explicit provider-revocation lifecycle. Cancelling a pending connection, letting it expire, or denying its exact-account approval changes its terminal status to `cancelled`, `expired`, or `rejected` and marks revocation `pending`. Serverware then calls the configured Google or X revocation endpoint with the refresh token when present, otherwise the access token. Success audits `credential.oauth_pending.revoked` and deletes the staged token material. Failure audits `credential.oauth_pending.revocation_failed`, retains only the terminal encrypted row plus bounded `revocation_status: failed`/`revocation_error` metadata, and exposes **Retry provider revocation** to the requester or an admin. A terminal row cannot be activated while revocation is pending or failed.

Provider-aware revocation also applies after activation. `DELETE /api/credentials/{id}` takes the cross-process credential lock, marks a managed OAuth credential `revocation_pending`, and immediately excludes it from normal reads, token refresh, injection, and lease snapshots. Serverware deletes local encrypted material only after Google or X confirms revocation; failure leaves a visible `revocation_failed` record and **Retry disconnect** action. **Reconnect** binds the existing credential ID and version into OAuth state, requires the callback to prove the same provider subject and account, revokes mismatched or stale newly issued material, and rotates the existing record in place so route and policy references do not change.

For X, the callback also stores the OAuth client ID as `x_app_id`. X route assignment requires that binding and replaces the template's `adapter.config.appIds` with the selected credential's stored app ID. Typed templates declare required OAuth scopes. The one-post-per-day template requires `tweet.write` in addition to its read/user/offline scopes, so a default read-only X credential is disabled in the selector until the operator reconnects with write consent. A credential from another provider, an X credential without an app ID, a scope-incomplete OAuth credential, or an incompatible injection shape is rejected before candidate creation.

## Connect A Provider Credential

1. Open `http://localhost:3000` for local Docker or the production control-plane URL.
2. Use **Sign in** for production browser OIDC, or enter the local admin token/a bearer JWT when that authentication path is intended.
3. In **Connect Provider Credential**, choose `Google` or `X / Twitter`.
4. Keep the default scopes for common read-only use or enter stricter provider scopes.
5. Click **Connect with OAuth** and finish the provider consent screen.
6. When exact-account two-person controls are enabled, inspect the verified account in **Verified accounts awaiting activation**, request activation, have a different authorized operator approve the `credential.oauth.activate` item, then complete activation as the original requester.
7. Confirm that the active credential appears as `kind: oauth2`, shows the expected provider account, and reports a verified identity. Treat `identity unverified` as unusable and reconnect it.

OAuth credentials store token material as encrypted JSON. Policies should inject only the access token:

```json
{"type": "bearer", "header": "Authorization", "field": "access_token"}
```

`field` must be a strict dotted object path. If that field is missing, empty, not a string, uses wildcard syntax, or the secret is not JSON, Serverware fails closed before forwarding the request.

## Assign The Credential

Production policy should be published as a signed `PolicyBundle`, not as ad hoc route state. The portal templates are a convenience authoring layer for candidate bundles; the enforced production contract is the signed, activated bundle.

[Private deployment screenshot omitted from public source.]

The screenshot shows the Gmail template, principal and credential selectors, a signed candidate preview, two passing dry-run checks, and staged-candidate lifecycle controls. Previewing does not activate the assignment.

The canonical, schema-valid examples live in [credential-limits.examples.json](../policies/credential-limits.examples.json). Extract one without copying a potentially stale fragment:

```bash
jq '.routes[] | select(.id == "example.gmail.last_30_days")' \
  policies/credential-limits.examples.json
```

The common templates are:

| Template route | Enforced capability |
| --- | --- |
| `example.gmail.last_30_days` | Gmail list/get only, a forced 30-day query, page cap 10, prior-search proof for direct reads, response `internalDate` validation, projected fields, only `From`/`Subject`/`Date` message headers, and bounded projected provider errors. |
| `example.x.search.seven_days` | Exact X recent-search read operation, app-ID binding, seven-day request and response windows, page cap 100, and bounded JSON projection. |
| `example.x.tweet.one_per_day` | Exact `POST /2/tweets`, app-ID binding, one shared principal/credential/route/operation use per 86,400 seconds, a 280-character body allowlist, and bounded JSON projection. |
| `example.npm.publish.yubikey_jit` | Only publish and dist-tag writes, explicit token/metadata write denial, one-use 30-second operation-bound grant, and WebAuthn user verification with trusted YubiKey or hardware attestation. |
| `example.stripe.readonly_customers` | Only customer GET endpoints, page cap 25, and a projected customer response. |
| `example.stripe.payment_intent.tokenized_jit` | Only tokenized `pm_...` PaymentIntent creation, a required bounded `Idempotency-Key`, USD 50-50,000 minor-unit amount bounds, five shared attempts per day, raw card/source fields denied, and one-use hardware-backed JIT. Serverware does not accept or store raw card numbers in this template. |

The same file includes Slack, GitHub, and object-store examples. Every template is an ordinary signed route: operators can narrow it further, but unknown fields, operations, hosts, paths, content types, policy extensions, and unsupported response modes fail admission or execution closed.

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

When an agent hits a route that requires human approval, Serverware returns `428 serverware_approval_required` and stores a pending approval. The agent does not receive a grant token or credential. It waits and retries the same request after approval.

In the portal **Approvals** table, open **Review** before approving. The review panel is populated from `GET /api/approvals/{id}/review` and shows:

- principal and source identity;
- route, credential reference, credential version, and policy hash;
- method, URL, normalized operation fields, and request body hash;
- redacted payload summary and risk flags such as WebAuthn requirement, hardware attestation requirement, current policy hash, credential-version binding, and one-use grant;
- previous similar approvals or denials;
- exact retry semantics, including the request digest, operation digest, grant TTL, max uses, and the fact that the agent receives no secret or token.

The portal keeps **Approve** disabled until the matching review has been opened. If the active policy changed after the approval request was created, the review shows `policy_hash_not_current`, the portal keeps approval disabled, and the approval API returns `409` so the agent must issue a new request under the current policy. Approval still runs through the configured WebAuthn/YubiKey policy, creates a server-side one-use grant, and authorizes only the identical retry through the proxy. Denial can include an operator reason through the API, and denial records are searchable in audit.

[Private deployment screenshot omitted from public source.]

The mobile screenshot shows the responsive approval queue. Its rows are seeded demo history, not evidence that production WebAuthn or a physical YubiKey was exercised.

## Teach Agents To Use Serverware

Agents do not need provider tokens, OAuth refresh tokens, npm tokens, or API keys. Give them only the proxy/CA setup and the upstream API task.

![Serverware agent enrollment flow](images/agent-enrollment-flow.svg)

Generate an enrollment packet from the portal:

1. Open `http://localhost:3000` or the production control-plane URL.
2. In **Agent Enrollment**, choose the policy principal that will run the agent.
3. Enter the Serverware proxy URL, control-plane URL, proxy egress CIDR, namespace, CA mount path, and optional pod selector JSON.
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

After exact packet verification succeeds, install the CA through the independent CA verifier:

```bash
export SERVERWARE_ADMIN_TOKEN=...
python3 scripts/verify_attestation.py \
  --base https://serverware.example.com \
  --admin-token "$SERVERWARE_ADMIN_TOKEN" \
  --ca-out .tmp/serverware-ca.pem
install -D -m 0644 .tmp/serverware-ca.pem /etc/serverware/serverware-ca.pem
```

The copied portal command performs these steps in this order with shell error handling, defaults to the downloaded packet under `$HOME/Downloads`, and reads the admin token only from `SERVERWARE_ADMIN_TOKEN`; it does not embed the token. Set `SERVERWARE_ENROLLMENT_PACKET` first when the browser saves downloads elsewhere. The verifier writes `.tmp/serverware-ca.pem`. The enrollment packet's `agentHandoff.caInstall.command` installs that verified file at the packet's configured `ca.installPath`; run it in the agent image or VM before starting the agent. The packet enumerates every allowed route URL, not just the first path, and exposes the exact proxy environment and required CONNECT/provider headers. Proxy-authorization secret material is deliberately absent and must be provisioned separately when `agentHandoff.proxyAuthorization.required` is true.

Run the agent with only proxy configuration:

```bash
export HTTPS_PROXY=http://serverware-proxy.internal:8080
export HTTP_PROXY=http://serverware-proxy.internal:8080
export SSL_CERT_FILE=/etc/serverware/serverware-ca.pem
export REQUESTS_CA_BUNDLE=/etc/serverware/serverware-ca.pem
```

For a principal that uses top-level `principals[].requiredHeaders`, HTTPS clients must send those identity headers on the proxy `CONNECT` request as well as the provider request. For example, curl uses `--proxy-header 'X-Serverware-Agent: mail-reader'` for the tunnel and `-H 'X-Serverware-Agent: mail-reader'` inside it. The enrollment packet exposes the exact `identity.requiredHeaders` and any `identity.proxyAuthorization` requirements. Production deployments should prefer source-bound proxy authorization or isolated source CIDRs when the agent SDK cannot set custom proxy headers.

Do not confuse principal identity headers with `generic.rest` `adapter.config.request.requiredHeaders`. Adapter-required headers are ordinary provider request fields that must also appear in `request.allowedHeaders`; they are checked after route/principal matching for bounded UTF-8 byte length and an optional safe anchored pattern, then forwarded upstream. They do not authenticate the `CONNECT` tunnel. The Stripe template uses this second mechanism for `Idempotency-Key`, so the agent must provide a fresh policy-conforming key on the provider request while separately satisfying its principal identity requirements.

Agent instruction block:

```text
Use the normal provider SDKs and upstream URLs.
Do not ask for, store, print, or cache provider credentials.
All HTTP and HTTPS traffic must use the configured Serverware proxy.
Apply the enrollment packet's proxy identity requirements to the proxy connection, including CONNECT.
If Serverware returns 428, wait for human approval and retry the same request.
If Serverware returns 403 or 5xx, stop and report the route/error; do not bypass the proxy.
```

Enforce egress so the agent cannot bypass Serverware. The enrollment packet includes a Kubernetes `NetworkPolicy` and iptables rules that only allow outbound traffic to the configured Serverware proxy CIDRs.

## Exact Credential Lease Flow

An enrolled agent never calls the secret broker. The Rust data plane requests a lease only after a signed route has matched an exact `(policy hash, principal, route, credential)` scope:

1. Rust creates an ephemeral X25519 recipient key and one-use 32-byte nonce, then sends `serverware.credentialLeaseRequest/v2` with the scoped IDs, measured binary digest, requested TTL, and recipient-attestation evidence.
2. The control plane rechecks the active policy, principal-to-route assignment, route-to-credential assignment, provider/scopes, measured binary, nonce replay state, and recipient evidence.
3. It refreshes a managed OAuth access token when it is near expiry under a cross-process single-flight lock. A successful refresh rotates the credential version; a failed or scope-changing refresh returns `503` and requires reconnection.
4. It returns `serverware.credentialLeaseEnvelope/v2`, encrypted with X25519/HKDF-SHA256/AES-256-GCM and signed by the attested response key. The decrypted `serverware.credentialLeaseSet/v2` must contain exactly one credential matching the requested scope.
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

For a safe, buffered `GET` or `HEAD`, `serverware-proof-client` can send a fresh proof nonce through the CONNECT TLS tunnel and write `serverware.proxyResponseProof/v2`. The proof pairs an external client capture with the Rust `serverware.proxyResponseStatement/v1`; both bind the request and operation digests, exact released status/body digest/selected headers, policy, runtime manifest, measured binary, release, server instance, and TLS exporter. The server statement and client capture are independently signed, and the local test verifies their equality. This is a real end-to-end byte binding in the development stack, but its `vendor_tee` is explicitly `none-dev`/`development-fixture`.

`make production-release-proof` binds the real Linux/Nitro/AppArmor/KMS/Sigstore/registry readiness artifacts, but that alone is not final hardware proof. `serverware.completionProof/v3` reports `ServerwarePreEnclaveReadiness`, `completion_status: pre-enclave-readiness`, `final_completion: false`, and `hardware_proof: false` unless the verifier also receives a separately trusted, fresh `serverware.hardwareAssurance/v1` statement and an unbypassed current-host binding. That independent statement must bind EIF/PCR measurements, enclave and parent CIDs, a verified vsock handshake, KMS Recipient enclave key custody, evidence that parent processes did not hold key material, the exact Nitro evidence, host preflight, and attested release. No such real hardware artifact exists for this checkout. The current proxy-proof path also requires a safe method and fully buffered request/response; streaming responses do not yet expose an equivalent final client-verifiable proof.

## Current Local Evidence

The latest local Compose benchmark artifact, `.tmp/decision-gate-rs-bench.json`, binds the measured Rust executable `sha256:1f5ed058b743cbf28224fe8db6f9a090c640e3ffac5da1f07ce7c40514519901`. It records p50 `0.405 ms`, p95 `0.530 ms`, p99 `0.583 ms`, mean `0.412 ms`, and maximum `0.635 ms` across 1,000 calls after 100 warmups to the authenticated `/v1/decide` management endpoint. This is decision-engine latency, not CONNECT, TLS interception, full proxy, streaming, provider, or production-host latency.

The local provenance and image-signature records are explicitly development fixtures, and no current hardware-bound production image/quote set exists for this checkout. They cannot be combined with this benchmark as production release evidence; rebuild every source-, image-, binary-, signature-, benchmark-, and quote-bound artifact from one exact checkout on the target host.

## Current Operational Limits

- Managed OAuth credentials refresh on lease demand shortly before access-token expiry, with scope non-expansion, refresh-token rotation handling, version rotation, audit, and cross-process single flight. A missing/expired refresh token or provider failure fails closed and requires operator reconnection.
- Exact-account two-person activation is implemented for OAuth callbacks when `credential.oauth.activate` is protected. Terminal pending connections and post-exchange failures retain encrypted provider-revocation work for bounded automatic retry. Active managed OAuth disconnect fails closed through `revocation_pending`/`revocation_failed`, and exact-account reconnect rotates the same credential ID only after version and identity validation.
- Staged candidates receive no traffic before activation. The observation gate measures active-policy baseline events for affected route IDs, while schema/semantic checks and explicit dry-runs evaluate the candidate. The local workflow test injects observation records; production acceptance still requires real deployment traffic and denial canaries before activation.
- Source CIDRs, headers, and proxy tokens are implemented, but non-spoofable mTLS/SPIFFE workload identity remains future work.
- An approved agent can still misuse data that policy legitimately allows, and an approver can approve the wrong operation. Least-privilege provider scopes and careful review remain necessary.
- The proxy and host can observe destination and timing metadata. A compromised host can deny service even when a TEE protects keys.
- Streaming response proofs, real hardware quote/KMS Recipient execution, parent-host observation evidence, TEE vendor bugs, side channels, and incorrect PCR/release mappings remain part of the deployment threat model.
