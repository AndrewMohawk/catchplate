# Serverware

Serverware is a Dockerized credential-control proxy for agentic flows. Agents keep using normal HTTP clients and normal endpoint URLs, but route traffic through Serverware as an HTTP(S) proxy. Serverware's CA lets it inspect HTTPS requests, inject credentials from its vault, and enforce local policies before the upstream service sees the request.

For the operator OAuth flow, policy assignment screenshots, and copy-pasteable agent instructions, see [docs/portal-oauth-agent-guide.md](docs/portal-oauth-agent-guide.md). For the current security review and production acceptance gates, see [docs/security-review.md](docs/security-review.md).

## Run

```bash
make up
open http://localhost:3000
```

Google and X OAuth are optional in development. A provider is reported as configured only when its client ID, client secret, and redirect URI are all present. The canonical Compose file forwards `SERVERWARE_GOOGLE_OAUTH_CLIENT_ID`, `SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI`, `SERVERWARE_X_OAUTH_CLIENT_ID`, and `SERVERWARE_X_OAUTH_REDIRECT_URI` with empty/local defaults, so `make up` does not require provider credentials. For local-only setup, either provide the corresponding `SERVERWARE_*_OAUTH_CLIENT_SECRET` value or point `SERVERWARE_*_OAUTH_CLIENT_SECRET_FILE` at a host file; Compose mounts a supplied file read-only at a fixed `/run/secrets/...` container path.

OAuth client-secret files must be absolute-path, non-symlink regular files containing at most 4096 bytes of UTF-8 text, with mode `0400` or `0600`. Production additionally requires at least 16 secret bytes with eight distinct characters. The distroless production control plane runs explicitly as UID/GID `65532`; both host files must be owned by UID `65532`, and the production host preflight verifies owner, mode, type, and size before deployment. Run that preflight with enough host privilege to inspect the owner-only files. Production uses only `SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE` and `SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE`; `docker-compose.production.yml` requires both provider IDs and callbacks, mounts both host files read-only, and never forwards plaintext provider secret variables. Set the two production callbacks exactly to `${SERVERWARE_PUBLIC_URL}/api/oauth/callback/google` and `${SERVERWARE_PUBLIC_URL}/api/oauth/callback/x`.

Install the proxy CA through the attestation verifier before using the proxy:

```bash
export SERVERWARE_ADMIN_TOKEN=dev-admin-token
make install-ca
```

That target creates a one-use CA install session, verifies the nonce-bound runtime manifest, signed dev quote, signed policy bundle, policy signing key, rollback epoch, release channel, and CA SPKI, copies the CA to `.tmp/serverware-ca.pem`, then starts the Rust decision-gate proxy on `localhost:8080`. Point an isolated agent runtime at that proxy:

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
curl -X POST -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/demo/seed
curl --proxy "$HTTPS_PROXY" \
  --proxy-header 'X-Serverware-Agent: demo-agent' \
  --cacert .tmp/serverware-ca.pem \
  -H 'X-Serverware-Agent: demo-agent' \
  https://demo-upstream:8443/echo
```

For HTTPS, the proxy authenticates the `CONNECT` tunnel before it can inspect the encrypted upstream request. Identity headers therefore belong on both the proxy request (`--proxy-header`) and the provider request (`-H`) in this header-based demo. The production release gate rejects header-only, CIDR-only, legacy exact-secret, universal-CIDR, unbounded, expired, overlong, or reused principal identities. Its accepted source-bound, expiring, hashed bearer is explicitly an interim replayable control; cryptographically non-spoofable workload identity still requires outer mTLS and validated SPIFFE/SPIRE SVIDs.

For local debugging only, `/ca.pem` remains an authenticated endpoint and returns `X-Serverware-Debug-Only: true`. Production sets `SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED=0` and uses `/api/ca/install-sessions` plus `scripts/install_verified_ca.sh`, so the CA is only released through a short-lived nonce-bound verifier-mediated install session.

The Compose development token is `dev-admin-token`. In a real deployment set `SERVERWARE_ADMIN_TOKEN` to a high-entropy secret or use the OIDC/WebAuthn/RBAC flow in [goal.md](goal.md). The UI keeps a manually entered token only in browser `sessionStorage` and sends it as `X-Serverware-Admin-Token`; it is cleared when the tab session ends. Serverware also accepts pinned OIDC bearer JWTs for automation and now initiates browser OIDC Authorization Code login through `GET /api/auth/oidc/start`. Browser login uses S256 PKCE, one-use encrypted server-side state, a separate browser-binding cookie, and an OIDC nonce. The callback validates the returned ID token against the configured issuer, audience, pinned JWKS, allowed algorithms, nonce, subject, and role claim, then stores it in an `HttpOnly`/`SameSite=Lax` session cookie whose lifetime is capped by both token expiry and `SERVERWARE_OIDC_SESSION_TTL_SECONDS`. Cookie-authenticated unsafe control-plane requests require the double-submit CSRF cookie/header pair.

The Compose profile maps that token to `user:demo` with the demo admin roles so the demo NPM route can enforce its configured approver allowlist. Production requires browser OIDC plus WebAuthn MFA. In addition to the pinned issuer/audience/JWKS/role settings, configure `SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED=1`, HTTPS authorization and token endpoints on the issuer origin, `SERVERWARE_OIDC_CLIENT_ID`, an owner-only `SERVERWARE_OIDC_CLIENT_SECRET_FILE`, the exact `${SERVERWARE_PUBLIC_URL}/api/auth/oidc/callback` redirect, scopes including `openid`, and `client_secret_basic` or `client_secret_post`. The production config gate requires the client ID to match the configured audience. When `SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED=1`, credential, route, and policy-publish mutations require a WebAuthn assertion from `/api/control-plane/mutations/webauthn/options`; the challenge binds only the canonical mutation payload digest, not plaintext credential material. When `SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED=1`, those high-risk mutations first return `428 control_plane_approval_required`; a different authorized operator approves `/api/control-plane/approvals/{id}/approve`, and the original requester retries with `mfa.approvalId`.

Every supported control-plane launch path runs the same startup preflight. Both `python -m serverware.control_plane_runner` and direct ASGI launch such as `uvicorn serverware.app:app` validate TLS pairing, production TLS, internal service identity, WebAuthn/two-person requirements, setup receipt trust, key-unseal custody commands, an active signed policy, policy high-water state, database initialization, and CA material before runtime workers start. `make verify-control-plane-startup` proves the shared gate is invoked before the wrapper server and before FastAPI workers.

Run the core Docker end-to-end suite:

```bash
make e2e
```

Run the local proxy benchmark:

```bash
make bench
```

Run the broader Rust decision-gate verification matrix and benchmark:

```bash
make bench-gate-rs
```

`make e2e` covers the core control-plane/proxy workflow, credential-delivery outage and recovery behavior, WebAuthn, and key release. `make bench-gate-rs` is the larger release-candidate gate: it adds Rust forwarding and CONNECT tests, response contracts and streaming validators, response-proof capture, policy rollback protection, shared JIT/rate limits, attestation, audit, OAuth, production-readiness fixtures, provenance, image signing, and the measured decision benchmark.

Together, the Docker verification targets cover:

- CA-backed HTTPS interception through mitmproxy in the local prototype path and through the Rust decision gate in the production path.
- Fail-closed blocking for unknown routes.
- Principal access control using source CIDRs, required trusted identity headers, and hashed `Proxy-Authorization` bearer tokens bound to agent ID, source CIDR, and expiry.
- Bearer token injection from the encrypted credential vault.
- Portal OAuth login for Google and X/Twitter using Authorization Code with PKCE, one-use server-side state bound to a state-specific host-only `Secure`/`HttpOnly`/`SameSite=Lax` browser nonce cookie, encrypted OAuth token JSON storage, and audit records that omit auth codes and token material. Managed OAuth policies are restricted to canonical `Authorization: Bearer` injection from `access_token`; the broker and prototype runtime project leases/caches to an access-token-only JSON object, so refresh material never crosses into the data plane. State-specific cookies let independent provider flows finish out of order without weakening callback binding. WebAuthn mutation MFA runs before redirect when configured; production two-person authorization is deferred until callback identity discovery, when the encrypted token is staged and a second approval binds the exact provider subject/account, granted scopes, X app ID when applicable, expiry metadata, and token-source digest before atomic activation by the original requester. A durable Setup flow additionally binds a canonical setup ID and revision to the OAuth start, stores the setup ID only in the one-use server-side state, verifies the owner/provider/state-digest relationship at callback, and, only after a successful callback, binds either the exact active credential generation or the pending-activation row back to that same session before returning the browser to `/?setup=<id>`. Provider denial and callback validation, exchange, or persistence failure are terminal callback outcomes rendered as non-redirecting error pages. Pending activation must present the same setup ID and current CAS revision; the setup ID is not sent to the provider or copied into credential metadata.
- OAuth activation and disconnect have explicit provider-revocation states. Cancellation, expiry, exact-account approval denial, or any post-token-exchange validation/persistence failure retains encrypted revocation work until Google/X confirms revocation; bounded background reconciliation uses leased claims and exponential backoff, and expired activation rows no longer consume activation capacity. Active disconnect first marks the credential `revocation_pending`, immediately excludes it from normal reads, refresh, injection, and leases, and deletes local material only after provider revocation. A provider failure leaves `revocation_failed` encrypted material for retry. X refresh always queues the superseded access token and queues the old refresh token only when the provider rotates it; reconnect replaces the grant and queues both old tokens. Reconnect also binds the existing credential ID, version, provider, subject, and account and rejects mismatched or stale callback material. If the retirement queue is full, replacement and any approval consumption roll back together. Google reconnect is deliberately disconnect-then-connect because Google revocation invalidates the account/project grant rather than one logical token.
- `scripts/oauth_provider_simulator.py`, `scripts/test_oauth_http_flow.py`, and `scripts/test_portal_browser_oauth.py` exercise the complete Google/X lifecycle through the real FastAPI middleware and endpoints against a bounded local HTTPS authorization server. The HTTP fixture validates client authentication, exact redirect URI, PKCE S256, one-use codes, scopes, identity, refresh rotation, and revocation while checking that endpoint responses, audit records, pending rows, durable queues, and simulator observations contain no token values. The Playwright fixture additionally drives Chromium through both portal redirects, verifies callback-derived accounts, previews/stages/activates Gmail and X assignments, checks active policy bindings, removes OAuth cookies, scans browser/API/disk evidence for token values, and verifies desktop/mobile overflow. `make verify-oauth-credentials` runs both proofs after the focused OAuth regression suite.
- A typed policy bundle with strict JIT binding schema, bounded generic REST config, explicit success/error response profiles, safe response-header allowlists, response `allowedFields` redaction, and a stable policy hash exposed through quote-backed `/attestation`. Credential injection is a closed, type-specific contract: bearer, Basic, custom-header, query, and cookie modes admit only their applicable fields, require explicit Basic usernames or custom target names, and reject hop-by-hop, Serverware-internal, malformed, multiline, or incompatible targets at schema and semantic compilation. Generic REST `request.requiredHeaders` can require bounded, pattern-checked forwarded headers; the Stripe PaymentIntent example uses it to require a valid `Idempotency-Key` independently of principal identity headers.
- A shared credential-constraint layer for route-level quotas, operation allow/deny lists, query lookback windows, query caps, JSON/form body shape rules, response date-window validation, and bounded request-to-response field binding. Credential-bearing generic buffered JSON/form routes must bind the matching non-empty `jsonBody`/`formBody` allowlist; credential-bearing projected responses must have a non-empty bounded field projection in schema, Python, and Rust. The Stripe PaymentIntent template binds response `amount`, `currency`, and `payment_method` to the captured create operation: missing request sources deny before credential release, while a missing or mismatched success-response field becomes a synthetic `502` before any upstream response bytes are released. This is a Serverware policy contract, not a claim of live Stripe or PCI validation. See [docs/credential-constraints.md](docs/credential-constraints.md) and [policies/credential-limits.examples.json](policies/credential-limits.examples.json).
- A policy publish workflow where `/api/policy/candidate` validates and signs a candidate bundle with diff and dry-run decision results, `/api/policy/publish` enforces monotonic sequence/rollback rules, `policy_publisher` RBAC, optional WebAuthn mutation MFA, required two-person production approval, required production dry-runs, and staged-candidate review, and `/api/policy/canary/activate` performs an all-at-once activation only after the baseline observation/audit/denial gates pass. A staged candidate receives no proxy traffic; direct and staged-candidate activations are audited through `policy.published`.
- Persistent policy high-water records in the control plane and Rust gate, so a signed bundle with a stale sequence or rollback epoch is rejected across reloads and restarts; attestation and key release bind the active high-water digest.
- A Gmail adapter that forces `newer_than:30d`, tightens weaker existing age guards, caps `maxResults`, validates response `internalDate`, redacts responses to `allowedFields`, drops list items whose age is unproven, and only allows message reads for IDs observed from validated recent responses under the same scoped proof context.
- An X adapter that allows configured read operations, blocks write methods, denies unconfigured read operations, binds the route `appIds` policy to credential metadata, and redacts responses to policy-selected fields.
- An npm adapter that classifies operations before JIT, denies publish requests missing package/version/integrity fields, requires approval only for configured sensitive operations, and redacts publish responses before returning them to agents.
- JIT approval where the first publish request fails closed with `428`, approval requires a short-lived server-issued receipt for the exact redacted review digest, token-only or review-skipping approval fails with `412`, WebAuthn signs the receipt and creates a one-use request-digest-bound grant in the HA Postgres grant store, repeated approval fails with `409`, the Rust data plane consumes the grant through the shared control-plane endpoint, the retry succeeds, grant consumption is audited, and grant or review-receipt reuse fails closed.
- Break-glass grants through `POST /api/break-glass/grants` and `POST /v1/break-glass/grants`, requiring approver RBAC plus configured WebAuthn/two-person mutation controls, creating a normal digest-bound one-use JIT grant, and auditing `approval.break_glass_granted` with the human reason and no credential material.
- JIT denial records where approvers can attach an optional reason to `/api/approvals/{id}/deny`; the reason is stored on the approval, written to the hash-chained `approval.denied` audit event, and searchable through audit search.
- Redacted JIT approval review through `GET /api/approvals/{id}/review` and the portal approval-review panel, including principal/source identity, route, credential version, policy hash, normalized operation fields, body hash, redacted payload summary, risk flags, previous similar approvals, and exact retry semantics without exposing secrets. The endpoint hashes that document and issues a short-lived approver-bound receipt; WebAuthn and the final approval transaction must present the same unused receipt and digest. Both the portal and approval API fail closed if the active policy changed after the request was created.
- WebAuthn registration verifies packed/fido-u2f hardware attestation chains against signed, rollback-protected FIDO/YubiKey trust bundles before assigning a hardware class. A known YubiKey AAGUID without a trusted chain remains `unknown`.
- Non-public control plane APIs: `/ca.pem`, `/api/bootstrap`, credential CRUD, route CRUD, approvals, logs, audit, policy status, and demo seeding require the admin token.
- OIDC bearer-token and browser-session control-plane auth where RS256, ES256, or Ed25519 JWTs are verified against a pinned JWKS, issuer, audience, expiry, and role claim before FastAPI RBAC dependencies accept the identity. Browser authorization adds S256 PKCE, one-use state, browser and OIDC nonce binding, an `HttpOnly` session cookie, logout, and CSRF enforcement for cookie-authenticated mutations.
- Optional production mutation MFA where credential and route create/update/delete operations must carry a WebAuthn assertion over the canonical mutation payload digest before the audited change is accepted.
- Two-person control-plane approval where high-risk credential, route, policy-publish, RBAC/deprovisioning, and generated admin-token rotation changes are bound to a canonical payload digest, store only redacted request summaries, block self-approval, require a different authorized role owner, consume the approval once, and audit request, approval, consumption, and mutation evidence.
- Audited RBAC/bootstrap/token operations: `/api/bootstrap` writes a hash-chained `control_plane.bootstrap` event, `/api/rbac/role-bindings/{subject}` and `/api/rbac/deprovision` persist role-binding state and audit role changes/deprovisioning with WebAuthn mutation evidence when required, and `/api/control-plane/tokens/admin/rotate` rotates only generated-file admin tokens while auditing old/new token hashes without exposing the new token in the audit log.
- Signed policy bundles and a hash-chained audit log that can be checked with `GET /api/audit/verify`.
- Searchable audit review through `GET /api/audit/search` with filters for event type, actor, principal, route, policy hash, credential ID/version, approval ID, decision, attestation measurement, time window, and raw text.
- Envelope-encrypted credentials with per-credential DEKs, visible credential versions that advance when secret material or enforcement-relevant metadata changes, and JIT/audit records bound to the exact credential generation.
- One administrative credential trust domain per deployment. Operators with credential-management roles act on the shared inventory; credentials have no tenant ownership boundary, and credential visibility or mutation is not isolated by tenant.
- Recipient-bound, response-signed credential lease delivery from the control plane to the Rust data plane, with at most five-second in-memory leases, one-use nonces, atomic cache replacement, and no active plaintext credential-generation or credential-lease file transport.
- A Docker operator CA installer that runs the client verifier, checks attestation freshness, dev quote signature/claims, policy signature/digest, signing key hash, release channel, rollback epoch, and CA SPKI, then copies the verified CA into the agent runtime path.
- Agent enrollment packets from `POST /api/agents/enrollment`, with principal identity requirements, attestation pins, proxy environment variables, allow/deny canaries, and a deny-by-default Kubernetes NetworkPolicy plus iptables rules that only allow egress to configured Serverware proxy CIDRs. The control-plane origin is derived from `SERVERWARE_PUBLIC_URL`; a caller-supplied mismatch is rejected. Each signed packet carries a principal/policy-bound, expiring, one-use verifier capability for only the pinned policy and CA download, so the portal handoff never gives an agent the admin token. `scripts/generate_agent_enrollment.py --sign-setup-receipt` is the independent enrollment-verifier adapter: it rechecks the exact downloaded packet and live nonce-bound attestation, requires an owner-only Ed25519 signing key matching an expected SPKI ID, and emits a short-lived `serverware.enrollmentVerifierReceipt/v2` bound to the setup session, immutable assignment, enrollment capability, packet, nonce, and receipt trust profile.
- A durable Setup-session ledger whose table and storage operations support SQLite and PostgreSQL, exposed through `/api/setup/sessions`. Backend-neutral wording applies to that ledger layer only. It uses bounded TTL/capacity/retention, owner and current-assignee subject strings, named phase transitions, revision compare-and-swap, immutable backend bindings, exact route-policy and credential-generation commitments, duplicate evidence-digest rejection, and a claimable idempotent audit outbox. The list GET returns session summaries; the item GET returns one session with evidence and transition events. Owner/admin handoff records a bounded assignee subject string but does not verify subject existence at handoff, grant a role, reserve the run exclusively, or transfer OAuth ownership; API authentication and authorization are enforced when that subject acts. Server-side verification derives enrollment-consumption, activated-canary, and runtime response-release evidence from authoritative state and the audit chain rather than accepting those facts from the browser. The first-screen **Setup and Verify** UI creates and selects durable runs, resumes the exact run from `?setup=<id>` after reauthentication, and reconciles preview, stage, activation, enrollment, and verification actions through revision-checked endpoints. Committed backend bindings cannot be rebound; edits to still-enabled `created`-phase form fields may cause the next action to create a replacement run.
- Setup receipt trust and completion APIs are implemented. `GET /api/setup/receipt-trust` publishes the pinned role identities; `POST /api/setup/sessions/{id}/enrollment-receipt`, `/attestation-challenge`, `/hardware-verification`, and `/final-receipt` enforce current-assignee RBAC, revision CAS, strict closed-field JSON, canonical Ed25519 signatures, short validity windows, exact assignment/session/challenge/artifact bindings, three distinct configured keys and providers, and cross-session replay rejection. The challenge must be fresh when hardware evidence is accepted; after that durable acceptance, a fresh off-host final receipt may complete during the setup-session lifetime even if the original challenge deadline elapsed, so human approval cannot permanently strand the run. Shared approval transactions independently reject an expired setup session. The ledger retains canonical signed receipt documents and the exact submitted hardware-assurance and proxy-statement bytes, keeps security-bearing terminal sessions out of TTL pruning, and enters `completion_pending_audit` until the final receipt transition is durably hash-chain audited; configured WebAuthn mutation MFA and two-person approval protect finalization. This is implemented and fixture-tested code, not production assurance: independently operated hardware and final authorities, real receipts, a live cloud/TEE deployment, and end-to-end production execution remain outstanding.
- OAuth token exchanges reserve bounded recovery capacity and durably enter `exchange_in_flight` before provider contact. A timeout, ambiguous success response, or interrupted exchange becomes an operator-visible issuance uncertainty instead of being deleted. The reconciler reports it once without token material; clearing it requires confirmed provider-side app revocation, an evidence note, WebAuthn, and the production `credential.oauth.uncertain.resolve` two-person action. This prevents unknown grants from disappearing silently but does not make provider issuance and Serverware persistence atomic; measured exchange custody remains production work.
- A dev key-release gate that requires a signed quote authorizing `broker-kek` before credential DEK unwrap and `decision-gate-ca` before handing the CA private key to the Rust data plane. The `decision-gate-ca` release also requires the release-pinned Rust binary digest.
- External TEE/KMS provider hooks plus an AWS Nitro-compatible provider: `SERVERWARE_TEE_QUOTE_COMMAND`, `SERVERWARE_TEE_QUOTE_VERIFY_COMMAND`, and `SERVERWARE_KEY_RELEASE_COMMAND` let deployments plug in vendor quote verification and KMS/HSM policy without changing the policy engine. Docker verifies both the generic external-command interface and [scripts/aws_nitro_tee_provider.py](scripts/aws_nitro_tee_provider.py), including Nitro CBOR/COSE_Sign1 parsing, certificate-chain trust-root checks, PCR allowlisting, Serverware claim binding through Nitro `user_data`, a material-release policy for `broker-kek`/`decision-gate-ca`, and the production KMS/HSM command contract through [scripts/nitro_kms_fixture.py](scripts/nitro_kms_fixture.py).
- A Dockerized Rust data plane that verifies the Ed25519 policy signature against an attested control-plane trust root, denies unknown CONNECT authorities before leaf issuance, performs explicit CONNECT TLS interception, validates upstream TLS, injects credentials from exact principal/route/credential v2 leases, enforces status-specific response projection before release, and supports bounded credentialless or redacting stream modes. Policy admission rejects credential-bearing opaque/non-redacting response streams and credential-bearing mutating request streams. Every credential-bearing upstream release synchronously requires a durable control-plane acknowledgment of `data_plane.credential.release_started`; ordinary redacted telemetry remains bounded and asynchronous.
- Hardened Docker runtime settings verified by [scripts/test_container_hardening.sh](scripts/test_container_hardening.sh): application services run as UID/GID `10001`, Postgres runs as its non-root database user, all services use read-only root filesystems, drop all Linux capabilities, enable `no-new-privileges`, set PID and memory limits, disable core dumps, mount `/tmp` as `noexec,nosuid,nodev` tmpfs, and run under [security/seccomp/serverware-deny-dangerous.json](security/seccomp/serverware-deny-dangerous.json). The verifier confirms Docker seccomp filter mode, runtime core dump limits, and proves the profile is active by checking a denied `bpf` syscall returns the profile's custom errno.
- Signed local release provenance with Python/Rust SBOM summaries, a CycloneDX 1.5 SBOM at `.tmp/sbom.cdx.json`, source/config/image/hardening inventory, source tree digest, build recipe, published control-plane and data-plane attestations, provenance/source digest binding in both attestation endpoints, and a `release.provenance.v1` record with a verified inclusion proof in the signed transparency log. The source identity is `serverware.sourceTree/v2`: it commits to path, entry type, normalized executable mode, file bytes, symlink target, tracked deletions, all Git-tracked inputs, and relevant untracked source/build/config inputs while excluding Git metadata, caches/build outputs, and the runtime production secret env.
- Sigstore-compatible image-release bundle at `.tmp/image-signatures.json` with per-image in-toto statements for every Compose image, a cosign `sign-blob`/`verify-blob` adapter, required transparency evidence, provenance/SBOM/config/source bindings, image-signature digest binding in both attestation endpoints, and a `release.image_signatures.v1` transparency-log record with a verified inclusion proof.
- Control-plane responses carry `X-Serverware-Response-*` proof headers: a nonce-capable Ed25519 signature over method, path, query, status, response body hash, source tree digest, runtime manifest digest, policy hash, provenance digest, and image-signature digest. The response signing key ID is itself bound into `/attestation` quote claims.

## Policy Model

The proxy now requires a signed/hashed `PolicyBundle` at `/data/policy-bundle.json`, generated by the demo seed endpoint and modeled after [policies/demo.policy.json](policies/demo.policy.json). The current Python compiler validates the JSON Schema and adapter configs, verifies the Ed25519 signature, compiles path templates to regexes, computes a canonical policy hash over the unsigned payload, and keeps the hot-path route snapshot in memory.

Policy authors can submit a candidate bundle to `POST /api/policy/candidate` to receive a signed candidate, schema/semantic validation, a human-readable principal/credential/route diff, and dry-run decision results. Policy publishers can use `POST /api/policy/publish` with the legacy-named `activationMode: "canary"` to write a separate signed candidate at `SERVERWARE_POLICY_CANARY_BUNDLE`, persist staged state, and audit `policy.canary.started` without changing the active bundle. The staged candidate receives no proxy traffic. `GET /api/policy/canary/status` reports active-policy baseline audit events, denials, and p95 latency for affected routes since staging; candidate behavior is evaluated by schema/semantic checks and explicit dry-runs. `POST /api/policy/canary/activate` performs an all-at-once publish only if the observation window, audit evidence, and denial threshold pass, then records both `policy.canary.activated` and `policy.published`. Production sets `SERVERWARE_POLICY_CANARY_REQUIRED=1`; direct full publish remains available for local/dev paths when that flag is off.

The on-disk schema contract lives in:

- [schemas/policy-bundle.v1.schema.json](schemas/policy-bundle.v1.schema.json)
- [schemas/adapters/generic.rest.schema.json](schemas/adapters/generic.rest.schema.json)
- [schemas/adapters/gmail.v1.schema.json](schemas/adapters/gmail.v1.schema.json)
- [schemas/adapters/x.v2.schema.json](schemas/adapters/x.v2.schema.json)
- [schemas/adapters/npm.registry.schema.json](schemas/adapters/npm.registry.schema.json)

Every route binds:

- principals: source CIDR, trusted identity headers, hashed proxy bearer tokens with expiry/source binding in the Rust data plane, mTLS/SPIFFE later;
- endpoint allowlist: scheme, host, port, methods, and path templates;
- credential reference and injection mode;
- API adapter and typed config;
- shared request/response credential constraints;
- optional JIT approval policy.

Unknown hosts, paths, methods, principals, and missing policy bundles are blocked. The legacy SQLite `routes` table remains only for UI compatibility and state inspection.

Route `constraints` are the reusable layer for limits that should apply to any credential, independent of the upstream SDK. Implemented constraint types are `operationPolicy`, `rateLimit`, `queryDateWindow`, `queryNumericBounds`, `requestTimeWindow`, `jsonBody`, `formBody`, `responseDateWindow`, and `responseBinding`. The Python proxy and Rust data plane enforce the same typed rules before credential injection or response release; response date-window and response-binding checks run before redaction and release. The first `responseBinding` contract is intentionally bounded to buffered `generic.rest` form operations: policy admission proves each source is captured, required, and typed; each policy declares admitted `2xx` statuses and JSON media types; and object-only dotted response traversal prevents fields from separate array elements being combined. Missing operation fields deny before credential release, and response envelope, shape, or value mismatches fail with a synthetic `502` before upstream bytes are released to the agent. `jsonBody` allowlisting is structural, so unknown keys holding empty objects, empty arrays, or nested empty containers are denied rather than disappearing from scalar-leaf traversal. String, numeric, and array-specific field rules require explicit compatible types at schema and semantic admission. `requestTimeWindow` provides RFC3339 activation/expiry bounds plus UTC weekday and daily intervals. For an actual Docker/production proxy request, `rateLimit.store: "shared"` counters are reserved through the authenticated release-authority endpoint in the same metadata-store transaction as any one-use JIT grant. The separate rate-limit consume endpoint remains an authenticated compatibility and diagnostic surface, not the authoritative composed proxy path. The X one-post-per-day template uses the callback-verified provider subject as its stable account scope, so rotating a principal, credential ID, or credential version cannot reset the daily quota; missing account identity fails policy admission and runtime authorization closed. Typed static-credential templates also require the stored credential's operator-declared provider metadata to match the template, so an unrelated shape-compatible bearer cannot be selected for Stripe or npm. Unknown types or fields fail policy admission rather than being ignored.

Response policy is status-specific and fail closed. A `2xx` response must satisfy the route's success profile; a `4xx` or `5xx` response must satisfy an explicit nested `error` profile; redirects are rejected. Each profile has a required `maxBodyBytes`, a structured projection/redaction mode, and optional `allowedHeaders`. Only `Cache-Control`, `Content-Language`, `ETag`, `Last-Modified`, `Retry-After`, and `WWW-Authenticate` can be released when selected. Transport and state-bearing headers such as `Set-Cookie`, `Location`, hop-by-hop headers, upstream `Content-Length`, and upstream content encodings are removed and safe framing is rebuilt.

Credential-bearing routes cannot use `response.mode: "any"` or a non-redacting `response.mode: "stream"`; every JSON or structured-stream release requires a non-empty bounded projection. A credential-bearing buffered JSON/form mutation must also carry the matching typed body constraint with a non-empty field allowlist, and a credential-bearing mutating route cannot stream its request body because a malformed or truncated tail could otherwise be detected only after an upstream side effect. Credentialless routes may use bounded opaque streams, and structured streaming modes remain available when they redact to declared fields. Unsupported combinations are rejected when the signed policy is compiled and repeated as runtime defenses rather than being deferred to upstream behavior.

Policy publication is monotonic. The control plane persists the highest accepted `(policyId, sequence, rollbackEpoch, policyHash)` and exposes its digest in attestation. The Rust gate independently persists and checks its own high-water record before startup or hot reload, retaining the last good snapshot when a signed replay or rollback is presented.

Principal `proxyAuthorization` rules can be either a legacy exact string for compatibility or a structured bearer-token constraint:

```json
{
  "scheme": "Bearer",
  "tokenId": "agent-sidecar-token",
  "tokenSha256": "sha256:...",
  "sourceCidrs": ["127.0.0.0/8", "172.16.0.0/12"],
  "expiresAtEpochMs": 4102444800000
}
```

The token itself is never stored in the policy bundle. The Rust CONNECT preflight validates the token before leaf issuance, carries the authenticated principal into the intercepted request, strips `Proxy-Authorization` before upstream forwarding, and denies missing, expired, wrong-source, or wrong-token requests as `client_principal_denied`.

Policy signing uses `/data/policy-signing-ed25519.pem` in the Docker prototype. The public key hash and signature are exposed through `/attestation`, `/api/bootstrap`, and `/api/policy` so agents or operators can pin the key and detect policy replacement. The Rust Docker data plane does not trust a public-key file mount directly: it fetches the policy trust root from the control-plane `/attestation` endpoint through `SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL`, verifies the dev quote signature, nonce, optional quote-signing key pin, policy signing-key hash, and attested policy digest, then verifies the local signed bundle against that attested key. Unsigned or invalid bundles fail closed: `/healthz` stays alive, but the proxy has no usable policy snapshot. Stale bundles that no longer satisfy the active schema are treated as policy-load failures instead of uncaught control-plane exceptions.

To verify a live server against this exact source tree and a concrete response, run:

```bash
python scripts/verify_codebase_attestation.py \
  --base http://localhost:3000 \
  --admin-token "$SERVERWARE_ADMIN_TOKEN"
```

The verifier checks the attestation quote, the published release provenance signature, the local source tree digest, the attested source/provenance/image-signature digests, and a nonce-bound response signature from the server it contacted.

## Secret Broker

Credential rows use envelope encryption. Each secret update creates a fresh random data-encryption key, encrypts the secret under that DEK, then wraps the DEK under the prototype KEK from `/data/master.key` or `SERVERWARE_MASTER_KEY`. In the default Docker profile, that KEK is usable only after the key-release gate verifies a signed quote authorizing `broker-kek`; `secret_kek_id` is reported with the `attested-dev-kek:` prefix. The API exposes non-secret broker metadata such as `credential_version`, `secret_kek_id`, and `secret_updated_at`, but never returns plaintext secrets from list/bootstrap endpoints.

`credential_version` advances when either the stored secret or its metadata changes because metadata participates in adapter enforcement and injection. JIT approval requests, one-use grants, canonical request digests, leases, and proxy audit events include that version, so an approval for `cred-demo-bearer` version `7` cannot authorize the same request after a secret rotation or metadata-only update produces version `8`.

The active Python, Rust, and Docker paths no longer produce or consume `/data/credential-generations.json` or plaintext `/data/credential-leases.json`. Control-plane startup unlinks those names and their `.tmp` variants. That cleanup cannot sanitize old snapshots, volume backups, image layers, or copied artifacts; every credential ever published by an older version through either plaintext path must be rotated.

The Rust gate pulls one exact credential lease from `POST /api/data-plane/credential-leases`. A v2 request is bound to the principal, route, credential, active policy, and measured executable; unknown fields fail validation:

```json
{
  "apiVersion": "serverware.credentialLeaseRequest/v2",
  "principalId": "agent:demo",
  "routeId": "demo.echo",
  "credentialId": "cred-demo-bearer",
  "recipientPublicKey": "<unpadded-base64url raw 32-byte X25519 public key>",
  "recipientKeyId": "sha256:<sha256 of those exact 32 bytes>",
  "recipientNonce": "<unpadded-base64url 32-byte one-use nonce>",
  "policyHash": "sha256:<active signed policy hash>",
  "dataPlaneBinaryDigest": "sha256:<configured measured Rust executable>",
  "maxTtlSeconds": 5
}
```

The caller sends `X-Serverware-Data-Plane-Token` and a fresh `X-Serverware-Response-Nonce`. The control plane verifies the exact principal is assigned to the active route, the exact credential is assigned to that route, the policy and binary digests match, the nonce is one-use, the X25519 key ID is correct, and recipient evidence is valid when required. It then returns exactly that credential, not a snapshot of every active credential. The Rust client requests a five-second TTL; accepted requests are capped to 1-10 seconds and by the configured broker TTL.

Consumed recipient nonces remain tombstoned for 24 hours. A read-only duplicate lookup avoids repeating expensive verification, but a new nonce consumes replay capacity only after recipient attestation succeeds; the final reservation is still atomic, so concurrent duplicates fail closed. The shared metadata store keeps a transactionally maintained count rather than scanning the replay table on every lease, and `SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES` sets a bounded 10,000-10,000,000 entry capacity with a 1,000,000 default. Capacity exhaustion fails closed with `503`; expiry cleanup releases capacity without accepting a replay inside the retention window.

The response is `serverware.credentialLeaseEnvelope/v2` with `X25519-HKDF-SHA256-AES-256-GCM`. Its authenticated cleartext and encrypted `serverware.credentialLeaseSet/v2` repeat the recipient, nonce, policy, binary, principal, route, credential, issue-time, and expiry bindings. The attested Ed25519 response key signs the HTTP request/response context. Rust verifies the signature and every duplicated binding before accepting the one matching credential into a generation-scoped, monotonic `Zeroizing` cache; lower versions and same-version secret or metadata changes are rejected.

Rust keeps leased secrets only in memory with monotonic expiry no later than the signed wall-clock expiry. A bounded worker pool polls warm, near-expiry scopes every `0.25` seconds in Docker and renews them in the background. This is not fully off-path acquisition: the first request for a scope, or a request after expiry, may synchronously fetch its lease. The cache and renewal queue are bounded; a valid cached lease survives a failed refresh only until expiry. Policy reload clears leases and grants, credential rotation replaces only a lower-version scoped entry, and every final upstream send rechecks that the selected lease is still current and unexpired.

Development Docker uses a software X25519 recipient. This removes plaintext credential delivery from disk and the lease HTTP response body, but host root can still inspect Rust process memory. Production requires the recipient-attestation generator and verifier command pair; their v2 statements include the recipient and all three scope fields. These command contracts remain integration points, not proof of a real Nitro deployment.

`serverware-custody-runtime` is a standalone development protocol slice for moving response-proof signing behind a bounded typed interface. Its UDS transport supports only `hello/v1` and `responseProof.sign/v1`, returns public material and signatures only, and reports `hardwareProof:false`. The decision gate does not use it yet. It does not provide vsock, EIF/PCR, quote, peer-authentication, or enclave custody evidence, and its process-held ephemeral key remains inspectable by host root.

The production-intended broker-KEK adapter path is concrete: `aws_kms_recipient_release.py` sends the signed Nitro document to AWS KMS, rejects any plaintext response, and retains `CiphertextForRecipient` plus its attestation, recipient-key, KMS-key, and source-ciphertext bindings. The image-bundled `aws_nitro_kms_unseal.py` validates that nested release receipt, passes only recipient ciphertext to `SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE`, and returns the 32-byte KEK over a bounded pipe without a plaintext temp file. The Nitro document's RSA public-key digest is persisted in key-release state, so a new enclave recipient key forces a fresh KMS release. This is a pre-enclave integration path; production acceptance still requires running it inside real Nitro hardware and parent-host observation proving only ciphertext and digests are visible.

The control-plane and Rust runtime manifests declare `scoped-recipient-bound-pull/v2`, recipient-attestation requirements, and renewal/cache bounds. Run `make verify-credential-lease-delivery` for exact-scope, signature, independent-decrypt, replay, tamper/wrong-binding, rotation/deletion, metadata-version, verifier, and plaintext-absence coverage. `make e2e` additionally stops the broker, proves leases expire to `503`, restarts it, and proves acquisition recovers.

## Gmail Age Proof

The Gmail adapter treats request rewriting as a hint and response validation as the authority. It adds or tightens `newer_than:30d` on list queries, but a message ID only becomes readable after Serverware sees a trusted `internalDate` that satisfies the route policy.

Validated IDs are cached in memory with this full proof scope:

- route ID;
- principal ID;
- credential ID and `credential_version`;
- policy hash;
- Gmail user path parameter;
- day-bucketed cutoff epoch for the configured max age;
- message ID.

That means a list result for one agent, Gmail user, policy hash, cutoff window, or credential generation cannot authorize a direct body read in another context. If a Gmail list item omits `internalDate`, Serverware drops the entire item before release and does not disclose its ID or insert it into the proof cache. A direct `GET /gmail/v1/users/{user}/messages/{id}` therefore fails with `403` until a later allowed list response supplies a trusted in-window `internalDate`. The configured bounded metadata-fetch workflow is not implemented yet. After validation, `response.allowedFields` is enforced on list and direct message JSON so upstream echo fields, credentials, raw bodies, and non-allowlisted Gmail fields are removed before release.

## JIT Grants

JIT approval is server-side. The agent never receives a token. For a sensitive request, Serverware computes a canonical request object containing principal, route, credential version, policy hash, method, authority, path, selected headers, body hash, and adapter operation fields. It hashes that object into `request_digest` and `operation_digest`. `POST /v1/decide` evaluates this object as a non-mutating preview; the first actual proxied request sends the complete canonical object to the control-plane release authority.

If no matching grant exists, Serverware returns:

```json
{"error":"serverware_approval_required","approval_id":"...","request_digest":"sha256:..."}
```

When that first real request has no matching grant, the release authority verifies every route, identity, credential-version, policy, request, and operation binding. It leaves no quota or grant reservation behind, atomically creates or reuses the exact pending approval, and returns `428` with its bounded status, expiry, creation flag, and retry interval. Approving is a separate atomic pending-to-approved transition. It rejects expired or already-decided approvals, and the approval row plus its digest-bound grant are committed in one metadata-store transaction; a grant insertion failure leaves the approval pending and no orphan grant. PostgreSQL issuance fails closed unless the metadata and grant stores use the same DSN/transaction.

The identical approved retry reserves the one-use grant and every shared quota in one release-authority transaction. Immediately before network dispatch, the data plane advances that exact attempt from `reserved` to `dispatching`; completion records `forwarded`, refunds a proven `not_forwarded` attempt, or conservatively commits an `unknown` post-dispatch result as indeterminate. An attempt ID, flow ID, and binding digest correlate every transition. Credential injection and upstream contact cannot occur without a live matching reservation. A successful grant defaults to `maxUses: 1`, so a later identical request requires a fresh approval.

The demo NPM policy now sets `jit.approvers.authn.webauthnRequired: true`. Approval requires:

- the caller has the `approver` role;
- the caller user ID is listed in `jit.approvers.users`;
- the caller signs a WebAuthn assertion over a server-issued challenge bound to approval ID, request digest, operation digest, credential ref/version, policy hash, grant TTL/max uses, display digest, and expiry;
- the registered authenticator class is allowed by policy.

For policies with `requireHardwareAttestation: true`, authenticator class is not inferred from AAGUID alone. Registration accepts `packed`, `fido-u2f`, and `none` attestation formats, but only a valid attestation signature and certificate chain anchored in the active signed WebAuthn trust bundle can set enrollment trust and classify a credential as `yubikey` or `hardware`. Every assertion rechecks the stored root digest, AAGUID restriction, and class against the current valid bundle. A withdrawn root therefore removes the credential's effective hardware class immediately; missing, self, untrusted, withdrawn, or unsupported attestation cannot satisfy hardware-only approval policies. Production additionally requires hardware attestation and limits mutation authenticators to `yubikey,hardware`.

WebAuthn trust roots are packaged as signed bundles validated by [schemas/webauthn-trust-bundle.v1.schema.json](schemas/webauthn-trust-bundle.v1.schema.json). The bundle carries sequence, rollback epoch, validity window, root certificates, allowed AAGUIDs, and authenticator class. `SERVERWARE_WEBAUTHN_TRUST_BUNDLE` points to the active bundle; `SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE` stores the highest accepted sequence/epoch and digest. Different content at the same epoch/sequence and any lower sequence are rejected. A signed bundle with an empty `roots` array is the emergency withdraw-all operation. Publishing through the API permanently soft-revokes every affected active credential, retains actor/reason/source and historical enrollment evidence, and cancels still-active JIT grants authorized by that credential. Re-adding a root does not reactivate those rows; the operator must complete a fresh, separately authorized registration with a new credential ID. Legacy `SERVERWARE_WEBAUTHN_TRUST_ROOTS` PEM loading remains only as a development fallback when no signed bundle exists.

Credential IDs are insert-only, including after revocation. The portal lists active and revoked passkeys without returning their COSE public keys, development private material, or raw credential IDs. Revocation requires a reason and uses the same payload-digest-bound mutation WebAuthn and production two-person controls as registration. Revoking the last active credential does not reopen first-enrollment bootstrap; it intentionally leaves that operator unable to perform passkey-protected actions until an administrator executes the deployment's recovery procedure.

Useful trust endpoints:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/webauthn/trust/status

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bundle":{...signed WebAuthnTrustBundle...},"reason":"retire compromised FIDO root","mfa":{...}}' \
  http://localhost:3000/api/webauthn/trust/publish

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  'http://localhost:3000/api/webauthn/credentials?includeRevoked=true'

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"lost authenticator","mfa":{...}}' \
  http://localhost:3000/api/webauthn/credentials/$CREDENTIAL_RECORD_ID/revoke
```

Useful endpoints:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"YubiKey"}' \
  http://localhost:3000/api/webauthn/register/options

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/webauthn/options
```

Docker e2e enables `SERVERWARE_DEV_AUTHENTICATOR=1` and uses `/api/dev/webauthn/*` only to produce a deterministic software assertion. That path is disabled unless the env var is explicitly set and is not a production approval mechanism.

## Attestation

The prototype exposes a dev-signed quote attestation shape:

```bash
curl 'http://localhost:3000/attestation?nonce=test'
```

It returns runtime manifest digest, policy bundle digest, policy signature, policy signing public key, CA SPKI hash, release-pinned data-plane binary digest, rollback epoch, release channel, release provenance digest, image-signature bundle digest when present, and the caller nonce. The default `quote` is an Ed25519-signed development quote whose claims bind those same values plus authorized key-release materials: `broker-kek` and `decision-gate-ca`. Setting `SERVERWARE_TEE_QUOTE_PROVIDER=external-command` switches quote production and verification to `SERVERWARE_TEE_QUOTE_COMMAND` and `SERVERWARE_TEE_QUOTE_VERIFY_COMMAND`; setting `SERVERWARE_KEY_RELEASE_COMMAND` adds an external KMS/HSM release policy gate after claim validation. For the AWS Nitro path, use `SERVERWARE_TEE_QUOTE_PROVIDER=aws-nitro-enclaves`, `SERVERWARE_TEE_PLATFORM=aws-nitro`, and `scripts/aws_nitro_tee_provider.py quote|verify|release`; production deployments set `SERVERWARE_NITRO_ATTESTATION_COMMAND` to a Nitro NSM helper that returns a fresh attestation document for the exact Serverware `user_data`, pin the Nitro trust root and PCR allowlist, and require `SERVERWARE_NITRO_KMS_RELEASE_COMMAND`, while Docker uses fixture roots and [scripts/nitro_attestation_fixture.py](scripts/nitro_attestation_fixture.py) plus [scripts/nitro_kms_fixture.py](scripts/nitro_kms_fixture.py) to exercise the same verifier and command contracts.

The verifier in [scripts/verify_attestation.py](scripts/verify_attestation.py) implements the client trust flow:

1. create `/api/ca/install-sessions` to get a one-use install token and nonce;
2. request `/attestation` with that install-session nonce;
3. verify the nonce and runtime manifest digest;
4. verify the quote signature or call the configured external TEE verifier, then check claim parity with the attestation document;
5. verify the policy signing public key hash;
6. fetch the signed policy bundle through `/api/policy`;
7. verify the Ed25519 policy signature and canonical policy hash;
8. verify the attested policy digest and policy signature match the bundle;
9. fetch the install-session CA URL with `X-Serverware-CA-Install-Token`, verify its SPKI hash matches attestation, then write the CA.

The normal Docker operator wrapper is [scripts/install_verified_ca.sh](scripts/install_verified_ca.sh):

```bash
SERVERWARE_CA_OUT=.tmp/serverware-ca.pem ./scripts/install_verified_ca.sh
```

It runs the verifier in the Serverware container, copies only the verified CA out to the host path, writes `.tmp/attestation-verify.json`, and fails closed if any attestation or policy check fails. Run the verifier directly inside the container when debugging the verifier itself:

```bash
docker compose exec -T serverware python scripts/verify_attestation.py \
  --base http://localhost:3000 \
  --admin-token "$SERVERWARE_ADMIN_TOKEN" \
  --ca-out /tmp/serverware-verified-ca.pem
```

The verifier accepts `--expected-policy-key-hash`, `--expected-rollback-epoch`, and `--tee-verify-command` for pinning and external quote verification. The Nitro verifier rejects unsigned or stale documents, wrong trust roots, PCR mismatches, debug PCRs unless explicitly enabled, and claims that are not bound into the signed Nitro document's `user_data`.

Generate an agent enrollment packet after policy publish and CA verification:

```bash
python3 scripts/generate_agent_enrollment.py \
  --principal-id agent:demo \
  --proxy-url http://10.42.0.10:8080 \
  --proxy-egress-cidr 10.42.0.10/32 \
  --selector app=demo-agent
```

The packet contains no plaintext credentials or proxy bearer tokens. It gives the agent runtime the proxy/CA environment, policy and attestation pins, route canaries, and a deny-by-default egress policy. Every packet is bound to a caller-generated base64url nonce, expires after 30-900 seconds, and carries an Ed25519 signature from the response key pinned by attestation. Verification mode requires an independently precommitted raw-file SHA-256, expected principal, and expected nonce; the digest commits the proxy URLs, egress CIDRs, selectors, and every attestation pin. The CLI then fetches fresh attestation with that nonce, verifies the quote, runtime manifest, measurement pins, expiry, packet digest, and signature, and adds a local `verificationReceipt`. Production readiness requires verified enrollment packets and agent egress enforcement before credentials are enabled.

The control plane exposes `GET /api/key-release/status` and admin-only `POST /api/key-release/verify`. The verifier checks quote signature, material authorization, policy digest, CA SPKI, data-plane binary digest, rollback epoch, release channel, and optional provenance digest, then records key-release events in the audit chain. Docker enables this gate by default for the broker KEK and the Rust data-plane CA private-key handoff.

The Rust data-plane gate exposes agent proxy traffic and `GET /attestation?nonce=...` on port `9090`. Its direct `POST /v1/decide` and `POST /v1/grants` management API is isolated on port `9091`, requires `X-Serverware-Data-Plane-Token` with the high-entropy `SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN`, and rejects unauthorized requests from the parsed request head without waiting for or reading the remaining declared body. Credential leases, audit ingestion, JIT grant consumption, shared rate-limit consumption, and Rust management each use a different required token; production rejects missing, weak, or equal values. Audit callers cannot submit `actor_id` or `actorId`; the control plane derives the stored data-plane actor from its configured instance identity. These remain scoped bearer credentials, not authenticated SVIDs. The header parser may retain only bytes already coalesced into its bounded final header read. Production publishes only proxy port `9090` as host port `8080`; the management listener is reachable only on the internal Compose network. Development additionally maps it to loopback-only `127.0.0.1:9091`. Missing or incorrect tokens receive `401`, management paths on the public listener receive `404`, proxy requests on the management listener receive `404`, and all Serverware service-auth headers are stripped from forwarded requests and response-proof request bindings. [scripts/verify_decision_gate_attestation.py](scripts/verify_decision_gate_attestation.py) verifies nonce binding, runtime manifest digest, SHA-256 digest of the running gate executable, policy hash/signing-key consistency with the control plane, the control-plane quote's pinned data-plane digest, image-signature digest parity, and the declared zero SQLite/filesystem hot path. When `SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID` or `SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID` is set, the Rust gate refuses to boot unless the quote signer and signed bundle key match those pins. `make bench-gate-rs` verifies listener isolation, management authentication, attestation, startup failure for tampered policy signatures, wrong policy-key pins, and wrong control-plane quote-key pins, raw CONNECT preflight allow/deny behavior, CONNECT MITM with dynamic leaf issuance, absolute-form HTTPS forwarding with credential injection, policy-declared request-body streaming, binary response streaming, JSONL, JSON-array, JSON-SSE, nested JSON, form-urlencoded, and CSV request/response streaming redaction, Gmail response validation/redaction, shared JIT grant consumption, dev/external-command/Nitro key release for `broker-kek`/`decision-gate-ca`, release provenance generation, image-release signing, and latency.

[scripts/generate_release_provenance.py](scripts/generate_release_provenance.py) creates `.tmp/release-provenance.json`, signs the canonical provenance with a local dev Ed25519 release key, writes it into `/data/release-provenance.json`, verifies both attestation endpoints expose the provenance digest, and anchors a `release.provenance.v1` record in the signed transparency log. [scripts/sign_release_images.py](scripts/sign_release_images.py) creates `.tmp/image-signatures.json`, signs per-image in-toto statements through `SERVERWARE_IMAGE_SIGN_COMMAND`, verifies them through `SERVERWARE_IMAGE_VERIFY_COMMAND`, requires the verifier to bind the same statement digest/key provider/transparency evidence, requires Sigstore-style transparency evidence when `SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1`, writes the bundle into `/data/image-signatures.json`, verifies both attestation endpoints expose the image-signature digest, and anchors a `release.image_signatures.v1` record:

```bash
make release-provenance
make image-signatures
```

The provenance includes the `serverware.sourceTree/v2` manifest and digest, Python requirements and Rust `Cargo.lock` SBOM entries, a CycloneDX 1.5 SBOM digest, Compose config digest, Docker image IDs, container hardening inventory, pre/post-publish attestations, audit/transparency-log state, the transparency-log append response, and a verified inclusion proof for the release record. The source manifest is deterministic with or without Git; in a checkout it includes every tracked entry even when an opaque tracked input is deleted, and outside Git it falls back to the relevant filesystem source/build/config set. The image-signature bundle binds each image statement to that provenance digest, SBOM digest, Compose config digest, source tree digest, and transparency inclusion proof. Docker exercises the production cosign command path through [scripts/cosign_sigstore.py](scripts/cosign_sigstore.py) and the local [scripts/cosign_fixture.py](scripts/cosign_fixture.py); the adapter signs the exact canonical statement bytes, and the completion verifier rejects Sigstore bundles whose embedded message digest, signature, Rekor log entry, or inclusion proof differs from the exposed signing response. Production release channels must set `SERVERWARE_COSIGN_BINARY=cosign`, a KMS/HSM-backed `SERVERWARE_COSIGN_KEY`, `SERVERWARE_COSIGN_KEY_ID` equal to the SHA-256 SPKI digest of the pinned ECDSA/RSA key in `SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY`, and `SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID` for the expected Sigstore transparency log. Keyless Fulcio identity verification is not yet implemented by release completion, so production readiness rejects keyless-only and mixed key/keyless configurations.

The `audit-anchor` service also supports external checkpoint publication through `SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND`. Docker sets this to [scripts/transparency_checkpoint.py](scripts/transparency_checkpoint.py) in fixture mode with `SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED=1`, so every local signed tree head must be published to a managed-log fixture before the append is accepted. The same adapter can publish to an HTTPS managed-log endpoint with `SERVERWARE_TRANSPARENCY_LOG_URL`; it sends a canonical `serverware.externalTransparencyCheckpointRequest/v1` document, requires the response to bind the checkpoint digest, request digest, tree size, tree head, provider, and log ID, and verifies an Ed25519 signed receipt by default. `make verify-transparency-checkpoint` covers the fixture path, TLS fail-closed behavior, digest mismatch rejection, missing receipt rejection, and signed HTTP managed-log success path. Production release channels can either point that URL at a public/managed log implementing this receipt contract or replace the command with a log-specific publisher that returns the same normalized checkpoint response.

The default Compose file applies the custom seccomp profile. Linux hosts that support AppArmor can also install the checked-in AppArmor profile and run Compose with the override:

```bash
make install-apparmor
make verify-apparmor-contract
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d --build
make verify-apparmor-runtime
```

`verify-apparmor-contract` checks the profile and Compose override everywhere, including Docker Desktop. `verify-apparmor-runtime` is intentionally Linux-only: it checks that the profile is loaded, starts the full override stack, verifies each container's Docker `security_opt`, reads `/proc/self/attr/current` inside every service, and proves AppArmor denies a normally readable `/proc/sys/kernel/hostname` probe.

Production release channels should run the fail-closed readiness gate before publishing a production tag:

```bash
cp ops/production-readiness.env.example ops/production-readiness.env
make run-production-readiness \
  PRODUCTION_POLICY_BUNDLE=/evidence/policy-bundle.json \
  PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY=/evidence/policy-signing.pub.pem \
  PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT=/evidence/policy-identity.json \
  POLICY_ACTIVATION_VERIFICATION_OUT=/evidence/policy-activation-verification.json \
  POLICY_ACTIVATION_VERIFICATION_SIGNATURE=/evidence/policy-activation-verification.signature.json \
  POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY=/evidence/release-verifier.pub.pem \
  REPRODUCIBLE_BUILD_VERIFICATION_OUT=/evidence/reproducible-build-verification.json \
  REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE=/evidence/reproducible-build-verification.signature.json \
  REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY=/evidence/release-verifier.pub.pem
```

The runner loads `ops/production-readiness.env` without shell evaluation, rejects placeholder values such as `CHANGE_ME`, `${...}`, or `<...>`, keeps environment values out of dry-run output, then runs the config gate, live claims generation, redacted Nitro/KMS evidence collection, final live readiness gate, and release-proof verification in sequence. The verifier requires the persisted production-policy identity report, externally signed activation and independent-build verification reports, `.tmp/production-readiness-config.json`, `.tmp/production-host-preflight.json`, `.tmp/production-images-build.json`, `.tmp/production-images.env`, `.tmp/production-images-published.json`, `.tmp/release-provenance-summary.json`, `.tmp/release-provenance.json`, `.tmp/image-signatures-summary.json`, `.tmp/image-signatures.json`, `.tmp/decision-gate-rs-bench.json`, the current production readiness env, and the current KMS materials file to exist and agree with the live readiness evidence; it recomputes the current `serverware.sourceTree/v2` digest before accepting release provenance, rechecks that the current host matches preflight, and rejects config, KMS, image, signature, transparency, benchmark, or response-proof drift. It writes a `serverware.completionProof/v3` document to `.tmp/serverware-completion-proof.json`. When hardware assurance is supplied, the verifier requires exactly one caller-provided expected challenge, either the raw canonical unpadded base64url nonce or its lowercase `sha256:` digest, and constant-time checks it against the challenge in the independently signed statement. Ed25519 signatures must also use canonical unpadded base64url and decode to exactly 64 bytes. Readiness mode rejects hardware/final inputs and never claims final completion. Final mode requires the complete hardware tuple plus `serverware.finalChallengeReceipt/v1`, signed by a separately pinned off-host authority after atomically consuming that challenge and binding the exact completion, release, host, hardware-verifier, and proxy-response identities. The hashed production env independently pins the expected SHA-256 SPKI identity for both final trust roots; each loaded key must match its expected identity, and the hardware-verifier and challenge-authority keys must differ. The hardware document, hardware key, receipt, and authority key are each opened once with symlink rejection, regular-file and size checks, then parsed, verified, and reported from the same immutable bytes. The completion identity committed by the v1 receipt includes both the exact hardware-assurance document digest and the canonical signed-statement digest, so the receipt version remains v1 without weakening the new binding. Configure the hardware evidence path, verifier key path and ID, exactly one challenge form, receipt path, authority key path and ID, and authority provider shown in `ops/production-readiness.env.example`; set `SERVERWARE_COMPLETION_VERIFICATION_MODE=final` in that same hashed env file, then run `make run-production-readiness PRODUCTION_COMPLETION_VERIFICATION_MODE=final`. The runner requires the file and command mode selections to match. A caller-selected local file ledger is explicitly insufficient because production host root could delete, replace, or roll it back. Without separately trusted, fresh hardware evidence, the signed consumption receipt, an unbypassed current-host consistency check, pinned provenance/Sigstore/Rekor/external-checkpoint roots, and actual production TEE evidence, the document is intentionally `kind: ServerwarePreEnclaveReadiness`, `completion_status: pre-enclave-readiness`, `final_completion: false`, and `hardware_proof: false`.

All configured production trust roles must have unique SPKI identities: provenance, Sigstore, Rekor, external checkpoint, hardware verifier, and final challenge authority. Final completion rechecks this separation independently of readiness evidence.

Setup-receipt readiness validates all configured setup limits, three distinct Ed25519 setup roles/providers and SPKI identities, separation from every release-signing trust root, challenge TTL, setup roles, and finalization MFA/two-person policy; production Compose applies those limits and mounts the public keys read-only. In final mode the standalone gate also strictly parses and cryptographically verifies the complete hardware-assurance and final-authority statements, their expected key IDs, provider, challenge, release, hardware-verifier, and current-host bindings. It still does not run an independent authority, submit a live enrollment/hardware/final receipt chain, or prove cloud/TEE execution. The equivalent individual commands remain:

```bash
make verify-production-config
make generate-production-readiness-claims
make collect-nitro-kms-evidence
make verify-production-readiness
# run-production-readiness invokes the v3 completion-proof verifier with every
# policy, activation, build, KMS, image, quote, and response-proof binding;
# without independent hardware assurance, its result remains pre-enclave.
```

`verify-production-config` rejects dev/fixture settings and checks that control-plane admin auth uses an explicit high-entropy token, OIDC bearer verification and browser login are enabled with pinned issuer/audience/JWKS/role claim, HTTPS authorization/token endpoints on the issuer origin, an exact HTTPS browser callback, bounded unique scopes including `openid`, an authenticated token endpoint client, and a bounded owner-only client-secret file. It also requires complete Google and X providers, exact provider callbacks on `SERVERWARE_PUBLIC_URL`, OAuth state and pending-credential TTLs within their bounds, bounded pending capacity, and `credential.oauth.activate` in the two-person action set. The mandatory production host preflight requires all three OAuth/OIDC client-secret files to be owned by the explicit distroless control-plane UID `65532`, so a host-readable but container-unreadable bind mount cannot pass deployment. It also checks the production WebAuthn origin, disables direct CA download in favor of bounded install sessions, requires hardware-attested mutation WebAuthn restricted to `yubikey,hardware`, and requires two-person approval for high-risk credential/route/policy/RBAC/token/break-glass mutations plus WebAuthn registration, revocation, and trust publication. It requires policy-publish dry-run decision tests and policy canary activation with a positive observation window, audit evidence, and zero-denial threshold; Nitro NSM attestation, KMS/HSM release, stable public-key cosign/Sigstore identity plus pinned Rekor log ID, external transparency checkpointing, AppArmor, Postgres-backed metadata/grant/audit stores, the shared rate-limit consume endpoint, required agent enrollment plus egress enforcement, and immutable production image refs with required no-shell verification are configured for production. `verify-production-readiness` additionally signs and verifies a live Sigstore probe with required transparency evidence, expected key identity, and expected Rekor log ID, publishes and verifies an external transparency checkpoint probe, checks the metadata/grant/audit Postgres stores are reachable with the required tables, runs live Nitro quote/release probes from `SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON` or `--claims-file`, verifies the configured production image root filesystems contain no shell binaries, and requires the Linux AppArmor runtime probe to pass.

`make generate-production-readiness-claims` verifies `/attestation`, the runtime manifest digest, the quote-bound claim set, and the signed policy bundle from `/api/policy`, then writes `.tmp/production-readiness-claims.json` for the live Nitro/KMS probes. Production claims and `SERVERWARE_NITRO_ALLOWED_MATERIALS` must authorize exactly `broker-kek` and `decision-gate-ca`; extra material names fail closed. `make collect-nitro-kms-evidence` uses that claims file when present and writes `.tmp/nitro-kms-evidence.json` on both pass and fail; successful evidence proves a fresh Nitro NSM attestation command, quote verification, PCR/root/user-data binding, and KMS/HSM release decisions for both authorized materials, but is still classified `pre-enclave-readiness` with `hardware_proof:false`. Raw attestation documents, private keys, signatures, and plaintext material are omitted or reduced to SHA-256 evidence, and plaintext material fields fail closed. For Nitro NSM, set `SERVERWARE_NITRO_ATTESTATION_COMMAND="python3 scripts/nitro_nsm_attest.py attest"` and `SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE` to the in-enclave NSM helper invocation using `{user_data_path}` and `{output_path}` placeholders; the adapter validates the Serverware request digest and user-data hash before normalizing raw, base64, or JSON helper output. For AWS KMS Recipient-based releases, set `SERVERWARE_NITRO_KMS_RELEASE_COMMAND="python3 scripts/aws_kms_recipient_release.py release --materials-file /etc/serverware/kms-materials.json"`; the materials file must contain exactly the authorized `broker-kek` and `decision-gate-ca` entries, maps each material to a KMS `key_id`, encrypted ciphertext blob, and optional encryption context, and the adapter refuses release requests for any other material before calling AWS. Use the fixed `SERVERWARE_MASTER_KEY_UNSEAL_COMMAND="/usr/bin/python3 /app/scripts/aws_nitro_kms_unseal.py unseal"` with `SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE` consuming `{recipient_ciphertext_path}`. `make verify-production-readiness` writes the full live gate result to `.tmp/production-readiness.json` on both pass and fail while also printing a canonical pass/fail summary. `scripts/verify_release_completion.py` then binds that live result to the standalone Nitro/KMS evidence, release provenance, image signatures, benchmark, and proxy response proof. Those bindings prove readiness and consistency; final hardware-backed completion additionally requires fresh independently signed EIF/PCR, enclave CID/vsock, KMS Recipient custody, and no-parent-key evidence bound to the current host.

The required two-person set also includes `credential.oauth.uncertain.resolve`; production config fails when either exact-account activation or uncertainty resolution is omitted.

AWS KMS Recipient material files can be prepared without hand-editing ciphertext blobs:

```bash
cp ops/aws-kms-materials.spec.example.json ops/aws-kms-materials.spec.json
python3 scripts/prepare_aws_kms_materials.py --spec ops/aws-kms-materials.spec.json --dry-run
make prepare-aws-kms-materials AWS_KMS_MATERIALS_SPEC=ops/aws-kms-materials.spec.json AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json
```

The spec names exactly `broker-kek` and `decision-gate-ca`, their KMS key IDs, local plaintext source paths, and encryption contexts. The dry-run validates that exact material set and reports path state without requiring the plaintext files to exist yet. [scripts/prepare_aws_kms_materials.py](scripts/prepare_aws_kms_materials.py) calls `aws kms encrypt`, writes only `key_id`, `ciphertext_blob_b64`, `encryption_context`, and non-secret source metadata, chmods the output `0600`, and rejects AWS responses containing plaintext-like fields. The output is the exact JSON shape consumed by [scripts/aws_kms_recipient_release.py](scripts/aws_kms_recipient_release.py).

Production image no-shell verification is implemented by [scripts/verify_production_images_no_shell.py](scripts/verify_production_images_no_shell.py). Set `SERVERWARE_PRODUCTION_IMAGE_NO_SHELL_REQUIRED=1` and `SERVERWARE_PRODUCTION_IMAGES` to comma-separated digest-pinned refs such as `registry.prod.serverware.dev/serverware/control@sha256:...`; live readiness exports each rootfs with Docker and fails closed if shell binaries such as `/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/ash`, or BusyBox are present.

Production image candidates use shell-free final stages:

```bash
make verify-production-image-builds
make build-production-images
make decision-gate-bench-evidence
make production-handoff PRODUCTION_IMAGE_REGISTRY_PREFIX=registry.prod.serverware.dev/serverware PRODUCTION_IMAGE_TAG=2026-05-25
make publish-production-images PRODUCTION_IMAGE_REGISTRY_PREFIX=registry.prod.serverware.dev/serverware PRODUCTION_IMAGE_TAG=2026-05-25
make sign-production-images
make merge-production-images-env PRODUCTION_READINESS_ENV=ops/production-readiness.env
make production-host-preflight PRODUCTION_READINESS_ENV=ops/production-readiness.env AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json
make run-production-readiness PRODUCTION_READINESS_ENV=ops/production-readiness.env AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json

# Or run the ordered production sequence as one command on the production host:
make production-release-proof \
  PRODUCTION_IMAGE_REGISTRY_PREFIX=registry.prod.serverware.dev/serverware \
  PRODUCTION_IMAGE_TAG=2026-05-25 \
  PRODUCTION_READINESS_ENV=ops/production-readiness.env \
  PRODUCTION_POLICY_BUNDLE=/srv/serverware/release/policy-bundle.json \
  PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY=/srv/serverware/release/policy-signing-ed25519.pub.pem \
  POLICY_ACTIVATION_EVIDENCE_FILE=/srv/serverware/evidence/policy-activation.json \
  POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY=/srv/serverware/trust/audit-checkpoint.pub.pem \
  POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR=spiffe://prod.serverware/decision-gate/instance-01 \
  POLICY_ACTIVATION_VERIFICATION_SIGNATURE=/srv/serverware/evidence/policy-activation-verification.signature.json \
  POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY=/srv/serverware/trust/release-verifier.pub.pem \
  REPRODUCIBLE_BUILD_LEFT=/srv/serverware/evidence/builder-a.json \
  REPRODUCIBLE_BUILD_RIGHT=/srv/serverware/evidence/builder-b.json \
  REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT=builder-a=/srv/serverware/trust/builder-a.pub.pem \
  REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT=builder-b=/srv/serverware/trust/builder-b.pub.pem \
  REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE=/srv/serverware/evidence/reproducible-build-verification.signature.json \
  REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY=/srv/serverware/trust/release-verifier.pub.pem \
  AWS_KMS_MATERIALS_SPEC=ops/aws-kms-materials.spec.json \
  AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json \
  PRODUCTION_DEPLOY_COMMAND='/opt/serverware/bin/deploy-digest-pinned-release'
```

[Dockerfile.production](Dockerfile.production) builds the Python control-plane/audit-anchor image on a distroless Python nonroot base, and [data-plane/decision-gate-rs/Dockerfile.production](data-plane/decision-gate-rs/Dockerfile.production) builds the Rust data plane on a distroless cc nonroot base. Production installs only the control-plane requirements and starts `serverware.control_plane_runner`; the control plane serves TLS from `serverware.crt` and `serverware.key` in `SERVERWARE_CONTROL_PLANE_TLS_DIR`, while `ca.pem` in the same directory pins that channel for Rust. `SERVERWARE_ATTESTATION_HELPER_DIR` must contain the executable basenames configured by the six attestation/proof command settings (`nsm-attest`, `nsm-unseal`, `lease-recipient-attest`, `response-proof-attest`, `lease-recipient-verify`, and `control-plane-attestation-verify` in the example) plus the response-proof collector (`serverware-proof-client` in the example), mounted read-only as `/opt/serverware/bin`. The production host preflight parses the certificates, checks current validity and the required internal `serverware` DNS SAN, verifies the key match and CA issuance, requires private-key mode `0600`, and rejects missing, non-executable, or group/world-writable helpers. Default Docker Compose uses the control-plane runner plus the Rust decision-gate proxy, with the gate exposed on `localhost:8080` for agent traffic and `localhost:9090` for direct gate checks. Mitmproxy is installed only when the local prototype Dockerfile is explicitly built with `SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY=1`; it is not enabled by default because the available mitmproxy package line has known dependency advisories and is no longer the secure Docker path. `.dockerignore` keeps local VCS data, build outputs, caches, production env files, and key material out of the Docker context. `make validate-production-policy-identity`, `make validate-policy-activation-evidence`, and `make validate-reproducible-builds` verify the exact signed policy, deployment activation evidence, and two distinct signed builder captures first. `make production-release-input-preflight` is then the final read-only gate before mutation: it rejects a dirty checkout, placeholder or public env files, semantically invalid production settings, missing/private KMS plaintext inputs, placeholder registries, no-op deploy commands, stale policy identity, or activation/build reports lacking trusted external CI/HSM signatures. `make build-production-images` stamps OCI source/revision labels plus `dev.serverware.source_tree_digest`, writes `.tmp/production-images-build.json`, scans the locally built image IDs for forbidden shell paths, and hashes the Rust executable directly from the production image filesystem. `make decision-gate-bench-evidence` regenerates `.tmp/decision-gate-rs-bench.json` from the Rust gate self-test benchmark. `make release-provenance` writes both `.tmp/release-provenance.json` and `.tmp/release-provenance-summary.json`. `make publish-production-images` tags and pushes those image IDs to `PRODUCTION_IMAGE_REGISTRY_PREFIX`, recovers the immutable `repo@sha256` refs from Docker, writes `.tmp/production-images-published.json`, and writes `.tmp/production-images.env` containing `SERVERWARE_PRODUCTION_IMAGES=...`. `make sign-production-images` loads signer settings from the strict `PRODUCTION_READINESS_ENV`, reads the published-image env fragment, and signs the published digest refs into `.tmp/image-signatures.json` and `.tmp/image-signatures-summary.json`; published refs require `SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command`, explicit sign and verify commands, required Sigstore transparency, pinned Cosign major version 3, a stable ECDSA/RSA signing key whose SPKI digest matches the configured key ID, and a pinned Rekor key. Keyless Fulcio and transparent Ed25519ph completion verification are not implemented. `make merge-production-images-env` validates the same env fragment, updates only `SERVERWARE_PRODUCTION_IMAGES` in `ops/production-readiness.env`, preserves other env lines, and prints only a redacted key/image summary. `make production-host-preflight` writes `.tmp/production-host-preflight.json` after verifying Linux/Nitro/AppArmor host shape, TLS/helper trust material, the strict production env/config gate, current production config/env/image-env digests, the policy/activation/build reports and external signatures, published-image manifest binding back to the current no-shell build, exact published-image ref/signature coverage, signature statement bindings to release source/SBOM/Compose digests, release and image transparency records/Merkle proofs/signed tree heads/external checkpoint receipt signatures, env merge state, binary-bound current benchmark evidence, and non-world-readable KMS materials with key ID, ciphertext blob, encryption-context, and file digests; the test-only host/config bypass flags require `SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS=1` and are not set by production Make targets. `make run-production-readiness` runs that preflight first by default, stamps redacted env digests into config/live readiness artifacts, then rechecks the current host shape, re-parses the current production env and image env files, and requires those readiness env digests plus the config-gate semantic digest to match the preflight before producing `.tmp/serverware-completion-proof.json`; `make production-release-proof` runs the full ordered policy/activation/build-evidence validation, input preflight, image build, benchmark, publish, merge, provenance, sign, KMS, host-preflight, deploy, and final-proof sequence. Local image IDs are only a build-time check and are not accepted by the live production readiness config.

For two independently produced image builds, capture and compare normalized rootfs contents and the extracted Rust binary:

```bash
make capture-reproducible-build PRODUCTION_IMAGES_BUILD_FILE=/builder-a/production-images-build.json REPRODUCIBLE_BUILD_BUILDER_ID=builder-a REPRODUCIBLE_BUILD_SIGNING_KEY=/builder-a/attestor.key.pem REPRODUCIBLE_BUILD_CAPTURE_OUT=/evidence/builder-a.json
make capture-reproducible-build PRODUCTION_IMAGES_BUILD_FILE=/builder-b/production-images-build.json REPRODUCIBLE_BUILD_BUILDER_ID=builder-b REPRODUCIBLE_BUILD_SIGNING_KEY=/builder-b/attestor.key.pem REPRODUCIBLE_BUILD_CAPTURE_OUT=/evidence/builder-b.json
make validate-reproducible-builds REPRODUCIBLE_BUILD_LEFT=/evidence/builder-a.json REPRODUCIBLE_BUILD_RIGHT=/evidence/builder-b.json REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT=builder-a=/trust/builder-a.pub.pem REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT=builder-b=/trust/builder-b.pub.pem
```

The comparison normalizes archive ordering, timestamps, and Docker-generated runtime files while preserving file bytes, paths, types, permissions, ownership, links, devices, security extended attributes, image/source metadata, and the Rust executable digest. Each capture is a canonical Ed25519-signed builder attestation. Verification requires exactly two distinct operator-pinned builder identities and keys, rejects unsigned/forged/swapped/same-builder/same-key captures, and sets `independent_execution_proven:true` only after both trusted signatures and matching artifacts verify. It always reports `hardware_proof:false`; builder signatures do not prove TEE execution.

After a real staged policy activation, validate the complete PostgreSQL/HA audit slice containing baseline observations, candidate dry-runs, explicit activation/publish records, and post-activation allow and denial canaries:

```bash
make validate-policy-activation-evidence \
  POLICY_ACTIVATION_EVIDENCE_FILE=/evidence/policy-activation.json \
  POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY=/trust/policy-signing.pub.pem \
  POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY=/trust/audit-checkpoint.pub.pem \
  POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR=spiffe://prod.serverware/decision-gate/instance-01
```

This verifier runs the canonical PolicyBundle schema, semantic compiler, signature check, and production identity gate; rejects candidate-hash data-plane traffic before explicit activation and all fixture/synthetic production markers; and verifies the full audit slice against a separately pinned Ed25519 checkpoint key. It validates evidence already collected from the deployment; it does not synthesize production traffic or hardware proof. Before the one-shot release, an external CI/HSM attestor signs the exact deterministic activation and reproducibility verification report bytes as `serverware.externalArtifactSignature/v1`; input preflight, host preflight, and final completion all re-verify those detached signatures and current file digests.

`make production-handoff` writes `.tmp/production-handoff.json`, a redacted machine-readable handoff manifest for the production host. It verifies the local shell-free production image build artifact, release provenance document/summary, image-signature document/summary, cross-artifact source/provenance digests, transparency records/Merkle proofs/signed tree heads/external checkpoint receipt signatures, and Rust decision-gate benchmark target. Provenance, Sigstore, Rekor, and external-checkpoint verification uses four distinct public-key roots pinned by `ops/production-readiness.env`; embedded artifact keys cannot establish their own trust, and any configured final hardware or challenge-authority keys must also be distinct. The manifest includes a concrete Docker tag/push/inspect command plan when `PRODUCTION_IMAGE_REGISTRY_PREFIX` is set, reports only environment key names, and records the remaining host-bound work without claiming completion. Use it as the final local package before pushing images and running `make run-production-readiness` on the Nitro Linux host.

Use `make sign-production-images` after publishing production images. It loads the strict production readiness env, reads `.tmp/production-images.env` without shell evaluation, and passes the digest-pinned refs to `scripts/sign_release_images.py`; `scripts/verify_release_completion.py` rejects completion proofs whose signed image digest set differs from the no-shell production image set verified by readiness.

## Audit

Proxy decisions, response validation results, Rust data-plane decisions, JIT approval decisions, control-plane approval decisions, credential changes, route changes, log clearing, and demo policy seeding are written to the hash-chained audit store. Docker uses Postgres as the authoritative audit store with `pg_advisory_xact_lock` serializing chain appends across control-plane instances; SQLite remains the local fallback. Ordinary redacted telemetry uses a bounded Rust spool. Before every credential-bearing upstream send, however, Rust synchronously posts `data_plane.credential.release_started` and requires a successful control-plane ingest acknowledgment after the event is durably appended; missing configuration, transport failure, or ingest failure returns local `503` before release. JIT use additionally requires its authoritative grant-consume record. The control plane ingests data-plane events as `actor_type=data-plane`, derives `actor_id` from `SERVERWARE_DATA_PLANE_INSTANCE_ID`, rejects caller-supplied actor fields, and appends the event to the same chain. Until mTLS/SVID authentication is implemented, that actor is protected by the narrowly scoped audit-ingest token rather than a peer certificate. Each event includes the previous event hash and its own canonical hash:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/audit/verify
```

The control plane also exports verified chain heads to a transparency backend when `SERVERWARE_AUDIT_ANCHOR_URL` is configured. The Docker stack includes a separate `audit-anchor` service on port `9100`; despite the compatibility name, it stores each anchor as a Merkle leaf, signs every tree head with a pinned Ed25519 log key, verifies signed checkpoint receipts, exposes `GET /anchors/verify`, and serves inclusion proofs at `GET /anchors/inclusion/{sequence}`. A rollback is detectable only when a verifier retains or independently witnesses a newer trusted tree head. Compose uses a same-host development checkpoint fixture and colocated volume, so host control can roll back that fixture with the audit log; it is internal consistency and integration evidence, not an independently managed transparency service. Release provenance generation still fails unless the configured release record has a verified inclusion proof and checkpoint receipt.

`/api/audit/verify` verifies the complete local chain by default. Passing `?limit=N` performs a bounded check and returns `complete:false` when events exist beyond the checked prefix.

Auditors can search and export investigation slices without breaking the chain:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  "http://localhost:3000/api/audit/search?principalId=agent:demo&routeId=demo.echo&policyHash=sha256:..."

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  "http://localhost:3000/api/audit/export?principalId=agent:demo&decision=deny" \
  > audit-export.jsonl
```

The search response includes matching events plus `scanned`, `total_candidates`, and `complete` so bounded searches are explicit when the scan limit is smaller than the candidate set. The export endpoint returns NDJSON with a `serverware.auditExport.v1` manifest, one `serverware.auditEvent.v1` line per matching event including `prev_event_hash`/`event_hash`, and a closing `serverware.auditExportEnd.v1` line bound to the verified chain head.

Auditors can inspect the active audit backend through:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/audit/store/status
```

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -X POST http://localhost:3000/api/audit/anchors/flush

curl -H "X-Serverware-Audit-Anchor-Token: dev-audit-anchor-token" \
  http://localhost:9100/anchors/verify
```

## Runtime And Performance

The prototype still uses mitmproxy, but the normal allow/inject/response path now keeps the expensive parts in process:

- plaintext credentials are unwrapped only into short-lived v2 leases scoped by principal, route, credential, policy, and executable instead of being decrypted from SQLite on every request or published through marker files;
- the Rust gate renews warm near-expiry leases through a bounded background queue polled every `0.25` seconds; cold and expired misses may fetch synchronously, so acquisition is not fully off path;
- Gmail message IDs from validated recent responses are held in an in-memory proof cache scoped by principal, credential version, policy hash, Gmail user, and cutoff bucket;
- ordinary request/response audit events are queued to a bounded background spool, while `data_plane.credential.release_started` is posted synchronously and must receive a durable control-plane acknowledgment before release;
- other Rust-originated CONNECT, request, response, grant, and JIT consume telemetry is queued in the data plane and batch-ingested by the control plane;
- verified Postgres audit chain heads are exported off-path to a signed Merkle log; Compose uses a local fixture, while production requires an independently managed and witnessed backend;
- policy matching uses the signed compiled policy snapshot.

Docker uses Postgres as the authoritative release-authorization store; SQLite is a development fallback. The Rust and Python proxy paths use the same reserve/dispatch/complete protocol. Reserve locks and reserves the matching one-use JIT grant and every shared rate-limit counter in one transaction, or commits neither. A first real JIT request without a grant creates or reuses its exact pending approval only after the denied reserve has left no partial state. Pre-send dispatch and terminal completion are exact, idempotent state transitions; a request proven not to have been forwarded refunds its reservation, while an uncertain result after dispatch is committed conservatively. Lifecycle events use a durable outbox before hash-chain audit delivery. If the release authority is unavailable, malformed, or returns a mismatched binding, the proxy returns `503` without credential injection or upstream contact. Local Rust `POST /v1/grants` entries require the scoped data-plane management token and are non-authoritative when atomic release authorization is enabled.

Docker also uses Postgres as the control-plane metadata store for credentials, routes, approval requests, WebAuthn registrations/challenges, Gmail proof cache entries, and request logs. The existing DB call sites go through a Postgres adapter so SQLite remains the local fallback, while Docker can run multiple control-plane instances against the same metadata, grant, and audit stores.

Auditors can inspect the active backend and pending consumption audit outbox through:

```bash
curl -fsS -H "X-Serverware-Admin-Token: dev-admin-token" \
  http://localhost:3000/api/grants/status

curl -fsS -H "X-Serverware-Admin-Token: dev-admin-token" \
  http://localhost:3000/api/metadata/store/status
```

Required pre-release auditing applies to every Rust credential-bearing route, not only JIT routes. This guarantee is scoped to the Rust production data plane; the legacy mitmproxy path remains a local prototype.

Runtime counters are available to auditors:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/runtime/metrics
```

Historical local full-proxy benchmark from `make bench` on the demo echo route, after 10 warmups and 100 measured requests:

```json
{
  "p50_ms": 15.753,
  "p95_ms": 23.18,
  "p99_ms": 28.147,
  "mean_ms": 16.791
}
```

This run missed the target p99 under 20 ms for request-only policies on that machine. It is retained as historical prototype evidence and is not bound to the current source tree; release decisions require a refreshed full-proxy benchmark.

The Rust data plane in [data-plane/decision-gate-rs](data-plane/decision-gate-rs) isolates policy evaluation from mitmproxy and FastAPI. It verifies an attested policy trust root, signed snapshot, and persistent policy high-water; authenticates principals and CONNECT authorities before TLS leaf issuance; validates upstream TLS; fetches exact v2 credential leases; classifies adapter operations; enforces shared JIT and quotas; and applies bounded status-specific response projection. Credentialless opaque streams and declared structured redacting stream modes use backpressure and size caps. Credential-bearing opaque/non-redacting response streams and credential-bearing mutating request streams are rejected at policy admission. Warm leases renew in bounded background workers, but cold or expired leases can require a synchronous control-plane fetch. In-memory request-only decisions without a lease miss, shared JIT, or shared rate limit make no SQLite, Postgres, or filesystem call, and no decision response contains plaintext credentials.

Latest verified post-gate Docker benchmark, measured over the Compose network from the control-plane container after `100` warmups and `1000` decision calls:

```json
{
  "p50_ms": 0.475,
  "p95_ms": 0.679,
  "p99_ms": 0.985,
  "max_ms": 2.854,
  "mean_ms": 0.495
}
```

The full `make bench-gate-rs` matrix must pass on the final source tree before release evidence is regenerated. The benchmark runs inside the Docker network so Docker Desktop host-port bridge jitter is not attributed to the gate. Its pre/post nonce-bound documents are unsigned runtime self-reports in development, not vendor attestations; they require the executable, policy, and immutable runtime-manifest digests to remain unchanged, while mutable health counters are reported outside that manifest. Production release evidence must rerun the path on the target host and bind it to a verified vendor quote.

Rust is the current implementation track because it already carries the required policy, CONNECT, credential-lease, and response-validation behavior. The `/v1/decide` microbenchmark alone does not establish production scalability or prove Rust superior to an unbuilt Envoy candidate. The measured executable is `sha256:8b67aadd148c0f6462d179ccf3e6367ade51ee1e45388bb7870aa86c4e9a8da1`. Release builds use the lockfile, strip non-runtime symbols, and omit the nondeterministic GNU linker build ID; two independent clean Docker builds produced this exact executable digest. The local provenance and image-signature artifacts are development fixtures; production images, signatures, benchmark bindings, and hardware quotes must be regenerated together from one exact checkout on the target host. Any replacement must prove the same explicit HTTPS CONNECT interception, dynamic attested leaf issuance, response mutation/validation, no hot-path DB/filesystem calls, and an acceptable TEE TCB under comparable full-proxy load.

## TEE Path

The current Docker build still stores dev materials locally, but their use is gated by signed attestation claims: the broker KEK is not used until `broker-kek` key release succeeds, and the Rust data-plane CA private key is not published until `decision-gate-ca` key release succeeds with the release-pinned Rust binary digest from `SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST`. The default development quote is self-signed by `/data/dev-tee-quote-ed25519.pem`; its software lease recipient protects disk and network delivery, not process memory from host root. The AWS Nitro-compatible provider verifies Nitro CBOR/COSE documents and can require KMS recipient ciphertext, but Docker fixtures do not prove hardware PCR enforcement, enclave key custody, CA-key custody, or parent-host ciphertext-only observation.

For eligible buffered successful HTTPS responses, a client nonce can request a `serverware.proxyResponseProof/v2` artifact. The externally captured proof binds the request and operation digests, released status/selected headers/body digest, policy, runtime manifest, executable, release, SPIFFE server instance, and TLS exporter, with separate server and collector signatures plus vendor attestation evidence. It currently requires `GET` or `HEAD`, CONNECT TLS, and a buffered route. Streaming responses do not have an equivalent end-of-stream proof, and a real TEE claim still requires evidence collected on the deployed Nitro/SEV-SNP/TDX hardware rather than the development fixture.

For a TEE deployment:

1. Boot Serverware inside AWS Nitro Enclaves or another selected TEE.
2. Produce a Nitro attestation document whose signed `user_data` binds the Serverware claims digest: image/runtime digest, policy bundle digest, data-plane binary digest, CA SPKI, rollback epoch, release channel, provenance digest, and public sealing key.
3. Release or unwrap the broker KEK and CA intermediate only after vendor quote verification, PCR allowlist checks, and KMS/HSM policy pass.
4. Seal refreshed OAuth tokens, wrapped DEKs, and approval grants to the TEE identity.
5. Log policy decisions externally with redacted URLs and route IDs, not raw credentials.

The proxy/policy boundary is already isolated enough for that migration: in development the Rust process owns route policy and decrypted credential material, and agents only receive normal upstream responses. Ordinary Docker, a `/dev/nsm` device mount, a valid quote helper response, KMS Recipient-shaped ciphertext, and passing release-readiness checks do not prove that the executing Rust path or its private keys lived inside an enclave. They remain pre-enclave evidence. Final hardware-backed completion requires moving the recipient, unwrap, CA, response-proof, and credential-use boundary into the measured enclave and supplying fresh independently signed EIF/PCR, CID/vsock, key-custody, and parent-host observation evidence bound to the current release and host.
