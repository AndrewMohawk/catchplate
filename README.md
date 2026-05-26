# Serverware

Serverware is a Dockerized credential-control proxy for agentic flows. Agents keep using normal HTTP clients and normal endpoint URLs, but route traffic through Serverware as an HTTP(S) proxy. Serverware's CA lets it inspect HTTPS requests, inject credentials from its vault, and enforce local policies before the upstream service sees the request.

## Run

```bash
make up
open http://localhost:3000
```

Install the proxy CA through the attestation verifier before using the proxy:

```bash
export SERVERWARE_ADMIN_TOKEN=dev-admin-token
make install-ca
```

That target creates a one-use CA install session, verifies the nonce-bound runtime manifest, signed dev quote, signed policy bundle, policy signing key, rollback epoch, release channel, and CA SPKI, then copies the CA to `.tmp/serverware-ca.pem`. Then point an isolated agent runtime at the proxy:

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
curl -X POST -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/demo/seed
curl --proxy "$HTTPS_PROXY" \
  --cacert .tmp/serverware-ca.pem \
  -H 'X-Serverware-Agent: demo-agent' \
  https://demo-upstream:8443/echo
```

For local debugging only, `/ca.pem` remains an authenticated endpoint and returns `X-Serverware-Debug-Only: true`. Production sets `SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED=0` and uses `/api/ca/install-sessions` plus `scripts/install_verified_ca.sh`, so the CA is only released through a short-lived nonce-bound verifier-mediated install session.

The Compose development token is `dev-admin-token`. In a real deployment set `SERVERWARE_ADMIN_TOKEN` to a high-entropy secret or replace this dev guard with the WebAuthn/RBAC flow in [goal.md](goal.md). The UI stores the token in browser local storage and sends it as `X-Serverware-Admin-Token`. Cookie-based admin auth is protected with double-submit CSRF for unsafe control-plane requests; authenticated browsers can fetch `/api/csrf` and send the returned token as `X-Serverware-CSRF-Token`.

The Compose profile maps that token to `user:demo` with the demo admin roles so the demo NPM route can enforce its configured approver allowlist. Production should enable OIDC bearer-token auth plus WebAuthn MFA. Set `SERVERWARE_OIDC_ENABLED=1`, `SERVERWARE_OIDC_ISSUER`, `SERVERWARE_OIDC_AUDIENCE`, and a trusted JWKS through `SERVERWARE_OIDC_JWKS_JSON` or `SERVERWARE_OIDC_JWKS_PATH`; RBAC roles are read from `SERVERWARE_OIDC_ROLE_CLAIM`. When `SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED=1`, credential, route, and policy-publish mutations require a WebAuthn assertion from `/api/control-plane/mutations/webauthn/options`; the challenge binds only the canonical mutation payload digest, not plaintext credential material. When `SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED=1`, those high-risk mutations first return `428 control_plane_approval_required`; a different authorized operator approves `/api/control-plane/approvals/{id}/approve`, and the original requester retries with `mfa.approvalId`.

Run the full Docker smoke:

```bash
make e2e
```

Run the local proxy benchmark:

```bash
make bench
```

Run the Rust data-plane decision-gate benchmark:

```bash
make bench-gate-rs
```

The smoke test proves:

- CA-backed HTTPS interception through mitmproxy.
- Fail-closed blocking for unknown routes.
- Principal access control using source CIDRs, required trusted identity headers, and hashed `Proxy-Authorization` bearer tokens bound to agent ID, source CIDR, and expiry.
- Bearer token injection from the encrypted credential vault.
- A typed policy bundle with strict JIT binding schema, bounded generic REST config, response `allowedFields` redaction, and a stable policy hash exposed through quote-backed `/attestation`.
- A shared credential-constraint layer for route-level quotas, operation allow/deny lists, query lookback windows, query caps, JSON body shape rules, and response date-window validation. See [docs/credential-constraints.md](docs/credential-constraints.md) and [policies/credential-limits.examples.json](policies/credential-limits.examples.json).
- A policy publish workflow where `/api/policy/candidate` validates and signs a candidate bundle with diff and dry-run decision results, `/api/policy/publish` enforces monotonic sequence/rollback rules, `policy_publisher` RBAC, optional WebAuthn mutation MFA, required two-person production approval, required production dry-runs, and canary staging, and `/api/policy/canary/activate` fully activates only after the canary observation/audit/denial gates pass. Direct and canary activations are audited through `policy.published`.
- A Gmail adapter that forces `newer_than:30d`, tightens weaker existing age guards, caps `maxResults`, validates response `internalDate`, redacts responses to `allowedFields`, marks unproven list IDs as pending, and only allows message reads for IDs observed from validated recent responses under the same scoped proof context.
- An X adapter that allows configured read operations, blocks write methods, denies unconfigured read operations, binds the route `appIds` policy to credential metadata, and redacts responses to policy-selected fields.
- An npm adapter that classifies operations before JIT, denies publish requests missing package/version/integrity fields, requires approval only for configured sensitive operations, and redacts publish responses before returning them to agents.
- JIT approval where the first publish request fails closed with `428`, token-only approval fails with `412`, WebAuthn approval creates a one-use request-digest-bound grant in the HA Postgres grant store, repeated approval fails with `409`, the Rust data plane consumes the grant through the shared control-plane endpoint, the retry succeeds, grant consumption is audited, and grant reuse fails closed.
- Break-glass grants through `POST /api/break-glass/grants` and `POST /v1/break-glass/grants`, requiring approver RBAC plus configured WebAuthn/two-person mutation controls, creating a normal digest-bound one-use JIT grant, and auditing `approval.break_glass_granted` with the human reason and no credential material.
- JIT denial records where approvers can attach an optional reason to `/api/approvals/{id}/deny`; the reason is stored on the approval, written to the hash-chained `approval.denied` audit event, and searchable through audit search.
- Redacted JIT approval review through `GET /api/approvals/{id}/review`, including principal/source identity, route, credential version, policy hash, normalized operation fields, body hash, redacted payload summary, risk flags, previous similar approvals, and exact retry semantics without exposing secrets.
- WebAuthn registration verifies packed/fido-u2f hardware attestation chains against signed, rollback-protected FIDO/YubiKey trust bundles before assigning a hardware class. A known YubiKey AAGUID without a trusted chain remains `unknown`.
- Non-public control plane APIs: `/ca.pem`, `/api/bootstrap`, credential CRUD, route CRUD, approvals, logs, audit, policy status, and demo seeding require the admin token.
- OIDC bearer-token control-plane auth where RS256, ES256, or Ed25519 JWTs are verified against a pinned JWKS, issuer, audience, expiry, and role claim before FastAPI RBAC dependencies accept the identity.
- Optional production mutation MFA where credential and route create/update/delete operations must carry a WebAuthn assertion over the canonical mutation payload digest before the audited change is accepted.
- Two-person control-plane approval where high-risk credential, route, policy-publish, RBAC/deprovisioning, and generated admin-token rotation changes are bound to a canonical payload digest, store only redacted request summaries, block self-approval, require a different authorized role owner, consume the approval once, and audit request, approval, consumption, and mutation evidence.
- Audited RBAC/bootstrap/token operations: `/api/bootstrap` writes a hash-chained `control_plane.bootstrap` event, `/api/rbac/role-bindings/{subject}` and `/api/rbac/deprovision` persist role-binding state and audit role changes/deprovisioning with WebAuthn mutation evidence when required, and `/api/control-plane/tokens/admin/rotate` rotates only generated-file admin tokens while auditing old/new token hashes without exposing the new token in the audit log.
- Signed policy bundles and a hash-chained audit log that can be checked with `GET /api/audit/verify`.
- Searchable audit review through `GET /api/audit/search` with filters for event type, actor, principal, route, policy hash, credential ID/version, approval ID, decision, attestation measurement, time window, and raw text.
- Envelope-encrypted credentials with per-credential DEKs, visible credential versions, and JIT/audit records bound to the exact credential generation.
- Version-addressed runtime secret leases, broker-published credential generation and data-plane secret lease updates, in-memory Gmail response caches, and a bounded async audit spool so common request/response decisions avoid unnecessary SQLite work.
- A Docker operator CA installer that runs the client verifier, checks attestation freshness, dev quote signature/claims, policy signature/digest, signing key hash, release channel, rollback epoch, and CA SPKI, then copies the verified CA into the agent runtime path.
- Agent enrollment packets from `POST /api/agents/enrollment`, with principal identity requirements, attestation pins, proxy environment variables, allow/deny canaries, and a deny-by-default Kubernetes NetworkPolicy plus iptables rules that only allow egress to configured Serverware proxy CIDRs.
- A dev key-release gate that requires a signed quote authorizing `broker-kek` before credential DEK unwrap and `decision-gate-ca` before handing the CA private key to the Rust data plane. The `decision-gate-ca` release also requires the release-pinned Rust binary digest.
- External TEE/KMS provider hooks plus an AWS Nitro-compatible provider: `SERVERWARE_TEE_QUOTE_COMMAND`, `SERVERWARE_TEE_QUOTE_VERIFY_COMMAND`, and `SERVERWARE_KEY_RELEASE_COMMAND` let deployments plug in vendor quote verification and KMS/HSM policy without changing the policy engine. Docker verifies both the generic external-command interface and [scripts/aws_nitro_tee_provider.py](scripts/aws_nitro_tee_provider.py), including Nitro CBOR/COSE_Sign1 parsing, certificate-chain trust-root checks, PCR allowlisting, Serverware claim binding through Nitro `user_data`, a material-release policy for `broker-kek`/`decision-gate-ca`, and the production KMS/HSM command contract through [scripts/nitro_kms_fixture.py](scripts/nitro_kms_fixture.py).
- A Dockerized Rust data-plane candidate that verifies the Ed25519 policy signature against an attested control-plane trust root at startup, exposes a binary-digest attestation, loads the signed policy snapshot once, denies unknown CONNECT authorities before leaf issuance, performs explicit CONNECT TLS interception with dynamic leaf certificates from the verifier-installed CA, handles sequential keep-alive requests inside an intercepted CONNECT tunnel, validates upstream TLS, injects credentials from broker leases, validates and redacts Gmail responses before release, applies generic JSON response `allowedFields` redaction for non-Gmail adapters, streams policy-declared absolute-form and CONNECT MITM request bodies for non-mutating generic routes, streams policy-declared non-redacting responses with backpressure and constant-memory hashing, redacts JSON Lines, top-level JSON array, JSON SSE event-stream, arbitrary nested JSON, form-urlencoded, and CSV request/response streams to policy `allowedFields`, watches broker-published credential generations and secret leases, receives approved grants from the control plane, consumes one-use JIT grants through the shared transactional control-plane grant store, consumes `store: "shared"` credential quotas through the authenticated control-plane metadata store, returns request-only allow/deny/JIT decisions without plaintext secret exposure, and keeps SQLite/filesystem calls off the request path.
- Hardened Docker runtime settings verified by [scripts/test_container_hardening.sh](scripts/test_container_hardening.sh): application services run as UID/GID `10001`, Postgres runs as its non-root database user, all services use read-only root filesystems, drop all Linux capabilities, enable `no-new-privileges`, set PID and memory limits, disable core dumps, mount `/tmp` as `noexec,nosuid,nodev` tmpfs, and run under [security/seccomp/serverware-deny-dangerous.json](security/seccomp/serverware-deny-dangerous.json). The verifier confirms Docker seccomp filter mode, runtime core dump limits, and proves the profile is active by checking a denied `bpf` syscall returns the profile's custom errno.
- Signed local release provenance with Python/Rust SBOM summaries, a CycloneDX 1.5 SBOM at `.tmp/sbom.cdx.json`, source/config/image/hardening inventory, source tree digest, build recipe, published control-plane and data-plane attestations, provenance/source digest binding in both attestation endpoints, and a `release.provenance.v1` record with a verified inclusion proof in the signed transparency log.
- Sigstore-compatible image-release bundle at `.tmp/image-signatures.json` with per-image in-toto statements for every Compose image, a cosign `sign-blob`/`verify-blob` adapter, required transparency evidence, provenance/SBOM/config/source bindings, image-signature digest binding in both attestation endpoints, and a `release.image_signatures.v1` transparency-log record with a verified inclusion proof.
- Control-plane responses carry `X-Serverware-Response-*` proof headers: a nonce-capable Ed25519 signature over method, path, query, status, response body hash, source tree digest, runtime manifest digest, policy hash, provenance digest, and image-signature digest. The response signing key ID is itself bound into `/attestation` quote claims.

## Policy Model

The proxy now requires a signed/hashed `PolicyBundle` at `/data/policy-bundle.json`, generated by the demo seed endpoint and modeled after [policies/demo.policy.json](policies/demo.policy.json). The current Python compiler validates the JSON Schema and adapter configs, verifies the Ed25519 signature, compiles path templates to regexes, computes a canonical policy hash over the unsigned payload, and keeps the hot-path route snapshot in memory.

Policy authors can submit a candidate bundle to `POST /api/policy/candidate` to receive a signed candidate, schema/semantic validation, a human-readable principal/credential/route diff, and dry-run decision results. Policy publishers can use `POST /api/policy/publish` with `activationMode: "canary"` to write a signed canary bundle at `SERVERWARE_POLICY_CANARY_BUNDLE`, persist canary state, and audit `policy.canary.started` without changing the active bundle. `GET /api/policy/canary/status` reports observed audit events, denials, and p95 latency since canary start; `POST /api/policy/canary/activate` fully publishes only if the observation window, audit evidence, and denial threshold pass, then records both `policy.canary.activated` and `policy.published`. Production sets `SERVERWARE_POLICY_CANARY_REQUIRED=1`; direct full publish remains available for local/dev paths when that flag is off.

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

Route `constraints` are the reusable layer for limits that should apply to any credential, independent of the upstream SDK. Implemented constraint types are `operationPolicy`, `rateLimit`, `queryDateWindow`, `queryNumericBounds`, `jsonBody`, and `responseDateWindow`. The Python proxy and Rust data plane both enforce them before credential injection; response date-window checks run before redaction and release. `rateLimit.store: "shared"` uses the authenticated control-plane consume endpoint and metadata-store row locks/transactions so quotas such as the demo one-tweet-per-day policy are global across replicas.

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

`credential_version` advances only when stored secret material changes. JIT approval requests, one-use grants, canonical request digests, and proxy audit events include that version, so an approval for `cred-demo-bearer` version `7` cannot authorize the same request after the credential is rotated to version `8`.

The Docker prototype publishes credential generations to `/data/credential-generations.json` whenever credentials are created, rotated, or deleted. The mitmproxy subprocess watches that broker marker and keys plaintext leases by `(credential_id, credential_version)`, so a rotated credential invalidates stale leases across processes before the old lease TTL expires.

The control plane also publishes a prototype data-plane lease marker at `/data/credential-leases.json`. It is owned by the Rust data-plane UID/GID and chmod `0640`; the Rust gate watches it off the request path, requires a matching secret lease for the active credential generation, uses broker metadata from the lease instead of caller-supplied credential metadata, and never returns plaintext secrets from decision responses. Production should replace both marker files with a broker push channel, colocated lease store, or TEE key-release path, but keep the same version-addressed invariant.

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

That means a list result for one agent, Gmail user, policy hash, cutoff window, or credential generation cannot authorize a direct body read in another context. If a Gmail list response omits `internalDate` and the adapter is configured with `validateListByMetadataFetch`, Serverware returns the ID with `serverwareAgeProof: "pending"` and adds it to top-level `serverwarePendingAgeProof`. Pending IDs are not inserted into the read cache, so a direct `GET /gmail/v1/users/{user}/messages/{id}` fails with `403` until a bounded metadata fetch or direct response proves the age. After validation, `response.allowedFields` is enforced on list and direct message JSON so upstream echo fields, credentials, raw bodies, and non-allowlisted Gmail fields are removed before release.

## JIT Grants

JIT approval is server-side. The agent never receives a token. For a sensitive request, Serverware computes a canonical request object containing principal, route, credential version, policy hash, method, authority, path, selected headers, body hash, and adapter operation fields. It hashes that object into `request_digest` and `operation_digest`.

If no matching grant exists, Serverware returns:

```json
{"error":"serverware_approval_required","approval_id":"...","request_digest":"sha256:..."}
```

Approving is an atomic pending-to-approved transition. It rejects expired or already-decided approvals. A successful approval creates a short-lived grant with `maxUses: 1`; the next identical request consumes the grant atomically before credential injection and writes a `jit.grant.consumed` audit event. A third identical request requires a fresh approval.

The demo NPM policy now sets `jit.approvers.authn.webauthnRequired: true`. Approval requires:

- the caller has the `approver` role;
- the caller user ID is listed in `jit.approvers.users`;
- the caller signs a WebAuthn assertion over a server-issued challenge bound to approval ID, request digest, operation digest, credential ref/version, policy hash, grant TTL/max uses, display digest, and expiry;
- the registered authenticator class is allowed by policy.

For policies with `requireHardwareAttestation: true`, authenticator class is not inferred from AAGUID alone. Registration accepts `packed`, `fido-u2f`, and `none` attestation formats, but only a valid attestation signature and certificate chain anchored in the active signed WebAuthn trust bundle can set `attestation_trusted: true` and classify a credential as `yubikey` or `hardware`. Missing, self, untrusted, or unsupported attestation is still registrable as `unknown`, but cannot satisfy hardware-only approval policies.

WebAuthn trust roots are packaged as signed bundles validated by [schemas/webauthn-trust-bundle.v1.schema.json](schemas/webauthn-trust-bundle.v1.schema.json). The bundle carries sequence, rollback epoch, validity window, root certificates, allowed AAGUIDs, and authenticator class. `SERVERWARE_WEBAUTHN_TRUST_BUNDLE` points to the active bundle; `SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE` stores the highest accepted sequence/epoch so old bundles cannot be replayed. Legacy `SERVERWARE_WEBAUTHN_TRUST_ROOTS` PEM loading remains only as a development fallback when no signed bundle exists.

Useful trust endpoints:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/webauthn/trust/status

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bundle":{...signed WebAuthnTrustBundle...}}' \
  http://localhost:3000/api/webauthn/trust/publish
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

The packet contains no plaintext credentials or proxy bearer tokens. It gives the agent runtime the proxy/CA environment, policy and attestation pins, route canaries, and a deny-by-default egress policy. Production readiness now requires both enrollment packets and agent egress enforcement before credentials are enabled.

The control plane exposes `GET /api/key-release/status` and admin-only `POST /api/key-release/verify`. The verifier checks quote signature, material authorization, policy digest, CA SPKI, data-plane binary digest, rollback epoch, release channel, and optional provenance digest, then records key-release events in the audit chain. Docker enables this gate by default for the broker KEK and the Rust data-plane CA private-key handoff.

The Rust data-plane gate also exposes `GET /attestation?nonce=...` on port `9090`. [scripts/verify_decision_gate_attestation.py](scripts/verify_decision_gate_attestation.py) verifies nonce binding, runtime manifest digest, SHA-256 digest of the running gate executable, policy hash/signing-key consistency with the control plane, the control-plane quote's pinned data-plane digest, image-signature digest parity, and the declared zero SQLite/filesystem hot path. When `SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID` or `SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID` is set, the Rust gate refuses to boot unless the quote signer and signed bundle key match those pins. `make bench-gate-rs` verifies attestation, startup failure for tampered policy signatures, wrong policy-key pins, and wrong control-plane quote-key pins, raw CONNECT preflight allow/deny behavior, CONNECT MITM with dynamic leaf issuance, absolute-form HTTPS forwarding with credential injection, policy-declared request-body streaming, binary response streaming, JSONL, JSON-array, JSON-SSE, nested JSON, form-urlencoded, and CSV request/response streaming redaction, Gmail response validation/redaction, shared JIT grant consumption, dev/external-command/Nitro key release for `broker-kek`/`decision-gate-ca`, release provenance generation, image-release signing, and latency.

[scripts/generate_release_provenance.py](scripts/generate_release_provenance.py) creates `.tmp/release-provenance.json`, signs the canonical provenance with a local dev Ed25519 release key, writes it into `/data/release-provenance.json`, verifies both attestation endpoints expose the provenance digest, and anchors a `release.provenance.v1` record in the signed transparency log. [scripts/sign_release_images.py](scripts/sign_release_images.py) creates `.tmp/image-signatures.json`, signs per-image in-toto statements through `SERVERWARE_IMAGE_SIGN_COMMAND`, verifies them through `SERVERWARE_IMAGE_VERIFY_COMMAND`, requires Sigstore-style transparency evidence when `SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1`, writes the bundle into `/data/image-signatures.json`, verifies both attestation endpoints expose the image-signature digest, and anchors a `release.image_signatures.v1` record:

```bash
make release-provenance
make image-signatures
```

The provenance includes source file hashes, Python requirements and Rust `Cargo.lock` SBOM entries, a CycloneDX 1.5 SBOM digest, Compose config digest, Docker image IDs, container hardening inventory, pre/post-publish attestations, audit/transparency-log state, the transparency-log append response, and a verified inclusion proof for the release record. The image-signature bundle binds each image statement to that provenance digest, SBOM digest, Compose config digest, source tree digest, and transparency inclusion proof. Docker exercises the production cosign command path through [scripts/cosign_sigstore.py](scripts/cosign_sigstore.py) and the local [scripts/cosign_fixture.py](scripts/cosign_fixture.py); production release channels should set `SERVERWARE_COSIGN_BINARY=cosign` plus `SERVERWARE_COSIGN_KEY` or keyless identity/issuer settings backed by KMS/HSM or workload identity, set `SERVERWARE_COSIGN_KEY_ID` for KMS/HSM signing, and pin `SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID` to the expected Sigstore transparency log.

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
make run-production-readiness
```

The runner loads `ops/production-readiness.env` without shell evaluation, rejects placeholder values such as `CHANGE_ME`, `${...}`, or `<...>`, keeps environment values out of dry-run output, then runs the config gate, live claims generation, redacted Nitro/KMS evidence collection, final live readiness gate, and release-completion proof verification in sequence. The completion verifier requires `.tmp/release-provenance-summary.json`, `.tmp/release-provenance.json`, `.tmp/image-signatures-summary.json`, `.tmp/image-signatures.json`, and `.tmp/decision-gate-rs-bench.json` to exist and agree with the live readiness evidence; it writes `.tmp/serverware-completion-proof.json` when the artifact set proves the release. The equivalent individual commands remain:

```bash
make verify-production-config
make generate-production-readiness-claims
make collect-nitro-kms-evidence
make verify-production-readiness
python3 scripts/verify_release_completion.py --out .tmp/serverware-completion-proof.json
```

`verify-production-config` rejects dev/fixture settings and checks that control-plane admin auth uses an explicit high-entropy token, OIDC auth is enabled with pinned issuer/audience/JWKS/role claim, production WebAuthn origin, direct CA download is disabled in favor of bounded install sessions, required WebAuthn MFA plus two-person approval for high-risk credential/route/policy/RBAC/token/break-glass mutations, required policy-publish dry-run decision tests, and required policy canary activation with a positive observation window, audit evidence, and zero-denial threshold; Nitro NSM attestation, KMS/HSM release, cosign/Sigstore identity plus pinned Rekor log ID, external transparency checkpointing, AppArmor, Postgres-backed metadata/grant/audit stores, the shared rate-limit consume endpoint, required agent enrollment plus egress enforcement, and immutable production image refs with required no-shell verification are configured for production. `verify-production-readiness` additionally signs and verifies a live Sigstore probe with required transparency evidence, expected key identity, and expected Rekor log ID, publishes and verifies an external transparency checkpoint probe, checks the metadata/grant/audit Postgres stores are reachable with the required tables, runs live Nitro quote/release probes from `SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON` or `--claims-file`, verifies the configured production image root filesystems contain no shell binaries, and requires the Linux AppArmor runtime probe to pass.

`make generate-production-readiness-claims` verifies `/attestation`, the runtime manifest digest, the quote-bound claim set, and the signed policy bundle from `/api/policy`, then writes `.tmp/production-readiness-claims.json` for the live Nitro/KMS probes. `make collect-nitro-kms-evidence` uses that claims file when present and writes `.tmp/nitro-kms-evidence.json` on both pass and fail; successful evidence proves a fresh Nitro NSM attestation command, quote verification, PCR/root/user-data binding, and KMS/HSM release decisions for both `broker-kek` and `decision-gate-ca`; raw attestation documents, KMS public keys, signatures, and plaintext material are omitted or reduced to SHA-256 evidence, and plaintext material fields fail closed. For Nitro NSM, set `SERVERWARE_NITRO_ATTESTATION_COMMAND="python3 scripts/nitro_nsm_attest.py attest"` and `SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE` to the in-enclave NSM helper invocation using `{user_data_path}` and `{output_path}` placeholders; the adapter validates the Serverware request digest and user-data hash before normalizing raw, base64, or JSON helper output. For AWS KMS Recipient-based releases, set `SERVERWARE_NITRO_KMS_RELEASE_COMMAND="python3 scripts/aws_kms_recipient_release.py release --materials-file /etc/serverware/kms-materials.json"`; the materials file maps each material to a KMS `key_id`, encrypted ciphertext blob, and optional encryption context, and the adapter returns only recipient-encrypted ciphertext evidence plus key identity. `make verify-production-readiness` writes the full live gate result to `.tmp/production-readiness.json` on both pass and fail while also printing a canonical pass/fail summary. `scripts/verify_release_completion.py` then binds that live result to the standalone Nitro/KMS evidence file, signed and anchored release provenance, Sigstore image-signature bundle with transparency proofs, and Rust decision-gate p99 benchmark target.

AWS KMS Recipient material files can be prepared without hand-editing ciphertext blobs:

```bash
cp ops/aws-kms-materials.spec.example.json ops/aws-kms-materials.spec.json
python3 scripts/prepare_aws_kms_materials.py --spec ops/aws-kms-materials.spec.json --dry-run
make prepare-aws-kms-materials AWS_KMS_MATERIALS_SPEC=ops/aws-kms-materials.spec.json AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json
```

The spec names each material, its KMS key ID, a local plaintext source path, and an encryption context. The dry-run validates the spec and reports path state without requiring the plaintext files to exist yet. [scripts/prepare_aws_kms_materials.py](scripts/prepare_aws_kms_materials.py) calls `aws kms encrypt`, writes only `key_id`, `ciphertext_blob_b64`, `encryption_context`, and non-secret source metadata, chmods the output `0600`, and rejects AWS responses containing plaintext-like fields. The output is the exact JSON shape consumed by [scripts/aws_kms_recipient_release.py](scripts/aws_kms_recipient_release.py).

Production image no-shell verification is implemented by [scripts/verify_production_images_no_shell.py](scripts/verify_production_images_no_shell.py). Set `SERVERWARE_PRODUCTION_IMAGE_NO_SHELL_REQUIRED=1` and `SERVERWARE_PRODUCTION_IMAGES` to comma-separated digest-pinned refs such as `registry.example/serverware/control@sha256:...`; live readiness exports each rootfs with Docker and fails closed if shell binaries such as `/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/ash`, or BusyBox are present.

Production image candidates use shell-free final stages:

```bash
make verify-production-image-builds
make build-production-images
make publish-production-images PRODUCTION_IMAGE_REGISTRY_PREFIX=registry.example/serverware PRODUCTION_IMAGE_TAG=2026-05-25
```

[Dockerfile.production](Dockerfile.production) builds the Python control-plane/audit-anchor image on a distroless Python nonroot base, and [data-plane/decision-gate-rs/Dockerfile.production](data-plane/decision-gate-rs/Dockerfile.production) builds the Rust data plane on a distroless cc nonroot base. `.dockerignore` keeps local VCS data, build outputs, caches, production env files, and key material out of the Docker context. `make build-production-images` stamps OCI source/revision labels plus `dev.serverware.source_tree_digest`, writes `.tmp/production-images-build.json`, and scans the locally built image IDs for forbidden shell paths. `make publish-production-images` tags and pushes those image IDs to `PRODUCTION_IMAGE_REGISTRY_PREFIX`, recovers the immutable `repo@sha256` refs from Docker, writes `.tmp/production-images-published.json`, and writes `.tmp/production-images.env` containing `SERVERWARE_PRODUCTION_IMAGES=...`. Merge that env fragment into `ops/production-readiness.env`, then run `make run-production-readiness`; local image IDs are only a build-time check and are not accepted by the live production readiness config.

Set the same `SERVERWARE_PRODUCTION_IMAGES` value when running `image-signatures` or `scripts/sign_release_images.py`. When present, the image-signature bundle signs those production digest refs instead of the local Compose image inventory, and `scripts/verify_release_completion.py` rejects completion proofs whose signed image digest set differs from the no-shell production image set verified by readiness.

## Audit

Proxy decisions, response validation results, Rust data-plane decisions, JIT approval decisions, control-plane approval decisions, credential changes, route changes, log clearing, and demo policy seeding are written to the hash-chained audit store. Docker uses Postgres as the authoritative audit store with `pg_advisory_xact_lock` serializing chain appends across control-plane instances; SQLite remains the local fallback. Proxy request/response events enter a bounded in-process spool first, then a background worker writes the chain. The Rust gate uses its own bounded in-memory audit spool and posts redacted batches to `POST /api/data-plane/audit` with `X-Serverware-Data-Plane-Token`; the control plane ingests those events as `actor_type=data-plane` and appends them to the same hash chain. Each event includes the previous event hash and its own canonical hash:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/audit/verify
```

The control plane also exports verified chain heads to a transparency backend when `SERVERWARE_AUDIT_ANCHOR_URL` is configured. The Docker stack includes a separate `audit-anchor` service on port `9100`; despite the compatibility name, it stores each anchor as a Merkle leaf, signs every tree head with an Ed25519 log key, exposes `GET /anchors/verify`, and serves inclusion proofs at `GET /anchors/inclusion/{sequence}`. Deleting or rolling back the audit store is detectable against the exported tree head, and release provenance generation fails unless the release record has a verified inclusion proof.

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

- plaintext credentials are read into short-lived `(credential_id, credential_version)` leases after envelope unwrap instead of decrypted from SQLite on every request;
- credential generation updates and data-plane secret lease updates are published by the control plane and observed by proxy workers for cross-process lease invalidation;
- Gmail message IDs from validated recent responses are held in an in-memory proof cache scoped by principal, credential version, policy hash, Gmail user, and cutoff bucket;
- request/response audit events are queued to a bounded background spool;
- Rust-originated CONNECT, request, response, grant, and JIT consume audit events are queued in the data plane and batch-ingested by the control plane;
- verified Postgres audit chain heads are exported off-path to a signed Merkle transparency log;
- policy matching uses the signed compiled policy snapshot.

JIT approval requests remain in the control-plane database, but Docker now uses Postgres as the authoritative grant store with SQLite as the local fallback. Approval creates a deterministic `approval:<approval_id>` grant row in Postgres. The mitmproxy path and the Rust data-plane shared mode both call the same consume function; Postgres locks the candidate grant with `SELECT ... FOR UPDATE SKIP LOCKED`, decrements it in one transaction, records a durable consumption outbox row, and then Serverware writes the hash-chained audit event to the Postgres audit store before returning success. If the HA grant store errors, JIT routes fail closed locally instead of forwarding upstream. Local Rust `POST /v1/grants` entries are treated as non-authoritative when shared mode is configured, which keeps one-use grants consistent across multiple Rust data-plane instances and any control-plane instance connected to the same grant store.

Docker also uses Postgres as the control-plane metadata store for credentials, routes, approval requests, WebAuthn registrations/challenges, Gmail proof cache entries, and request logs. The existing DB call sites go through a Postgres adapter so SQLite remains the local fallback, while Docker can run multiple control-plane instances against the same metadata, grant, and audit stores.

Auditors can inspect the active backend and pending consumption audit outbox through:

```bash
curl -fsS -H "X-Serverware-Admin-Token: dev-admin-token" \
  http://localhost:3000/api/grants/status

curl -fsS -H "X-Serverware-Admin-Token: dev-admin-token" \
  http://localhost:3000/api/metadata/store/status
```

For Rust JIT routes, the grant-consume audit event is required: if the data-plane audit spool is missing or full, the gate returns a local `503` instead of releasing a credential.

Runtime counters are available to auditors:

```bash
curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  http://localhost:3000/api/runtime/metrics
```

Latest local benchmark from `make bench` on the demo echo route, after 10 warmups and 100 measured requests:

```json
{
  "p50_ms": 15.753,
  "p95_ms": 23.18,
  "p99_ms": 28.147,
  "mean_ms": 16.791
}
```

This misses the target p99 under 20 ms for request-only policies on this machine, so the current evidence supports keeping mitmproxy as local/prototype mode and continuing the Envoy ext_authz/ext_proc or custom Rust/Go data-plane track from [goal.md](goal.md).

The Rust data-plane candidate in [data-plane/decision-gate-rs](data-plane/decision-gate-rs) isolates the request-only hot path from mitmproxy and FastAPI. It fetches an attested policy signing trust root from the control plane at startup, verifies the quote signature, nonce, optional quote-signing key pin, policy signing-key SPKI hash, and attested policy digest, verifies the Ed25519 policy signature against that trust root, optionally pins the expected policy signing-key hash from `SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID`, measures its own executable digest for data-plane attestation, compiles route/principal matching into an in-memory snapshot, hot-reloads changed signed bundles from a background watcher, retains the last good snapshot on malformed/unsigned/wrong-key bundles, clears local grant cache entries on policy hash changes, enforces raw HTTP `CONNECT` preflight with principal, source CIDR, hashed proxy bearer-token, and host/port allowlisting, performs CONNECT TLS interception with cached dynamic leaf certificates after the quote-gated data-plane CA handoff, handles sequential keep-alive requests inside an intercepted CONNECT tunnel, forwards absolute-form and intercepted HTTP proxy requests after the same policy decision, validates upstream TLS with `SERVERWARE_UPSTREAM_CA_BUNDLE`, injects credentials from broker-fed secret leases, applies Gmail response validation plus generic JSON `allowedFields` redaction for generic REST, X, and npm responses before releasing bytes, streams `request.bodyMode: "stream"` generic upload bodies to upstream from absolute-form sockets and CONNECT MITM TLS streams with backpressure and audit hashing, streams non-redacting `response.mode: "stream"` responses directly to the client with backpressure and bounded hashing, redacts `jsonlStream` request/response records, `jsonArrayStream` top-level array items, `jsonSseStream` `text/event-stream` JSON `data:` events, `jsonNestedStream` arbitrary nested JSON documents, `formUrlencodedStream` flat `application/x-www-form-urlencoded` pairs, and `csvStream` rows by header name to configured `allowedFields` while enforcing body, line, item, event, nested-value, pair-size, and record-size caps, watches the broker credential-generation and credential-lease markers in background tasks, classifies adapter operations, computes canonical request and operation digests, rejects decisions for stale/deleted/missing credential generations or missing secret leases, consumes one-use JIT grants through the authenticated shared control-plane grant endpoint backed by Postgres, consumes policy-declared shared rate limits through an authenticated control-plane metadata-store endpoint, ignores caller-supplied `credentialVersions`, overrides caller-supplied credential metadata with broker lease metadata, and returns credential injection plans by reference only. Request-only decisions without shared JIT or shared rate-limit constraints do not touch SQLite, Postgres, the control plane, or the filesystem, and no decision returns plaintext secrets.

Latest post-gate Docker benchmark, after 100 warmups and 1000 measured decision calls:

```json
{
  "p50_ms": 1.476,
  "p95_ms": 3.501,
  "p99_ms": 5.704,
  "mean_ms": 1.766
}
```

This supports choosing Rust as the current production data-plane track over a generic Envoy front-proxy configuration. Envoy should only replace it if a runnable ext_authz/ext_proc candidate proves the same explicit HTTPS CONNECT interception, dynamic attested leaf issuance, response mutation/validation, no hot-path DB/filesystem calls, and an acceptable TEE TCB.

## TEE Path

The current Docker build still stores dev materials locally, but their use is gated by signed attestation claims: the broker KEK is not used until `broker-kek` key release succeeds, and the Rust data-plane CA private key is not published until `decision-gate-ca` key release succeeds with the release-pinned Rust binary digest from `SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST`. The default development quote is self-signed by `/data/dev-tee-quote-ed25519.pem`; the AWS Nitro-compatible provider verifies real Nitro-shaped CBOR/COSE documents and, when `SERVERWARE_NITRO_REQUIRE_KMS_COMMAND=1`, refuses material release unless `SERVERWARE_NITRO_KMS_RELEASE_COMMAND` returns an allow decision bound to the canonical release request digest and a KMS/HSM key identity without plaintext material.

For a TEE deployment:

1. Boot Serverware inside AWS Nitro Enclaves or another selected TEE.
2. Produce a Nitro attestation document whose signed `user_data` binds the Serverware claims digest: image/runtime digest, policy bundle digest, data-plane binary digest, CA SPKI, rollback epoch, release channel, provenance digest, and public sealing key.
3. Release or unwrap the broker KEK and CA intermediate only after vendor quote verification, PCR allowlist checks, and KMS/HSM policy pass.
4. Seal refreshed OAuth tokens, wrapped DEKs, and approval grants to the TEE identity.
5. Log policy decisions externally with redacted URLs and route IDs, not raw credentials.

The proxy/policy boundary is already isolated enough for that migration: mitmproxy sees traffic, Serverware owns route policy and decrypted credential material, and agents only receive normal upstream responses.
