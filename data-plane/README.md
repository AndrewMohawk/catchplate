# Data Plane Candidates

The current production track is a Rust data plane. It now owns the hot-path policy decision component, absolute-form forwarding, explicit CONNECT MITM with dynamic leaf certificates, upstream TLS validation, credential injection, sequential keep-alive request handling, Gmail response validation/redaction, generic JSON response field redaction for non-Gmail adapters, policy-declared absolute-form and CONNECT MITM request-body streaming, policy-declared non-redacting response streaming, JSONL request/response streaming redaction, JSON array request/response streaming redaction, JSON SSE event-stream redaction, arbitrary nested JSON stream redaction, form-urlencoded stream redaction, CSV stream redaction, and one-use JIT grant consumption through the shared control-plane store. It is still not an arbitrary streaming mutation proxy: additional selected non-JSON request/response mutation formats need dedicated streaming validators beyond the current JSON Lines, top-level JSON array, SSE event-stream, nested JSON, form-urlencoded, and CSV paths.

## Rust Decision Gate

Location: `data-plane/decision-gate-rs`.

The gate loads `/data/policy-bundle.json` at startup, fetches the policy signing trust root from the control-plane `/attestation` endpoint through `SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL`, verifies the dev-signed quote signature, nonce, optional quote-signing key pin, policy signing-key SPKI hash, and attested policy digest, then verifies the Ed25519 policy bundle signature before compiling principals/routes/path templates into memory and serving `POST /v1/decide` on port `9090`. `SERVERWARE_POLICY_SIGNING_PUBLIC_KEY` remains a file-based fallback for isolated tests, but the Docker path does not trust a mounted public key directly. A background watcher reloads changed signed bundles into an atomically swapped in-memory snapshot, clears local grant cache entries on policy hash change, and retains the last good snapshot if a new bundle is unsigned, malformed, signed by the wrong key, or no longer matches the attested control-plane policy digest.

The decision API covers:

- principal checks from source CIDR, trusted headers, and hashed `Proxy-Authorization` bearer tokens with token expiry and token-specific source CIDR binding;
- raw HTTP `CONNECT` preflight that denies missing principal identity, missing/bad/expired/wrong-source proxy tokens, unknown hosts, and unknown ports before leaf-certificate generation;
- explicit CONNECT TLS interception with cached dynamic leaf certificates signed by the verifier-installed data-plane CA handoff, including sequential keep-alive requests inside one intercepted tunnel;
- absolute-form HTTP proxy forwarding for policy-allowed `http://` and `https://` targets, with proxy-auth and Serverware-only identity headers stripped before upstream forwarding;
- upstream TLS validation through `SERVERWARE_UPSTREAM_CA_BUNDLE`;
- host, port, method, and path-template route matching;
- request-only adapter checks for `generic.rest`, `gmail.v1`, `x.v2`, and `npm.registry`;
- shared route constraints for operation allow/deny lists, fixed-window credential quotas, query lookback windows, query numeric caps, JSON body rules, and JSON response date-window validation;
- Gmail recent-query rewrite planning and unproven direct-message read denial;
- X read/write classification and credential app metadata binding;
- npm publish/dist-tag classification, required field extraction, and JIT-required decisions;
- canonical request and operation digests bound to policy hash, credential ref, and credential version;
- non-authoritative local JIT grant cache through `POST /v1/grants` for dev fallback, addressed by principal, route, credential ref/version, policy hash, request digest, and operation digest;
- atomic one-use grant consumption through the shared control-plane grant endpoint before returning a credential injection plan when `SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL` is configured;
- control-plane approval publish integration, with shared-consume digest parity tested against a real proxy-created npm approval;
- optional `SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID` and `SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID` startup pins so a replaced control-plane quote signer or policy signing key is rejected before any policy snapshot becomes active;
- signed policy hot reload from a background watcher, with no request-path filesystem calls and fail-closed last-good retention for invalid bundles;
- broker-fed credential generation cache from `/data/credential-generations.json`, refreshed outside the decision path;
- stale JIT grant invalidation when credential generations rotate or are deleted;
- decision-time rejection for missing or deleted credential generations;
- caller-supplied `credentialVersions` ignored in favor of the broker cache;
- credential injection from broker-fed leases during forwarding, while decision responses still carry injection plans by credential reference only;
- Gmail response validation that blocks old `internalDate`, marks unproven list IDs as pending, validates recent list IDs before release, enforces `response.allowedFields` redaction, and fails closed on invalid JSON/date proofs;
- generic JSON response redaction for `generic.rest`, `x.v2`, and `npm.registry` routes with `response.allowedFields`, including demo tests that prove upstream received the bearer credential while the agent only sees non-secret authorization presence/scheme/hash markers;
- forwarded response proof headers for released buffered responses: `X-Serverware-Policy-Hash`, `X-Serverware-Request-Digest`, `X-Serverware-Operation-Digest`, and `X-Serverware-Response-Body-SHA256`, so clients can bind received bytes to the decision and audit record over the attested CA/TLS channel;
- `request.bodyMode: "stream"` for absolute-form and CONNECT MITM generic REST routes that do not need JIT or body mutation, requiring `Content-Length`, rejecting oversized bodies before read, streaming absolute-form bodies from the client socket, streaming CONNECT bodies through a bounded TLS-reader channel, and hashing streamed bodies for audit;
- `response.mode: "stream"` for non-redacting routes, using a direct writer with upstream backpressure, constant-memory SHA-256 hashing, policy `maxBodyBytes` preflight when `Content-Length` is known, fail-closed denial for unknown-length capped streams, and CONNECT keep-alive reuse after streamed responses;
- `request.bodyMode: "jsonlStream"` plus `response.mode: "jsonlStream"` for generic REST routes, redacting each JSON Lines record to configured `allowedFields`, enforcing `maxBodyBytes` and `maxLineBytes`, hashing raw and mutated bodies for audit, and covering both absolute-form and CONNECT MITM paths;
- `request.bodyMode: "jsonArrayStream"` plus `response.mode: "jsonArrayStream"` for top-level JSON arrays of objects, redacting each array item to configured `allowedFields`, enforcing `maxBodyBytes` and `maxItemBytes`, hashing raw and mutated bodies for audit, and covering both absolute-form and CONNECT MITM paths;
- `request.bodyMode: "jsonSseStream"` plus `response.mode: "jsonSseStream"` for `text/event-stream` JSON `data:` events, redacting each event payload to configured `allowedFields`, enforcing `maxBodyBytes`, `maxLineBytes`, and `maxEventBytes`, dropping arbitrary SSE metadata lines instead of forwarding possible secret-bearing fields, preserving only the `[DONE]` terminal marker, hashing raw and mutated bodies for audit, and covering both absolute-form and CONNECT MITM paths;
- `request.bodyMode: "jsonNestedStream"` plus `response.mode: "jsonNestedStream"` for arbitrary nested JSON documents, redacting objects and arrays to configured dotted `allowedFields`, skipping denied fields with serde's streaming deserializer instead of materializing them, enforcing `maxBodyBytes` and `maxNestedBytes`, hashing raw and mutated bodies for audit, and covering both absolute-form and CONNECT MITM paths;
- `request.bodyMode: "formUrlencodedStream"` plus `response.mode: "formUrlencodedStream"` for flat `application/x-www-form-urlencoded` bodies, redacting each key/value pair to configured `allowedFields`, enforcing `maxBodyBytes` and `maxPairBytes`, hashing raw and mutated bodies for audit, and covering both absolute-form and CONNECT MITM paths;
- `request.bodyMode: "csvStream"` plus `response.mode: "csvStream"` for CSV bodies with a header row, redacting each record by allowed header name, rejecting duplicate headers and records wider than the header, enforcing `maxBodyBytes` and `maxRecordBytes`, hashing raw and mutated bodies for audit, and covering both absolute-form and CONNECT MITM paths;
- bounded async data-plane audit emission into the control plane hash chain for CONNECT allow/deny, policy denials, response release/block, grant receipt, and JIT grant consumption, with JIT credential release failing closed if the required consume audit event cannot be queued;
- shared JIT grant consumption through `POST /api/data-plane/grants/consume`, so one-use grants are atomic across multiple Rust data-plane instances instead of process-local;
- broker-fed secret lease cache from `/data/credential-leases.json`, refreshed outside the decision path;
- fail-closed credential-bound decisions when the active credential generation has no matching secret lease;
- broker lease metadata overrides caller-supplied credential metadata before adapter checks;
- fail-closed startup on unsigned, tampered, or wrong-key policy bundles;
- dev-mode `GET /attestation?nonce=...` with nonce binding, runtime manifest digest, running executable SHA-256 digest, active policy hash, policy signing key ID, policy trust-root source, release provenance digest, and image-signature bundle digest when present;
- CA private-key handoff only after the control plane's signed quote key-release gate authorizes `decision-gate-ca` for the release-pinned Rust binary digest;
- external-command TEE quote/KMS provider hooks plus an AWS Nitro-compatible control-plane provider that verifies CBOR/COSE_Sign1 documents, certificate chains, PCR allowlists, Nitro `user_data` claim binding, and a canonical KMS/HSM material-release command response before key handoff;
- explicit `hot_path.sqlite_calls = 0` and `hot_path.filesystem_calls = 0` in each decision response.

Run it in Docker:

```bash
make bench-gate-rs
```

Latest Docker benchmark, `100` warmups and `1000` measured `/v1/decide` calls:

```json
{
  "candidate": "rust-decision-gate",
  "p50_ms": 1.559,
  "p95_ms": 3.3,
  "p99_ms": 6.081,
  "mean_ms": 1.784,
  "requests": 1000
}
```

The benchmark target first verifies Docker hardening for all running services: non-root UID/GID `10001`, read-only root filesystems, dropped Linux capabilities, `no-new-privileges`, PID limits, `noexec,nosuid,nodev` `/tmp` tmpfs, and the custom seccomp profile with a denied-`bpf` syscall probe. It then runs startup failure tests for a tampered signed bundle and a valid bundle launched with the wrong trusted signing-key pin. It verifies the Docker trust-root path by proving the running Rust gate uses `SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL`, exposes `policy_trust_root_source: "attested-control-plane"`, has no `SERVERWARE_POLICY_SIGNING_PUBLIC_KEY` env var, and refuses startup when `SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID` does not match the control-plane quote signer. It then verifies signed policy hot reload by removing a route, observing denial without restarting Rust, writing an invalid bundle, proving the last good snapshot is retained, and restoring the route. It then verifies raw CONNECT preflight behavior: known `demo-upstream:8443` is allowed only with the configured principal identity, proxy-auth principals require a valid hashed bearer token from an allowed source range, unknown host and port are denied, and malformed CONNECT targets fail closed. It then verifies CONNECT MITM with curl and a raw TLS client using the verifier-installed CA: `/echo` proves upstream bearer injection through non-secret response markers, proxy-auth principals work when credentials are presented only on the CONNECT request, Serverware-only identity headers are stripped before upstream, and GET then POST can reuse one intercepted CONNECT tunnel with correct keep-alive/close response headers. It verifies absolute-form forwarding denial, injection behavior, proxy-auth stripping, generic JSON response redaction for echo and X responses, policy-declared binary response streaming in both absolute-form and CONNECT MITM paths while preserving keep-alive reuse, policy-declared request-body streaming for uploads, JSONL request/response streaming redaction, top-level JSON array request/response streaming redaction, JSON SSE event-stream request/response redaction, arbitrary nested JSON request/response streaming redaction, form-urlencoded request/response streaming redaction, and CSV request/response streaming redaction in both absolute-form and CONNECT MITM paths. It verifies Gmail response validation/redaction: missing `internalDate` list IDs are marked pending, recent list IDs are marked validated, old `internalDate` responses are blocked with `502`, upstream echo fields are removed, and non-allowlisted message fields such as raw bodies are stripped. It then verifies the gate attestation nonce, runtime manifest digest, executable digest, policy hash, signing key, control-plane pinned binary digest, and image-signature digest. It verifies the control-plane signed quote/key-release gate for `broker-kek` and `decision-gate-ca`, including negative tests for stale rollback epoch, policy mismatch, data-plane digest mismatch, and unauthenticated status, verifies the external-command TEE quote/KMS interface, and verifies the AWS Nitro-compatible provider against a Docker fixture root while exercising real Nitro-shaped CBOR/COSE/PCR/user-data checks. It then creates a real pending npm approval through the mitmproxy path, approves it through the WebAuthn dev flow, verifies the control plane publishes the grant into Rust, and proves the Rust gate consumes exactly one matching Postgres grant through the shared control-plane endpoint before denying reuse and leaving no pending consumption audit outbox rows. It verifies that Rust-originated data-plane audit events are ingested by the control plane, verifies the Postgres audit chain backend, proves concurrent chain appends are serialized, verifies the Postgres metadata backend against direct table counts for credentials, routes, approval requests, WebAuthn rows, Gmail proof cache, and request logs, verifies the audit chain head is exported to the signed Merkle transparency log with an inclusion proof, generates signed release provenance with SBOM summaries and a CycloneDX 1.5 SBOM, signs per-image release statements into an image-signature bundle, and verifies both provenance and image-signature digests are anchored with inclusion proofs and exposed by both attestation endpoints. Finally, it runs semantic self-tests before timing: broker secret lease cache loaded, echo allow without secret disclosure, proxy-auth allow/missing-token/bad-token/wrong-source decisions, unknown route deny, Gmail weak-query rewrite, Gmail unproven body read deny, X read allow using broker metadata despite spoofed caller metadata, X write deny, npm missing-fields deny, local grant cache ignored when shared mode is enabled, credential rotation observation from the broker cache, stale caller `credentialVersions` ignored, and stale grant invalidation after rotation.

## Envoy Candidate Status

Envoy remains behind the Rust track until it proves all required production properties in `goal.md`: explicit HTTPS proxy CONNECT interception, dynamic attested leaf issuance, streaming request/response mutation, zero hot-path database/filesystem calls, and acceptable TEE TCB.

Current selection: continue with Rust as the production data-plane path. The Rust gate already has lower measured decision p99 than the mitmproxy end-to-end proxy path and keeps the policy/credential decision TCB small. Envoy should be revisited only with a runnable ext_authz/ext_proc plus explicit MITM proof harness, not as a generic forward-proxy configuration.

## Remaining Data-Plane Work

- Extend beyond the current JSONL, top-level JSON-array, JSON SSE event-stream, arbitrary nested JSON, form-urlencoded, and CSV redaction set only when a specific API requires another bounded streaming validator such as multipart or XML.
- Point `SERVERWARE_COSIGN_BINARY` and the cosign key/keyless identity settings at production cosign/Sigstore backed by KMS/HSM or workload identity; Docker exercises the same fail-closed adapter contract with a local cosign-compatible fixture.
- Point `SERVERWARE_TRANSPARENCY_LOG_URL` or a log-specific `SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND` at a public or managed production log for release channels; Docker exercises the same required-publish and signed-receipt contract with a managed-log fixture and an HTTP fixture.
- Run `make verify-apparmor-runtime` on a Linux Docker host with AppArmor enabled; Docker Desktop runs `make verify-apparmor-contract` to prove the checked-in profile and Compose override cover every service.
- Run `make verify-production-readiness` in the production release environment with a real Nitro NSM attestation helper, production KMS/HSM unwrap command, production cosign identity, production transparency log URL, and Linux AppArmor enabled; Docker now verifies those command schemas and fail-closed checks with local fixtures.
