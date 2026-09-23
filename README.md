> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Serverware

Serverware is a credential-control proxy for agentic flows. Agents keep using normal HTTP clients and normal endpoint URLs, but route traffic through Serverware as an HTTP(S) proxy. Serverware's CA lets it inspect HTTPS requests, inject credentials from its vault, and enforce local policies before the upstream service sees the request. Docker remains a development and integration environment; the authoritative production design runs the TLS endpoint and complete credential-handling proxy inside an attested enclave.

For the operator OAuth flow, policy assignment screenshots, and copy-pasteable agent instructions, see [docs/portal-oauth-agent-guide.md](docs/portal-oauth-agent-guide.md). For the current security review and production acceptance gates, see [docs/security-review.md](docs/security-review.md).

## Run

Current source does **not** pass control-plane startup: four declared WebAuthn
authority transitions and their evidence/admission adapters are missing. The
registry fails closed before startup. See
[the exact implementation blocker](docs/authority-transition-startup-blocker.md).
The commands below describe the intended development workflow, not a verified
working deployment.

```bash
make up
open http://localhost:3000
```

## catchplate-host Developer Handoff

The private `AndrewMohawk/serverware` repository is the canonical handoff. The
requirements and acceptance boundaries are in [goal.md](goal.md), the current
security gaps are in [docs/security-review.md](docs/security-review.md), and the
credential-policy language and implemented examples are in
[docs/credential-constraints.md](docs/credential-constraints.md). Build only a
clean, recorded `main` commit from a fresh checkout:

```bash
git clone git@github.com:AndrewMohawk/serverware.git
cd serverware
git switch main
git pull --ff-only
test -z "$(git status --porcelain)"
git rev-parse 'HEAD^{commit}'
git rev-parse 'HEAD^{tree}'
docker version
docker buildx version
docker compose version
```

catchplate-host must be a Linux/amd64 host with Git, Make, Python 3.11, Docker Engine,
Buildx, and Docker Compose v2. Do not put production credentials, signing keys,
KMS/HSM authority, or registry-promotion credentials in the checkout.

For one development build followed by startup, pull the one immutable base
service, build the application images once, and start without rebuilding:

```bash
docker compose pull grant-store
docker compose build serverware demo-upstream audit-anchor decision-gate-rs
docker compose up -d --no-build serverware demo-upstream audit-anchor
docker compose ps
curl -fsS http://127.0.0.1:3000/healthz
```

`make up` is the shorter development convenience command, but it includes
`--build`; do not run it after the explicit build above. The Compose stack uses
development credentials and loopback-only published ports. It is not a
production deployment or TEE claim. Stop it with `make down`.

If port 3000 is occupied, export `SERVERWARE_CONTROL_PLANE_HOST_PORT=13000`
before those commands and use `http://127.0.0.1:13000/healthz`. Default public
URLs and OAuth/OIDC callbacks follow that port; explicitly configured URLs take
precedence. The default stack needs no custody credentials. Custody requires
both `docker-compose.yml` and `docker-compose.custody.yml`, the `custody` profile,
and the real required generation and authority inputs. Profile selection alone
does not provision them.

`python3 scripts/test_development_compose.py` checks this configuration without
Docker daemon access. For prepared Python engineering checks that need Git,
build the `development-test-runtime` Dockerfile target during preparation and
run it against the frozen source afterward. It adds test tooling only; the
default application image remains unchanged.

The separate `development-postgres-test-runtime` target also includes PostgreSQL
tools for focused SQL engineering checks. Prepare it before verification; tests
must create a disposable local Unix-socket cluster with networking disabled and
must never point at a production database. This target does not enter the
default or production image, and a passing query test does not establish the
complete authority protocol, independent witness state or WebAuthn startup.

Production candidates are intentionally built without network access from one
separately published, immutable dependency snapshot. At this handoff,
`requirements.lock` contains the patched `cryptography==50.0.0`, while
`production-dependencies/python-linux-amd64.sha256` still identifies the prior
lock and wheelhouse. The dependency-release owner must first create a new
Linux/amd64 wheelhouse from the committed hash-locked requirements, publish a
new credential-free HTTPS snapshot, and commit its reviewed snapshot ID and
SHA-256 values. Do not edit the manifest merely to match the new lock, reuse the
old wheelhouse, disable verification, or allow network access inside the
production build.

An unpublished candidate can be prepared with the bounded
[dependency-snapshot producer](docs/production-dependency-snapshot.md).
It checks carried-forward Rust artifacts and validates fresh Python wheels in
a separate offline container. It does not publish anything, change reviewed
pins, or supply release authority.

Once that dependency-snapshot commit is on `main`, use its exact immutable URL
and build all production artifacts before running any verification lane:

```bash
export SERVERWARE_PRODUCTION_DEPENDENCY_SNAPSHOT_URL='https://artifacts.example/serverware-production-dependencies-linux-amd64-v2'
make fetch-production-dependency-cache
make verify-production-dependency-cache
make build-production-images
make build-production-python-runtime
make build-production-launcher
make production-handoff \
  PRODUCTION_IMAGE_REGISTRY_PREFIX=registry.example/serverware \
  PRODUCTION_IMAGE_TAG="$(git rev-parse --short=12 HEAD)"
```

Replace both example hosts with operator-controlled infrastructure. Keep the
resulting `.tmp/production-images-build.json`, production runtime and launcher
artifact directories, and `.tmp/production-handoff.json` together with the
recorded commit and tree. Publishing, signing, deployment, host readiness,
Nitro/KMS evidence, and independent final verification are later trust-domain
steps; a successful build does not establish them.

The `coder-*` targets are not ordinary developer build commands. The current
workflow requires the separately installed root-owned v12 controller and its
signed fixed-operation bundle; the older `coder-build-all` path also remains
fail-closed on the prerequisites listed below. Do not grant repository code a
Docker socket or replace these controls with an ad hoc privileged runner.

## Build And Verification Boundary

Finish source, schema, documentation, and review work before any expensive execution. Then freeze one clean commit, run `make coder-build-all` once on catchplate-host, and run `make coder-test-no-build` sequentially without rebuilding or pulling. Coder output is cooperative engineering diagnostics only; it is not hostile-source containment, release provenance, server identity, or attestation.

The Coder lane requires a task-exclusive disposable Linux/amd64 DinD sidecar with `/var/run/docker.sock`, the expected ownership labels, and terminal sidecar destruction as the outer cleanup boundary. The approved workspace currently has no Docker socket. Repository code must never receive that socket. A root-owned controller outside the worker cgroup owns it and exposes only the signed fixed operations `describe/v1`, `openLane/v1`, one-use `runBuild/v1`, one-use `runNoBuild/v1`, `status/v1`, `cancel/v1`, `closeLane/v1`, and `receipt/v1`; there is no generic shell, path, environment, Docker, Compose, or exec API. Requests bind the exact source, approved coverage baseline, phase, daemon, controller, image identities, peer credential, sequence, nonce, and absolute monotonic deadline. Only a signed terminal receipt proving all task resources and the daemon/socket/cgroup/mount/network/storage state are destroyed closes the run.

The controller supplies `CODER_COVERAGE_BASE_COMMIT` as one exact approved ancestor. Build preparation binds that commit and tree, computes changed-test coverage from it, and rejects deleted or renamed tests until a separately reviewed transition contract exists. The no-build lane now also requires the current clean HEAD and tree to equal the exact built commit and tree. An immediate first parent is not an acceptable substitute for the approved baseline.

The closed controller contracts are [request v1](schemas/coder-test-controller-request.v1.schema.json) and [receipt v1](schemas/coder-test-controller-receipt.v1.schema.json). They are installation inputs for the external controller, not proof that the current Coder host has installed it.

`coder-build-all` now stops before pulls or builds while any `blocked-prerequisite` remains. The exact remaining prerequisites are:

- a reviewed privileged OCI launcher that creates the sealed clean-room mount namespace and enforced AppArmor/seccomp boundary for `test_agent_trust_clean_room.py`;
- a digest-bound Chromium/Node/npm closure, current completion-v6 same-journey inputs, and a trusted one-use npm companion broker that shares the browser network namespace without granting Docker authority for `test_portal_browser_oauth.py`;
- a root-owned fixed-command response-proof controller that owns the disposable DinD socket and exposes only the frozen lifecycle required by `test_response_proof_capture.sh`.

`test_production_host_preflight.py` has a prepared no-network/no-socket runtime image. `test_production_launcher_adversarial.py` is prepared during the build phase and run from its exact prebuilt image during no-build; it is not excluded. In the standalone split workflow, terminal cleanup removes the exact task images and dependency resources introduced by the run. There is no documented retain option. `SIGKILL`, daemon loss, or host loss still requires destruction of the exclusive disposable sidecar.

Coder must not receive production signing keys, KMS/HSM authority, promotion credentials, witness credentials, action-gate credentials, or release-publication authority. The current source tree remains unbuilt and unexecuted; all earlier test totals, image IDs, screenshots, transfer manifests, and journey results belong to older source snapshots.

### Response Observation V2

Response-observation v2 is a new negotiated Rust contract, not a compatible widening of v1. It binds one attempt to typed policy, authorization, credential-authority, exact staged target-request, target-egress, upstream-observation, attestation, publication, retrieval, and terminal states. The gate independently retrieves the immutable HTTP/1.1 object before consuming dispatch authority; signed credential-transition records, provider-idempotency profiles, ambiguous-outcome recovery, fencing, replay protection, and one retrievable finalized envelope prevent an uncertain or failed publication from authorizing a replacement statement.

The source also defines separately keyed state, credential-transport, policy-verifier, immutable-ledger, release/publisher, cleanup-watchdog, and custody-router services plus generation activation and an external Nitro verifier interface. These are source contracts until the frozen commit builds and executes. Even a passing catchplate-host run is only engineering evidence; the production claim additionally requires independently pinned Nitro/KMS/HSM/release/transparency/witness authorities, live provider recovery evidence, and fresh verifier challenges. V2 does not claim provider truth, downstream delivery, nonce-free traffic, CONNECT establishment, malformed TLS, streamed requests, or Gmail fanout causality.

### Historical Experimental Consolidated Lane

The remaining preparation and lane details in this section document the superseded experimental consolidated design and are retained for source-contract history. Do not interpret them as current Coder provisioning instructions or as a production acceptance path.

Before resetting any prior output, that experimental preparation contract performs a read-only preflight for Linux amd64 and a pinned Git source closure. It expected npm `11.8.0`, uv `0.5.26`, Rust/Cargo `1.88.0`, Python `3.11`, bubblewrap, `lsof`, Docker CLI access through a dedicated socket, a functioning `systemd --user` manager, cgroup-v2 delegation, and permitted user, PID, and network namespaces. Those requirements describe only the historical experimental lane.

Preflight also checks configured CPU/memory/free-disk minimums and the current-user-owned mode-`0600` dedicated Unix Docker socket. The independently authenticated Linux/amd64 reference is `docker.io/library/python:3.11.15-slim-bookworm@sha256:28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941`; the tag/index digest is `sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba`, and the expected local image ID/config digest is `sha256:7e666cfcc7bd4c47b26b7a5ec0116d80e9bc5415ea06c0dc0bd117a50e9fa6c6`. These values were resolved from Docker Registry v2 metadata as of 2026-07-14. The image still must be preloaded through the dedicated daemon and remeasured locally; the consolidated pass neither builds nor pulls it. Python `3.11.15` being available as this Docker image is independent of uv `0.5.26`'s standalone Python catalog, which provides Python `3.11.11`; do not conflate the two distribution channels. A mutable or non-official image reference, shared or TCP Docker daemon, image pull, platform mismatch, image ID mismatch, unusable read-only bind, or residual probe container fails before reset. Binding an expected local ID prevents phase-to-phase image substitution; by itself it does not establish image origin, supply-chain provenance, source provenance, independent execution, server identity, or TEE provenance.

`make build-consolidated-test-artifacts` performs all permitted downloads, dependency resolution, compilation, package construction, offline installation into prepared environments, artifact-integrity checks, and sealing. It builds the checksum-closed Linux and host wheelhouses, sealed clean-room environment, host verifier environment, Rust runtime and prebuilt focused test harness, browser environment, dedicated proxy-test environment, and pinned Chromium installation. It performs no behavioral test beyond package, archive, checksum, manifest, and installed-artifact integrity checks. The browser-only Python closure is hash-locked separately in `requirements.browser.lock`; the production `requirements.lock` is not widened with Playwright.

Both credential-constraint lanes use the dedicated proxy-test Python environment and its complete resolver-produced `requirements.proxy-test.lock` closure for `mitmproxy==11.0.2`; neither lane may fall back to the browser or production environment. Preparation downloads that closure into its own checksum manifest, installs it into the proxy-test environment, validates the installed mitmproxy version, and binds the exact interpreter, lock, wheelhouse, installation, and manifest into the consolidated contract. The checked-in proxy lock is generated for CPython 3.11 on Linux amd64 (`x86_64-manylinux_2_17`) from its declared top-level inputs; a lock resolved for macOS or another target is not valid input. This separation is mandatory because authoritative mitmproxy metadata requires `cryptography<44.1`, while the production lock pins `cryptography==50.0.0`; neither environment is permitted to satisfy the other's lock, and the production lock remains unchanged.

`PORTAL_BROWSER_PLAYWRIGHT_BROWSERS_PATH` selects the prepared Playwright browser root. `PORTAL_BROWSER_CHROMIUM_INSTALLATION_SHA256` is the `sha256:` closure digest of only the exact executable-bearing `chromium-*` or `chromium_headless_shell-*` version directory beneath that root; it excludes `.links`, sibling browser versions, and other bookkeeping. The digest should come from authenticated build metadata or a separately prepared golden installation. Computing it from the same newly downloaded directory establishes only local consistency, not supply-chain provenance.

Preparation records one source- and artifact-bound manifest. Source enumeration uses the manifest-bound Git executable rather than ambient `PATH`, and portal listener ownership uses the manifest-bound `lsof` executable. `make verify-consolidated-no-build` first rejects source, tool, environment, image, or artifact drift and then executes the already prepared checks sequentially. It never downloads, resolves, compiles, builds, installs, seals, or pulls an image. On Linux, each non-container lane runs under bubblewrap with private PID and network namespaces, `--die-with-parent`, read-only source and artifact mounts, bounded writable tmpfs, and live-bounded stdout/stderr with containment-wide kill and reap on timeout or output overflow. Systemd execution containment starts from `NoExecPaths=/` and admits only the lane's exact manifest-bound executables plus the exact resolved ELF interpreter and recursively measured runtime-library files whose paths, sizes, and SHA-256 digests were recorded during preparation and remeasured before launch; it does not broadly permit `/usr/lib` or another mutable library directory. The clean-room lane reaches only `AGENT_ENROLLMENT_DOCKER_HOST`, uses the exact preflighted image ID with `--pull=never` and no external container network, and reuses the sealed environment prepared in the first phase. Its deterministic name and labels bind the frozen manifest and lane before launch. Both the inner script and outer supervisor remove that exact container through the dedicated socket, including timeout, output-limit, child-error, and drift-error paths, and the outer supervisor verifies absence. Every lane remeasures the frozen source, manifest, tools, image, and artifacts before and after execution in a `finally` path, so a child failure cannot suppress drift or cleanup failures; both failure classes are reported when both occur. `make verify-consolidated` is the convenience target that performs those two phases in order. Any source change after preparation invalidates the manifest and requires a new preparation phase.

The pre-correction Coder staging transfer matched 260 source files against transfer manifest `5d3a4211f0111d3626f2b2e1a96dad41199ee082eea43f4d02e8f1849b16ae28`. That was a non-final transport staging check, not a frozen-source, build, test, or execution proof. The documentation corrections in this batch postdate and invalidate that staging identity; the final source closure must be transferred and remeasured again after all edits are complete.

The default Compose stack uses known development credentials and binds every published control-plane, audit-anchor, and proxy port to `127.0.0.1`. Treat it as local-only: do not expose those ports through a tunnel, port forward, or container-network bridge. Production uses the separate hardened Compose and readiness path described below.

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

The Compose development token is `dev-admin-token`. A production deployment supplies a high-entropy token only through the absolute path in `SERVERWARE_ADMIN_TOKEN_FILE`, or uses the OIDC/WebAuthn/RBAC flow in [goal.md](goal.md); plaintext production token variables are rejected. The UI keeps a manually entered token only in page memory, sends it as `X-Serverware-Admin-Token`, and loses it on reload; it never writes that token to browser Web Storage. Serverware also accepts pinned OIDC bearer JWTs for automation and initiates browser OIDC Authorization Code login through `GET /api/auth/oidc/start`. Browser login uses S256 PKCE, one-use encrypted server-side state, a separate browser-binding cookie, and an OIDC nonce. The callback validates the returned ID token against the configured issuer, audience, pinned JWKS, allowed algorithms, nonce, subject, and role claim, but never stores the raw token. It creates a server-side record containing only token digests and puts a random opaque token in an `HttpOnly`/`SameSite=Strict` cookie. Production keeps that token nonprivileged for at most five minutes until a trusted WebAuthn assertion atomically claims the challenge, advances the authenticator counter, binds the session to the exact credential/trust generation, rotates the token, and activates it. If the database commit succeeds but the rotated cookie cannot be delivered, one exact assertion-bound, short-lived retry record can reissue the encrypted active token once; it cannot repeat authentication or activate another session. Cookie-authenticated unsafe control-plane requests require the double-submit CSRF cookie/header pair. Application responses add no-store, anti-framing, no-sniff, no-referrer, same-origin isolation, permissions, CSP, and HTTPS HSTS headers.

Production mounts nine service credentials as read-only files and rejects an environment/file pair for the same setting. The admin and first-WebAuthn-enrollment bootstrap files must be bounded, non-symlink regular files owned by `65532:65532` with mode `0400` or `0600`. The six independently scoped data-plane files for credential leases, audit ingestion, grant consumption, rate-limit consumption, release authorization, and management, plus the separate audit-anchor file, must be owned by `0:65530` with exact mode `0440`. The control plane and gate join shared group `65530` only where required; no universal internal bearer is used.

The Compose profile maps that token to `user:demo` with the demo admin roles so the demo NPM route can enforce its configured approver allowlist. Production requires browser OIDC plus WebAuthn MFA. In addition to the pinned issuer/audience/JWKS/role settings, configure `SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED=1`, `SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED=1`, bounded pending/challenge TTLs, HTTPS authorization and token endpoints on the issuer origin, `SERVERWARE_OIDC_CLIENT_ID`, an owner-only `SERVERWARE_OIDC_CLIENT_SECRET_FILE`, the exact `${SERVERWARE_PUBLIC_URL}/api/auth/oidc/callback` redirect, scopes including `openid`, and `client_secret_basic` or `client_secret_post`. Startup revokes legacy unbound opaque sessions, and every privileged cookie lookup rechecks the bound credential, current trust bundle digest/sequence, authenticator class, and authoritative RBAC state. First enrollment is available only for an OIDC subject with zero retained credential history and requires the production bootstrap token; it still must prove the new key before session activation. Production recovery uses a separately operated offline Ed25519 root whose public key alone is mounted into Serverware. A lost still-active last key requires one signed decommission statement and a replacement requires a second signed registration statement; the recovered key must then complete an ordinary WebAuthn assertion before the pending session becomes privileged. Production also requires a PostgreSQL recovery witness on a different server address or port from the metadata store; the witness burns each signed authorization and advances its per-user sequence before metadata commit, so a failed metadata transaction requires a fresh offline signature. This non-colocation and rollback contract is implemented and locally tested, but still requires a real two-server PostgreSQL race and rollback exercise before production acceptance. When `SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED=1`, credential, route, and policy-publish mutations require a WebAuthn assertion from `/api/control-plane/mutations/webauthn/options`; the challenge binds only the canonical mutation payload digest, not plaintext credential material. When `SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED=1`, those high-risk mutations first return `428 control_plane_approval_required`; a different authorized operator approves `/api/control-plane/approvals/{id}/approve`, and the original requester retries with `mfa.approvalId`. With mutation WebAuthn enabled, the second operator's approval also requires an assertion bound to the stored action, resource, and payload digest. Serverware records the verifying WebAuthn row, rechecks it during consumption, and atomically invalidates approved but unused control-plane authority and bound browser sessions if that passkey is explicitly revoked or loses attestation trust.

The production recovery-witness check is stronger than DSN or listener inequality: metadata and witness roles must expose different PostgreSQL `system_identifier` values and operators must provide distinct bounded `SERVERWARE_METADATA_STORE_FAULT_DOMAIN_ID` and `SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID` pins. Aliases or different listeners on one cluster fail closed. Both roles therefore need permission to execute `pg_control_system()`; the pins are deployment identities, not secrets. The local suite covers alias/listener rejection and parallel one-winner finalization, while real independent fault-domain operation and rollback remain production evidence.

Every control-plane launch path invokes the same startup preflight. The supported release path is `python -m serverware.control_plane_runner`, which additionally selects Serverware's pinned signed-only Uvicorn HTTP/1.1 protocol. It validates TLS pairing, production TLS, internal-service identity, WebAuthn/two-person requirements, setup-receipt trust, key-unseal custody commands, an active signed policy, policy high-water state, database initialization, and CA material before runtime workers start. A direct diagnostic launch such as `uvicorn serverware.app:app` still runs the FastAPI preflight and signs completed application responses, but it is not a release path because stock Uvicorn can synthesize unsigned protocol or application-error responses outside ASGI. `make verify-control-plane-startup` proves the shared gate runs before the wrapper server and before FastAPI workers.

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

- CA-backed HTTPS interception through mitmproxy only for credentialless development compatibility and through the Rust decision gate for every production credential path.
- Fail-closed blocking for unknown routes.
- Principal access control using source CIDRs, required trusted identity headers, and hashed `Proxy-Authorization` bearer tokens bound to agent ID, source CIDR, and expiry.
- Bearer token injection from the encrypted credential vault.
- Portal OAuth login for Google and X/Twitter using Authorization Code with PKCE, one-use server-side state bound to a state-specific host-only `Secure`/`HttpOnly`/`SameSite=Lax` browser nonce cookie, encrypted OAuth token JSON storage, and audit records that omit auth codes and token material. Managed OAuth policies are restricted to canonical `Authorization: Bearer` injection from `access_token`; the broker and prototype runtime project leases/caches to an access-token-only JSON object, so refresh material never crosses into the data plane. State-specific cookies let independent provider flows finish out of order without weakening callback binding. WebAuthn mutation MFA runs before redirect when configured; production two-person authorization is deferred until callback identity discovery, when the encrypted token is staged and a second approval binds the exact provider subject/account, granted scopes, X app ID when applicable, expiry metadata, and token-source digest before atomic activation by the original requester. A durable Setup flow additionally binds a canonical setup ID and revision to the OAuth start, stores the setup ID only in the one-use server-side state, verifies the owner/provider/state-digest relationship at callback, and, only after a successful callback, binds either the exact active credential generation or the pending-activation row back to that same session before returning the browser to `/?setup=<id>`. Provider denial and callback validation, exchange, or persistence failure are terminal callback outcomes rendered as non-redirecting error pages. Pending activation must present the same setup ID and current CAS revision; the setup ID is not sent to the provider or copied into credential metadata.
- OAuth activation and disconnect have explicit provider-revocation states. Cancellation, expiry, exact-account approval denial, or any post-token-exchange validation/persistence failure retains encrypted revocation work until Google/X confirms revocation; bounded background reconciliation uses leased claims and exponential backoff, and expired activation rows no longer consume activation capacity. Active disconnect first marks the credential `revocation_pending`, immediately excludes it from normal control-plane reads, refresh, injection, and new or renewed leases, and deletes local material only after provider revocation. A previously issued Rust lease remains a bounded capability until its original at-most-five-second expiry: after release dispatch, the gate revalidates policy, generation, secret fingerprint, metadata, and expiry immediately before upstream contact, requires at least 250 ms remaining, and caps the complete upstream attempt to that original expiry. A provider failure leaves `revocation_failed` encrypted material for retry. X refresh always queues the superseded access token and queues the old refresh token only when the provider rotates it; reconnect replaces the grant and queues both old tokens. Reconnect also binds the existing credential ID, version, provider, subject, and account and rejects mismatched or stale callback material. If the retirement queue is full, replacement and any approval consumption roll back together. Google reconnect is deliberately disconnect-then-connect because Google revocation invalidates the account/project grant rather than one logical token.
- `scripts/oauth_provider_simulator.py`, `scripts/test_oauth_http_flow.py`, and `scripts/test_portal_browser_oauth.py` cover the Google/X lifecycle through the real FastAPI middleware and endpoints against a bounded local HTTPS authorization server. The HTTP fixture validates client authentication, exact redirect URI, PKCE S256, one-use codes, scopes, identity, refresh rotation, and revocation while checking that endpoint responses, audit records, pending rows, durable queues, and simulator observations contain no token values. The portal source drives credential assignment through the authenticated authority-package, decision-gate publication, and finalization contracts. The current browser lane is still unexecuted for this frozen source, so it is not production activation or live-provider evidence.
- A typed policy bundle with strict JIT binding schema, bounded generic REST config, explicit success/error response profiles, safe response-header allowlists, response `allowedFields` redaction, and a stable policy hash exposed through quote-backed `/attestation`. Credential injection is a closed, type-specific contract: bearer, Basic, custom-header, query, and cookie modes admit only their applicable fields, require explicit Basic usernames or custom target names, reject reserved targets and controls, cap Python parity values at 16 KiB, require canonical cookie-octet values, and never reinterpret a selected Basic password as another credential object. Generic REST `request.requiredHeaders` can require bounded, pattern-checked forwarded headers; the Stripe PaymentIntent example captures its valid `Idempotency-Key` and permits one use of that key per 24 hours under a separate five-operation UTC-day cap.
- A shared credential-constraint layer for route-level fixed/calendar/sliding quotas, weighted budgets, bounded uniqueness, operation allow/deny lists, query lookback windows, query/page caps, durable cursor traversal, UTC schedules, exact request values, JSON/form body shape rules, response envelopes, response date/JSON validation, field projection, and bounded request-to-response field binding. Credential-bearing generic buffered JSON/form routes must bind the matching non-empty `jsonBody`/`formBody` allowlist; credential-bearing projected responses must have a non-empty bounded field projection in schema, Python, and Rust. `request.operation` can capture explicitly declared form fields, top-level typed JSON fields, matched route parameters, and a SHA-256 computed from the exact admitted buffered request bytes, with admission proving required body types and exact path placeholders before activation. The common templates use this to bind Slack's returned channel to the post, a Stripe customer response to `{customer_id}`, and an object-store response to `{artifact_id}` plus the Serverware-computed request digest echoed by the provider. The checked-in example catalog contains exactly 14 credential declarations and 19 routes, including the single canonical hardware-approved GitHub issue-create route, a three-page Google Calendar traversal with a required recent outbound request window, bounded and non-stored OpenAI Responses with daily count and requested-token budgets, one hardware-approved Cloudflare DNS update per day, and hardware approval for every Twilio SMS to a finite recipient set. Every generic example admits only an explicit finite success/error status set and bounded semantic headers before its success or error projection runs. Missing or mistyped request sources deny before credential release; a missing or mismatched success-response field becomes a synthetic `502` before any upstream response bytes are released. The generic Calendar contract does not prove the polymorphic returned event-start window; that stronger response guarantee requires a typed adapter. Request-dependent signing, body credential insertion, client certificates, and multi-fragment credentials likewise require typed adapters rather than policy templates. These are Serverware policy contracts, not claims of live-provider, PCI, or other external validation. See [docs/credential-constraints.md](docs/credential-constraints.md) and [policies/credential-limits.examples.json](policies/credential-limits.examples.json).
- A policy publish workflow where `/api/policy/candidate` validates and signs a candidate bundle with diff and exact-route selection dry-run results, `/api/policy/publish` enforces monotonic sequence/rollback rules, `policy_publisher` RBAC, optional WebAuthn mutation MFA, required two-person production approval, required production dry-runs, and staged-candidate review. Dry runs prove route selection only; schema and semantic compilation validate the policy language, while runtime enforcement still requires measured candidate evidence. A staged candidate receives no proxy traffic. Active-policy baseline events and caller-supplied direct audit rows are untrusted, zero-authority observations and cannot authorize a candidate. Durable candidate evaluation, signed readiness, evidence custody/generation, decision-gate publication, and authenticated prepare/inclusion/finalize authority contracts are implemented in source; the legacy direct activation endpoint is disabled. Production acceptance still requires this exact source to be built and deployed with independently controlled authorities, measured gates, trusted time, TEE evidence, and externally witnessed state. Direct full publication remains a development-only option when production staging is not required.
- Persistent policy high-water records in the control plane and Rust gate, so a signed bundle with a stale sequence or rollback epoch is rejected across reloads and restarts; attestation and key release bind the active high-water digest.
- A fail-closed Gmail adapter that forces `newer_than:30d`, tightens weaker existing age guards, caps `maxResults`, validates response `internalDate`, redacts responses to `allowedFields`, and only allows message reads for IDs observed from validated recent responses under the same scoped proof context. When Gmail's ordinary list response omits `internalDate`, the production Rust gate performs policy-bounded, same-origin `format=metadata&fields=id,internalDate` child reads before releasing any list result. Every child reacquires the exact credential generation, has independent body and time bounds under one total deadline, validates the echoed ID and canonical millisecond timestamp, and either hydrates, is withheld before dispatch, or makes the parent fail closed. A transport failure after child dispatch is recorded as provider-outcome-unknown with retry forbidden, never as definitely not sent. Cache insertion occurs only after response projection and mandatory start/completion audit acknowledgement. Routes that combine this multi-upstream workflow with response proofs are rejected until a proof format can bind the complete fanout.
- An X adapter that allows configured read operations, blocks write methods, denies unconfigured read operations, binds the route `appIds` policy to credential metadata, and redacts responses to policy-selected fields.
- An npm adapter that classifies operations before JIT, denies publish requests missing package/version/integrity fields, requires approval only for configured sensitive operations, and redacts publish responses before returning them to agents.
- JIT approval where the first publish request fails closed with `428`, approval requires a short-lived server-issued receipt for the exact redacted review digest, token-only or review-skipping approval fails with `412`, WebAuthn signs the receipt and creates a one-use request-digest-bound grant in the HA Postgres grant store, and repeated approval fails with `409`. Canonical requests and redacted review documents are digest-prefixed AES-GCM ciphertext at rest, the stored target URL is only a SHA-256 commitment, durable release attempts retain digest-only operation-context and binding commitments, and quota/counter operation columns retain only deterministic SHA-256 commitments; startup migrates the corresponding legacy plaintext rows without changing quota state. On retry, the Rust data plane atomically reserves the grant and shared quotas before credential injection. A request proven not to have reached dispatch is cancelled and refunded; after the gate records dispatch, `forwarded` consumes one use and every failure or ambiguous result commits conservatively as indeterminate. Grant consumption is audited and grant or review-receipt reuse fails closed.
- Break-glass grants through `POST /api/break-glass/grants` and `POST /v1/break-glass/grants`, requiring approver RBAC plus configured WebAuthn/two-person mutation controls, creating a normal digest-bound one-use JIT grant, and auditing `approval.break_glass_granted` with the human reason and no credential material.
- JIT denial records where approvers can attach an optional reason to `/api/approvals/{id}/deny`; the reason is stored on the approval, written to the hash-chained `approval.denied` audit event, and searchable through audit search.
- Redacted JIT approval review through `GET /api/approvals/{id}/review` and the portal approval-review panel, including principal/source identity, route, credential version, policy hash, normalized operation fields, body hash, redacted payload summary, risk flags, previous similar approvals, and exact retry semantics without exposing secrets. The endpoint hashes that document and issues a short-lived approver-bound receipt; WebAuthn and the final approval transaction must present the same unused receipt and digest. Both the portal and approval API fail closed if the active policy changed after the request was created.
- WebAuthn registration verifies packed/fido-u2f hardware attestation chains against signed, rollback-protected FIDO/YubiKey trust bundles before assigning a hardware class. A known YubiKey AAGUID without a trusted chain remains `unknown`.
- Non-public control plane APIs: `/ca.pem`, `/api/bootstrap`, credential CRUD, route CRUD, approvals, logs, audit, policy status, and demo seeding require the admin token.
- OIDC bearer-token and browser-session control-plane auth where RS256, ES256, or Ed25519 JWTs are verified against a pinned JWKS, issuer, audience, expiry, and role claim before FastAPI RBAC dependencies accept the identity. Browser authorization adds S256 PKCE, one-use state, browser and OIDC nonce binding, a digest-only opaque server-side session, WebAuthn activation with token rotation, durable logout/revocation, and CSRF enforcement for cookie-authenticated mutations.
- Optional production mutation MFA where credential and route create/update/delete operations must carry a WebAuthn assertion over the canonical mutation payload digest before the audited change is accepted.
- Two-person control-plane approval where high-risk credential, route, policy-publish, RBAC/deprovisioning, and generated admin-token rotation changes are bound to a canonical payload digest, store only redacted request summaries, block self-approval, require a different authorized role owner, consume the approval once, and audit request, approval, consumption, and mutation evidence. When mutation WebAuthn is enabled, the approval decision is bound to the exact approval ID, requester, expiry, decision, action, resource, payload digest, operator, and passkey record; revocation or trust withdrawal invalidates unused derived authority.
- A bounded metadata audit outbox that is written in the same PostgreSQL transaction as control-plane security mutations, then leased and delivered idempotently to the hash-chained audit store. Startup drains the outbox before audit verification; capacity exhaustion and unrecoverable delivery failure stop progress instead of recording an audit event for rolled-back metadata or committing unauditable authority.
- Database-authoritative RBAC/bootstrap/token operations: `/api/bootstrap` writes a hash-chained `control_plane.bootstrap` event; `/api/rbac/role-bindings/{subject}` and `/api/rbac/deprovision` require the current `expectedGeneration`, commit the binding, global CAS generation, two-person approval consumption, and audit intent in one metadata transaction, and publish an owner-only repairable JSON projection after commit. Trigger-maintained binding-table revisions force a full-state digest check after every row change, then allow constant-cost authorization reads until the next revision; replaying an old valid row therefore fails closed. OIDC administrators and second approvers are revalidated against the current binding under the commit lock. Credential create/update, route CRUD, direct development policy publication, and OAuth uncertainty resolution commit approval consumption, mutation, and authoritative audit together. Production canary activation is not claimed by this source pass and must remain fail closed until the candidate evidence, generation, and atomic authority lanes are integrated and validated. `/api/control-plane/tokens/admin/rotate` rotates only generated-file admin tokens while auditing old/new token hashes without exposing the new token in the audit log.
- Signed policy bundles and a hash-chained audit log that can be checked with `GET /api/audit/verify`.
- Searchable audit review through `GET /api/audit/search` with filters for event type, actor, principal, route, policy hash, credential ID/version, approval ID, decision, attestation measurement, time window, and raw text.
- Envelope-encrypted credentials with per-credential DEKs, visible credential versions that advance when secret material or enforcement-relevant metadata changes, and JIT/audit records bound to the exact credential generation.
- One administrative credential trust domain per deployment. Operators with credential-management roles act on the shared inventory; credentials have no tenant ownership boundary, and credential visibility or mutation is not isolated by tenant.
- Recipient-bound, response-signed credential delivery from the control plane to the Rust data plane, with at most five-second in-memory secret leases, one-use nonces, atomic cache replacement, and no active plaintext credential-generation or credential-lease file transport. Cold policy scopes are neither prefetched nor background-refreshed. A real request or authorized preview synchronously singleflights a secret-free `generationMetadata` check; only a successful authenticated non-preview request marks that exact scope hot for 30 seconds. Background work iterates the bounded hot set, not the policy Cartesian product. Non-JIT hot scopes may renew secret leases, while JIT hot scopes refresh metadata only and can request `dispatchSecret` solely after exact atomic release reservation. Expired secret leases are removed and zeroized.
- A Docker operator CA installer that runs the client verifier, checks attestation freshness, dev quote signature/claims, policy signature/digest, signing key hash, release channel, rollback epoch, and CA SPKI, then copies the verified CA into the agent runtime path.
- Agent enrollment packets from `POST /api/agents/enrollment`, with principal identity requirements, attestation pins, proxy environment variables, bodyless GET/HEAD allow canaries, non-executable write previews, and deny-by-default egress. Kubernetes receives a NetworkPolicy; a host or VM receives an atomic, verified `nftables` `inet` table installed only in the launcher-recorded agent network namespace, without flushing unrelated firewall state. The control-plane origin is derived from `SERVERWARE_PUBLIC_URL`; a caller-supplied mismatch is rejected. The portal serializes and downloads the packet once, separately precommits the SHA-256 of those exact bytes, and copies a fixed verifier invocation. The signed packet pins the closed enrollment tooling contract, including the exact `serverware-enrollment` distribution, command, version, and expected `--version` output. Both the portal handoff and the minimal installed package verify that contract before the package checks the raw-file digest, expected principal/nonce, packet signature, fresh attestation, and every signed pin or emits `agentHandoff.authenticatedInstructions`; neither path gives the agent an admin token or receipt-signing key. The separate `--sign-setup-receipt` operation runs outside the agent and Serverware workloads, requires an owner-only Ed25519 key matching an expected SPKI ID, and emits a short-lived `serverware.enrollmentVerifierReceipt/v3` bound to the setup session, immutable assignment, enrollment capability, packet, nonce, receipt trust profile, quote verification, and launcher-signed egress evidence.
- A durable Setup-session ledger whose table and storage operations support SQLite and PostgreSQL, exposed through `/api/setup/sessions`. Backend-neutral wording applies to that ledger layer only. It uses bounded TTL/capacity/retention, owner and current-assignee subject strings, named phase transitions, revision compare-and-swap, immutable backend bindings, exact route-policy and credential-generation commitments, duplicate evidence-digest rejection, and a claimable idempotent audit outbox. The list GET returns session summaries; the item GET returns one session with evidence and transition events. Owner/admin handoff records a bounded assignee subject string but does not verify subject existence at handoff, grant a role, reserve the run exclusively, or transfer OAuth ownership; API authentication and authorization are enforced when that subject acts. Server-side verification derives enrollment-consumption, activated-canary, and runtime response-release evidence from authoritative state and the audit chain rather than accepting those facts from the browser. The first-screen **Setup and Verify** UI creates and selects durable runs, resumes the exact run from `?setup=<id>` after reauthentication, and reconciles preview, stage, activation, enrollment, and verification actions through revision-checked endpoints. Committed backend bindings cannot be rebound; edits to still-enabled `created`-phase form fields may cause the next action to create a replacement run.
- Setup receipt trust and completion APIs are implemented. `GET /api/setup/receipt-trust` publishes the pinned role identities; `POST /api/setup/sessions/{id}/enrollment-receipt`, `/attestation-challenge`, `/hardware-verification`, and `/final-receipt` enforce current-assignee RBAC, revision CAS, strict closed-field JSON, canonical Ed25519 signatures, short validity windows, exact assignment/session/challenge/artifact bindings, three distinct configured keys and providers, and cross-session replay rejection. The challenge must be fresh when hardware evidence is accepted; after that durable acceptance, a fresh off-host final receipt may complete during the setup-session lifetime even if the original challenge deadline elapsed, so human approval cannot permanently strand the run. Shared approval transactions independently reject an expired setup session. The ledger retains canonical signed receipt documents and the exact submitted hardware-assurance and proxy-statement bytes, keeps security-bearing terminal sessions out of TTL pruning, and enters `completion_pending_audit` until the final receipt transition is durably hash-chain audited; configured WebAuthn mutation MFA and two-person approval protect finalization. This is implemented and fixture-tested code, not production assurance: independently operated hardware and final authorities, real receipts, a live cloud/TEE deployment, and end-to-end production execution remain outstanding.
- OAuth token exchanges reserve bounded recovery capacity and durably enter `exchange_in_flight` before provider contact. A timeout, ambiguous success response, or interrupted exchange becomes an operator-visible issuance uncertainty instead of being deleted. The reconciler reports it once without token material; clearing it requires confirmed provider-side app revocation, an evidence note, WebAuthn, and the production `credential.oauth.uncertain.resolve` two-person action. This prevents unknown grants from disappearing silently but does not make provider issuance and Serverware persistence atomic; measured exchange custody remains production work.
- A dev key-release gate that requires a signed quote authorizing `broker-kek` before credential DEK unwrap and `decision-gate-ca` before handing the CA private key to the Rust data plane. The `decision-gate-ca` release also requires the release-pinned Rust binary digest.
- External TEE/KMS provider hooks plus an AWS Nitro-compatible provider: `SERVERWARE_TEE_QUOTE_COMMAND`, `SERVERWARE_TEE_QUOTE_VERIFY_COMMAND`, and `SERVERWARE_KEY_RELEASE_COMMAND` let deployments plug in vendor quote verification and KMS/HSM policy without changing the policy engine. Docker verifies both the generic external-command interface and [scripts/aws_nitro_tee_provider.py](scripts/aws_nitro_tee_provider.py), including Nitro CBOR/COSE_Sign1 parsing, certificate-chain trust-root checks, PCR allowlisting, Serverware claim binding through Nitro `user_data`, a material-release policy for `broker-kek`/`decision-gate-ca`, and the production KMS/HSM command contract through [scripts/nitro_kms_fixture.py](scripts/nitro_kms_fixture.py).
- A Dockerized Rust data plane that verifies the Ed25519 policy signature against an attested control-plane trust root, denies unknown CONNECT authorities before leaf issuance, performs explicit CONNECT TLS interception, validates upstream TLS, and injects credentials from exact purpose-bound v3 request/decrypted-set bindings carried inside the v2 encrypted envelope. It enforces status-specific response projection before release and supports bounded credentialless or redacting stream modes. Policy admission rejects credential-bearing opaque/non-redacting response streams and credential-bearing mutating request streams. Every credential-bearing upstream release synchronously requires a durable control-plane acknowledgment of `data_plane.credential.release_started`; ordinary redacted telemetry remains bounded and asynchronous.
- Hardened Docker runtime settings verified by [scripts/test_container_hardening.sh](scripts/test_container_hardening.sh): ordinary application services run as UID/GID `10001`, the optional custody signer runs as UID `10002` with shared socket GID `10003`, Postgres runs as its non-root database user, and all services use read-only root filesystems, drop all Linux capabilities, enable `no-new-privileges`, set PID and memory limits, disable core dumps, mount `/tmp` as `noexec,nosuid,nodev` tmpfs, and run under [security/seccomp/serverware-deny-dangerous.json](security/seccomp/serverware-deny-dangerous.json). The verifier confirms Docker seccomp filter mode, runtime core dump limits, and proves the profile is active by checking a denied `bpf` syscall returns the profile's custom errno.
- Signed release provenance with Python/Rust SBOM summaries, a CycloneDX 1.5 SBOM at `.tmp/sbom.cdx.json`, source/config/image/hardening inventory, source tree digest, build recipe, published control-plane and data-plane attestations, provenance/source digest binding in both attestation endpoints, and verified signed-transparency-log inclusion. Development records remain `release.provenance.v1`; digest-pinned production records are `release.provenance.v2` and additionally bind the launch-authority root and reproducible-build verification. The source identity is `serverware.sourceTree/v3`. Its production mode requires a clean exact Git commit and binds the commit/tree identity plus every tracked regular file's path, normalized executable mode, Git blob ID, byte count, and SHA-256 in a deterministic source archive. Dirty indexes/worktrees, tracked deletions, symlinks, and submodules are rejected. Explicit development filesystem snapshots select relevant source/build/config inputs without consulting Git, exclude Git metadata, caches/build outputs and the runtime production secret env, and are never production-release eligible.
- Sigstore-compatible image-release bundle at `.tmp/image-signatures.json` with per-image in-toto statements for every Compose image, a cosign `sign-blob`/`verify-blob` adapter, required transparency evidence, provenance/SBOM/config/source bindings, image-signature digest binding in both attestation endpoints, and a `release.image_signatures.v1` transparency-log record with a verified inclusion proof.
- Control-plane responses carry `X-Serverware-Response-*` proof headers: a nonce-capable Ed25519 signature over method, path, an exact-query SHA-256 digest, status, exact wire-body hash, a digest and count for the canonical end-to-end response-header multimap, source tree digest, runtime manifest digest, policy hash, provenance digest, and image-signature digest. `serverware.responseSignature/v3` never copies raw query values, cookies, or other header values into proof headers: it signs only the digest of lowercase-name-sorted header items whose repeated-field value order is retained. Singleton duplicates are rejected; repeated `Set-Cookie`, `WWW-Authenticate`, `Link`, and `Warning` remain exact. The outer ASGI boundary admits at most 16 bounded response buffers, signs `HEAD` over the empty wire body while retaining its representation length, rejects invalid no-body status framing, replaces downstream proof/security headers, and returns a signed `400` without entering the app when the bounded base64url response nonce is invalid or repeated. Oversized or failed application output becomes a fresh bounded signed error. Before opening the listener, the release runner requires audited Uvicorn 0.34.0 plus httptools 0.8.0 and rejects Uvicorn concurrency-limit configuration; its direct cycle factory avoids process-global parser mutation. It disables WebSockets and Uvicorn-added date/server headers, and closes the connection instead of emitting unsigned parser, upgrade, `100 Continue`, admission-overflow, or top-level application fallbacks. If signing itself fails, no response bytes are released. The response signing key ID is itself bound into `/attestation` quote claims.

## Policy Model

The proxy now requires a signed/hashed `PolicyBundle` at `/data/policy-bundle.json`, generated by the demo seed endpoint and modeled after [policies/demo.policy.json](policies/demo.policy.json). The current Python compiler validates the JSON Schema and adapter configs, verifies the Ed25519 signature, compiles path templates to regexes, computes a canonical policy hash over the unsigned payload, and keeps the hot-path route snapshot in memory.

Policy authors can submit a candidate bundle to `POST /api/policy/candidate` to receive a signed candidate, schema/semantic validation, a human-readable principal/credential/route diff, and route-selection dry-run results. An allow case may bind `expectedRouteId`; the portal always does so, preventing an overlapping route from satisfying the wrong test. Preview and stage resolve every referenced credential from the live store and require it to be active with exact provider, provider subject, scopes, injection kind/name/field/prefix, and X application binding. A missing, inactive, or incompatible credential therefore blocks publication rather than becoming a latent runtime failure. Policy publishers can use `POST /api/policy/publish` with the legacy-named `activationMode: "canary"` to stage a separate signed candidate without changing the active bundle.

The current control-plane dry run and canary files are advisory caches, not activation authority. The intended production path uses one pure Rust policy core over immutable secret-free ingress facts. Candidate execution receives no credential, JIT, quota, durable-budget, provider, cache, filesystem, network, RNG, clock, or audit capability; it can return only deny, permit, conditional intents, or indeterminate. Every assigned measured gate emits a TEE-bound load receipt and contiguous signed checkpoints over complete fleet, decision, comparability, latency, error, and drop accounting. PostgreSQL owns the candidate artifact, canary lifecycle, instance receipts, checkpoints, and activation attempts; files are rebuildable projections. A sealed short-lived readiness root binds exact predecessor/candidate/compiler/schema/binary/fleet evidence and any separately approved expansion pilot. Fresh WebAuthn and two-person approval remain unconsumed until the same transaction checks that root and predecessor, consumes approval, advances the policy high-water mark, records publication, and emits the audit outbox event.

Candidate generation, the bounded Rust evaluator, durable reducer/readiness state, evidence custody/generation, decision-gate publication, and authenticated activation prepare/inclusion/finalize contracts now exist in source. The legacy direct activation endpoint remains disabled, and ordinary audit rows have zero activation authority. This source-only state does not prove a production activation: acceptance requires the exact committed build running behind independently controlled authorities with measured fleet receipts, trusted time, externally witnessed monotonic state, and TEE-bound evidence. Direct full publish remains available only for local/development paths when staging is disabled.

The on-disk schema contract lives in:

- [schemas/policy-bundle.v1.schema.json](schemas/policy-bundle.v1.schema.json)
- [schemas/policy-shadow-assignment.v1.schema.json](schemas/policy-shadow-assignment.v1.schema.json)
- [schemas/policy-shadow-load-receipt.v1.schema.json](schemas/policy-shadow-load-receipt.v1.schema.json)
- [schemas/policy-shadow-observation.v1.schema.json](schemas/policy-shadow-observation.v1.schema.json)
- [schemas/policy-shadow-checkpoint.v1.schema.json](schemas/policy-shadow-checkpoint.v1.schema.json)
- [schemas/policy-activation-readiness.v2.schema.json](schemas/policy-activation-readiness.v2.schema.json)
- [schemas/adapters/generic.rest.schema.json](schemas/adapters/generic.rest.schema.json)
- [schemas/adapters/gmail.v1.schema.json](schemas/adapters/gmail.v1.schema.json)
- [schemas/adapters/x.v2.schema.json](schemas/adapters/x.v2.schema.json)
- [schemas/adapters/npm.registry.schema.json](schemas/adapters/npm.registry.schema.json)

Every route binds:

- principals: source CIDR, trusted identity headers, hashed proxy bearer tokens with expiry/source binding in the Rust data plane, and typed mTLS/SPIFFE selectors; trusted-ingress population and live end-to-end mTLS proof remain deployment work;
- endpoint allowlist: scheme, host, port, methods, and path templates;
- credential reference and injection mode;
- API adapter and typed config;
- shared request/response credential constraints;
- optional JIT approval policy.

Unknown hosts, paths, methods, principals, and missing policy bundles are blocked. Gmail, X, and npm routes additionally require a closed provider request profile for their operation: admitted headers, intentionally discarded headers, query keys, media types, and body limit cannot be silently widened. Request-profile failure is decided before credential lookup or lease, JIT/grant work, quota reservation, release authorization, or upstream contact. A bodyless request may carry a syntactically valid `Content-Type`; because there are no body bytes to interpret, that header does not turn the request into a body-bearing operation.

`routes[].adapter.config.request.discardHeaders` is a signed, ordered list of at most 16 lower-case canonical field names for SDK-generated metadata that Serverware explicitly accepts and removes. Omission is a compatibility alias for an empty list; a provider preset that requires a non-empty discard, currently npm's `npm-session`, must declare it explicitly. The declaration itself is included in canonical request v2 and its request/operation commitments, while the discarded values are excluded because they are deleted before adapter admission, JIT digesting, quota and credential work, audit commitments, injection, and upstream forwarding. Legacy canonical request v1 remains the exact old shape and is accepted/emitted only for an active route whose discard list is empty; v2 is mandatory for a non-empty list. Empty-discard routes may use the staged v1/v2 rollout, but npm has no mixed-fleet bridge because upgraded npm admission requires explicit `npm-session` while pre-feature gates reject the new field. Drain or disable active npm routes, upgrade the compiler/control plane and every gate as one coordinated cutover, activate the exact v2 policy hash only after all consumers are upgraded, and use the same drain/disable discipline for rollback. Mixed shapes and v1 requests against a discard route fail closed.

Discard rules cannot overlap forwarded/required headers, principal identity selectors, credential injection targets, framing or hop-by-hop fields, authentication, cookies, conditional or integrity fields, Serverware/proxy fields, or reserved provider namespaces. The npm preset discards `npm-session` so separate ordinary npm CLI processes can retry the same approved operation without weakening the package, version, integrity, command, user-agent, body, path, principal, policy, or credential bindings. Python and Rust reject duplicate physical request fields before removal or canonicalization. Audit records retain only the closed declared/present name and count metadata; raw values and public value hashes are deliberately omitted until a dedicated audit HMAC key exists, avoiding offline guessing of low-entropy discarded values.

The exact npm `11.8.0` public-CLI lane and concurrent one-use contention lane are implemented in the current source, but the current source tree is unbuilt and unexecuted. They do not relax the mandatory coordinated disable, drain, whole-fleet cutover, exact-policy-hash activation, and equivalent rollback sequence above.

`routes[].match.resolvedCidrs` is an optional signed destination control. Omission means public-only resolution. An explicit list permits only canonical, host-bit-free networks admitted by the compiler; IPv4-mapped IPv6, metadata overlaps, and unconditional special-use denials remain forbidden. The production Rust gate resolves through a bounded four-worker, 256-job queue with a two-second timeout and 32-answer cap, validates every answer rather than filtering a mixed set, deterministically selects one address, and pins the socket while retaining the original host for SNI and certificate validation. Its 256-entry client cache is keyed by host, port, selected address, and pooling mode. It neither retries another answer nor resolves again, and Gmail metadata children reuse the parent's prepared client. Resolution failure occurs before credential, JIT, or quota side effects. The legacy SQLite `routes` table remains only for UI compatibility and state inspection.

Route `constraints` are the reusable layer for limits that should apply to any credential, independent of the upstream SDK. Implemented constraint types are `operationPolicy`, `rateLimit`, `slidingWindowLimit`, `weightedBudget`, `traversalBudget`, `queryDateWindow`, `queryNumericBounds`, `requestTimeWindow`, `requestValue`, `jsonBody`, `formBody`, `responseDateWindow`, `responseJson`, `responseBinding`, and `responseEnvelope`. Constraints compose only as an intersection of typed bounded data; unknown fields and extension semantics deny, and arbitrary policy code is never executed. The Rust gate is the only production credential enforcement and forwarding path. Python retains credentialless development compatibility and semantic parity helpers, but rejects credential-bearing routes before secret, JIT, quota, reservation, or provider work. Response validation runs before redaction and release. `requestValue` constrains compiler-proven path parameters and singleton allowlisted query/header/body/operation values with exact, enum, bounded-pattern, UTF-8 byte-length, or finite numeric predicates. Typed captures can bind JIT, response comparisons, weights, and secondary quota dimensions; an agent-selectable uniqueness dimension must be paired with a coarser quota that bounds durable-key cardinality.

`responseBinding` is intentionally bounded to buffered `generic.rest` operations with compiler-proven form fields, top-level typed JSON fields, matched path parameters, request-value captures, or an exact Serverware-computed request-body digest, plus `npm.publish` on compatible registries that explicitly return a bounded JSON package identity. Any signed compatible-registry route that enables `npm.publish` response binding must use buffered JSON capped at 65,536 bytes, statuses `200`/`201` only, content type exactly `application/json`, exact package-name and package-version echo bindings, and a required boolean `published: true`; Python and Rust reject weaker signed policies at admission. The exact `registry.npmjs.org` route instead requires `npm-public-registry-receipt-v1`: only `200`/`201` with one strict `application/json` header and a JSON object are accepted, `{}` is valid, optional `ok` or `published` fields must be boolean `true`, and only those booleans can survive projection. Public package/version claims are never validated or released because the official client does not define a stable ordinary-publish body identity contract. Each generic binding policy declares admitted `2xx` statuses and JSON media types, and object-only dotted response traversal prevents fields from separate array elements being combined. Missing operation fields deny before credential release, and response envelope, shape, or value mismatches fail with a synthetic `502` before upstream bytes are released to the agent.

`jsonBody` allowlisting is structural, so unknown keys holding empty objects, empty arrays, or nested empty containers are denied rather than disappearing from scalar-leaf traversal. String, numeric, and array-specific field rules require explicit compatible types at schema and semantic admission. `requestTimeWindow` provides RFC3339 activation/expiry bounds plus UTC weekday and daily intervals. A `rateLimit` with `windowSeconds` is a rolling fixed window anchored by first use; it must not be described as a calendar day. `calendarWindow` instead selects a half-open UTC calendar bucket: `utcDay` is `[00:00 UTC, 00:00 UTC the next day)`, `utcIsoWeek` is `[Monday 00:00 UTC, Monday 00:00 UTC the next ISO week)`, and `utcMonth` is `[the first day 00:00 UTC, the first day 00:00 UTC the next month)`. For an actual Docker/production proxy request, `rateLimit.store: "shared"` counters are reserved through the authenticated release-authority endpoint in the same metadata-store transaction as any one-use JIT grant. A reservation cannot cross any fixed or calendar boundary: an undispatched reservation expires and is refunded at the boundary, and the caller must reserve again in the new window; an uncertain result after dispatch remains charged conservatively. Changing a live fixed-window duration preserves the accumulated count while the requested replacement window is active. The separate rate-limit consume endpoint remains an authenticated compatibility and diagnostic surface, not the authoritative composed proxy path. The X template allows one post per UTC calendar day and resets at 00:00 UTC. It uses the callback-verified provider subject as its stable account scope, so rotating a principal, credential ID, or credential version cannot reset the quota; missing account identity fails policy admission and runtime authorization closed. The Slack, GitHub issue-create, Stripe PaymentIntent, OpenAI, Cloudflare, and Twilio examples use the same stable provider-account dimension for their principal limits; Stripe's idempotency uniqueness additionally binds the captured key. Typed static-credential templates require the stored credential's operator-declared provider metadata to match the template, so an unrelated shape-compatible bearer cannot be selected for Stripe or npm. Unknown types or fields fail policy admission rather than being ignored. These source examples have not been built or executed in this pass and are not production deployment or live-provider proof.

Response policy is status-specific and fail closed. A `2xx` response must satisfy the route's success profile; a `4xx` or `5xx` response must satisfy an explicit nested `error` profile; redirects are rejected. Each profile has a required `maxBodyBytes`, a structured projection/redaction mode, and optional `allowedHeaders`. Every selected `mode: "json"` success or error response requires one valid `application/json` media type before parsing or projection; missing, duplicate, malformed, or different content types synthesize `502`. Only `Cache-Control`, `Content-Language`, `ETag`, `Last-Modified`, `Retry-After`, and `WWW-Authenticate` can be released when selected. Transport and state-bearing headers such as `Set-Cookie`, `Location`, hop-by-hop headers, upstream `Content-Length`, and upstream content encodings are removed and safe framing is rebuilt.

Credential-bearing routes cannot use `response.mode: "any"` or a non-redacting `response.mode: "stream"`; every JSON or structured-stream release requires a non-empty bounded projection. A credential-bearing buffered JSON/form mutation must also carry the matching typed body constraint with a non-empty field allowlist, and a credential-bearing mutating route cannot stream its request body because a malformed or truncated tail could otherwise be detected only after an upstream side effect. Credentialless routes may use bounded opaque streams, and structured streaming modes remain available when they redact to declared fields. Unsupported combinations are rejected when the signed policy is compiled and repeated as runtime defenses rather than being deferred to upstream behavior.

Structured JSON streaming now uses the same semantic acceptance boundary as buffered strict JSON. JSON Lines records, top-level array items, SSE `data:` JSON, nested selected fields, and denied subtrees reject decoded duplicate keys, escaped-equivalent keys, integer `-0`, malformed values, invalid UTF-8, truncation, and trailing data. A failing unit is withheld; earlier streamed bytes remain provisional, and no terminal proof trailer or commit marker is emitted after a late failure. Only the proof-enforcing client stages those bytes until verification, so generic HTTP clients must not treat an unproved partial stream as committed output.

Policy publication is monotonic and crash-aware. Every production writer flocks the same shared policy-volume directory inode beneath root-owned, non-group/world-writable ancestry; the service may mutate files inside that directory but cannot replace the directory through its parent. Under that lock, publication binds the full candidate digest, predecessor digest, and signed-bundle digest before replacing the active bundle and committing metadata. The database records pending versus committed publication and distinguishes a definite rollback from an ambiguous commit acknowledgement; recovery re-reads the authoritative committed winner instead of guessing from a transport or filesystem error. The control plane persists the highest accepted `(policyId, sequence, rollbackEpoch, policyHash)` and exposes its digest in attestation. The Rust gate independently persists and checks its own high-water record before startup or hot reload, retaining the last good snapshot when a signed replay or rollback is presented. The shared volume namespace and both persistent high-water/store histories must be protected against replacement and coordinated rollback; restoring all of them together remains an external deployment boundary.

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
  --admin-token-file "$SERVERWARE_ADMIN_TOKEN_FILE"
```

The verifier checks the attestation quote, the published release provenance signature, the local source tree digest, the attested source/provenance/image-signature digests, and a nonce-bound response signature from the server it contacted.

## Secret Broker

Credential rows use envelope encryption. Each secret update creates a fresh random data-encryption key, encrypts the secret under that DEK, then wraps the DEK under the prototype KEK from `/data/master.key` or `SERVERWARE_MASTER_KEY`. In the default Docker profile, that KEK is usable only after the key-release gate verifies a signed quote authorizing `broker-kek`; `secret_kek_id` is reported with the `attested-dev-kek:` prefix. The API exposes non-secret broker metadata such as `credential_version`, `secret_kek_id`, and `secret_updated_at`, but never returns plaintext secrets from list/bootstrap endpoints.

`credential_version` advances when either the stored secret or its metadata changes because metadata participates in adapter enforcement and injection. JIT approval requests, one-use grants, canonical request digests, leases, and proxy audit events include that version, so an approval for `cred-demo-bearer` version `7` cannot authorize the same request after a secret rotation or metadata-only update produces version `8`.

The active Python, Rust, and Docker paths no longer produce or consume `/data/credential-generations.json` or plaintext `/data/credential-leases.json`. Control-plane startup unlinks those names and their `.tmp` variants. That cleanup cannot sanitize old snapshots, volume backups, image layers, or copied artifacts; every credential ever published by an older version through either plaintext path must be rotated.

The Rust gate pulls purpose-bound credential material from `POST /api/data-plane/credential-leases`. A v3 `generationMetadata` request is bound to the purpose, principal, route, credential, active policy, and measured executable; unknown fields fail validation. It cannot carry dispatch bindings and cannot return or refresh a secret:

```json
{
  "apiVersion": "serverware.credentialLeaseRequest/v3",
  "purpose": "generationMetadata",
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

The caller sends `X-Serverware-Data-Plane-Token` and a fresh `X-Serverware-Response-Nonce`. The control plane verifies the exact principal is assigned to the active route, the exact credential is assigned to that route, the policy and binary digests match, the nonce is one-use, the X25519 key ID is correct, and recipient evidence is valid when required. It returns the exact version and allowlisted metadata digest, but structurally no secret and without loading the credential master key.

`dispatchSecret` has two closed modes. A route with no configured JIT, shared-quota, sliding/weighted-budget, or traversal control may use authority-free request v3. Every controlled route must use `serverware.credentialLeaseRequest/v4` and carry the exact `serverware.credentialLeaseRequestAuthority/v1` committed by the policy decision. That authority binds the attempt/reservation, canonical request and operation digests, full bounded operation context, principal, route, credential generation, active policy, recipient, and expiry. JIT/shared release state is carried by release authorization v1; applicable durable policy uses release authorization v2. If a configured traversal or other control is not applicable to this exact operation, release authorization is null but the broker still atomically consumes a one-use `decisionBound` issuance. A second issuance request for the same attempt fails closed. Before entering any decrypt or managed-OAuth refresh path, the control plane records that sole issuance; the secret lease expiry is the minimum of five seconds, the configured broker TTL, and the request-authority expiry. Authority is checked again after envelope construction. A lost response strands that one-shot issuance and requires a fresh policy decision or approval rather than minting another lease.

Consumed recipient nonces remain tombstoned for 24 hours. A read-only duplicate lookup avoids repeating expensive verification, but a new nonce consumes replay capacity only after recipient attestation succeeds; the final reservation is still atomic, so concurrent duplicates fail closed. The shared metadata store keeps a transactionally maintained count rather than scanning the replay table on every lease, and `SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES` sets a bounded 10,000-10,000,000 entry capacity with a 1,000,000 default. Capacity exhaustion fails closed with `503`; expiry cleanup releases capacity without accepting a replay inside the retention window.

Controlled v4 dispatch returns `serverware.credentialLeaseEnvelope/v3`; its encrypted plaintext is `serverware.credentialLeaseSet/v4`. Both layers repeat the request-authority digest in addition to purpose, recipient, nonce, policy, binary, principal, route, credential, issue time, expiry, generation, metadata digest, and applicable release bindings. Envelope v2/set v3 remains compatibility-only for generation metadata and genuinely uncontrolled v3 dispatch. The attested Ed25519 response key signs the HTTP request/response context. Rust verifies the signature and every duplicated binding before placing generation metadata in its secret-free cache or accepting a matching dispatch secret into a generation-scoped, monotonic `Zeroizing` cache. Purpose or authority substitution, lower versions, and same-version secret or metadata changes are rejected.

Rust keeps leased secrets only in memory with monotonic expiry no later than the signed wall-clock expiry. Generation metadata and secret leases use separate bounded caches. A request or authorized preview synchronously singleflights a missing or expired generation check; previews do not make a scope hot. Only successful authenticated non-preview use adds the exact scope to the 30-second hot set. A bounded worker pool polls that set every `0.25` seconds in Docker and refreshes within one second of expiry. It refreshes generation metadata for every hot scope, may renew a non-JIT secret, and never fetches a JIT secret in the background. Cold scopes produce zero broker traffic, and invalid or expired secrets are pruned. A valid cached lease survives a failed refresh only until expiry. Policy reload removes incompatible generation floors, leases, and grants; credential rotation replaces only a lower-version scoped entry; and every final upstream send rechecks the active policy, generation, secret fingerprint, metadata, and unexpired authority.

Development Docker uses a software X25519 recipient. This removes plaintext credential delivery from disk and the lease HTTP response body, but host root can still inspect Rust process memory. Production requires the recipient-attestation generator and verifier command pair; their v2 statements include the recipient and all three scope fields. These command contracts remain integration points, not proof of a real Nitro deployment.

`serverware-custody-runtime` is an optional development signer for buffered `responseProof.sign/v2`. Its 256 KiB-capped UDS transport supports only `hello/v1` and `responseProof.sign/v2`, returns public material and signatures only, and reports `hardwareProof:false`. Among the application processes, only custody holds the ephemeral response-proof private key; host root and the host kernel remain able to inspect or impersonate the ordinary process. The gate authenticates the UDS peer by configured UID, pins the custody boot and signing SPKI/key ID for its lifetime, and requires custody's pinned control-plane response-signing key ID to match the active policy snapshot before policy high-water state advances. It repeats the complete pinned hello every second and makes health fail closed when transport, identity, capability, limit, hardware flag, or proof assembly is invalid or older than six seconds. A later successful full proof can clear a transient assembly failure only when the same pinned boot remains valid; a changed boot or key requires a coordinated gate restart. Streaming proof requests are rejected before credential acquisition or upstream contact.

Before signing, custody verifies the embedded dispatch signature and its signed control-plane runtime-manifest digest, distinct from the gate runtime digest, requires the signed control-plane policy and release provenance to match the gate statement, and independently recomputes the complete canonical release-authorization binding, including principal, route, credential/version, policy, request/operation context, JIT state, quotas, attempt, and flow. Receipt and statement temporal validation share one wall-clock sample. A checksummed, fsynced, bounded ledger then serializes claim evaluation, takes a second sample only after acquiring its process and file locks, rejects a backward step from the validation sample or durable high-water mark, and durably binds each attempt ID to one canonical statement digest through the signed dispatch expiry. Even rejected validation or claim work latches a forward clock sample before failing, so an attacker cannot present future time and then return the signer to an older clock. An exact retry is idempotent and substitution remains rejected across clean custody restarts. Ledger open and every valid attempt claim advance a durable maximum-observed wall-clock value even when no receipt is pruned; later startup or signing below that value fails closed. Normal startup requires preinitialized owner-only state, safely removes only exact validated orphan temporary files left by interrupted publication, and rejects missing, corrupt, inconsistent, symlinked, multiply linked, or incorrectly owned ledger files. A crash between publishing a new binding and its manifest can intentionally leave fail-closed state requiring operator recovery, and host root can restore an older complete self-consistent volume snapshot; this filesystem ledger is restart-persistent integrity state, not trusted rollback protection.

Custody does not independently observe upstream response bytes, the TLS exporter, or gate/runtime facts, so its signature authorizes an internally consistent gate-produced statement rather than independently attesting those facts. In development Compose the control plane's active response-signing private key is isolated in a control-plane-only volume, while custody and the gate receive only the self-published SPKI and key ID through read-only public material. Publication takes an exclusive advisory lock on the verified owner-controlled output-directory inode across control-plane processes, skips replacement only when both `0644` files repeatedly resolve to the exact expected bytes, and otherwise retains no-follow staging, snapshot, replace, and post-commit verification. A key/path/content-bound one-second cache keeps ordinary signed responses off the publication lock while bounding revalidation delay; thread and process lock waits fail closed after one second. The PEM and key-ID filenames cannot be replaced as one filesystem transaction; a crash or hostile same-UID writer between replacements can leave an inconsistent pair, which consumers reject until coordinated publication/restart repairs it. Production Compose uses an equivalent control-plane secret, gives custody a UID distinct from the gate, uses a shared UDS group, sets `network_mode: none` for custody, and keeps custody state private. The control plane and gate may use the same ordinary application UID, but the gate receives only the control-plane CA file rather than its TLS directory, and release validation rejects private-key paths that equal, alias, contain, or fall beneath any gate-visible host bind. Runtime and readiness readers use no-follow, nonblocking descriptor opens before validating regular-file identity, preventing configured FIFOs or file-type replacement races from blocking startup or preflight. These arrangements detect cross-wiring and post-start substitution, but the public key is not an independently administered trust root and ordinary Docker does not resist coordinated compromise or snapshot rollback by the control plane, host root, kernel, or daemon. Authenticated AF_VSOCK, sealed monotonic state or an external witness, EIF/PCR measurement, quote binding, and enclave-owned TLS/policy/lease/injection/response processing remain required.

Run the development custody configuration with both the profile and override:

```bash
docker compose --profile custody \
  -f docker-compose.yml \
  -f docker-compose.custody.yml \
  up -d serverware custody-runtime decision-gate-rs
```

Both selectors are required: the profile enables the sidecar, while the override selects custody mode for the gate, grants socket-group access, and configures the expected peer UID. `--profile custody` alone does not place the development gate in custody mode. A buffered proof request checks pinned transport identity and freshness before credential acquisition and again at the final dispatch boundary. A successful pinned probe can admit a retry after a prior signing or assembly failure; public health remains degraded until signing and complete proof assembly recover, avoiding a state where health itself prevents the request needed to prove recovery. Counted, operation-sequenced health transitions prevent a slow success from overwriting a newer transport, signing, or assembly failure without serializing independent upstream requests. A phase-fair ticketed dispatch authority keeps concurrent sends parallel, gives policy and credential mutations FIFO-exclusive phases, and holds the send permit through `reqwest` execution. After all contention and immediately before execution, the gate revalidates the exact policy snapshot, attested trust, credential generation, secret fingerprint, metadata, and lease expiry; stale read paths cannot remove a newer valid lease. This closes application-level mutation and stale-lease races, but blocking `reqwest` exposes only a relative timeout and cannot make an absolute wall-clock deadline atomic with the host kernel's TLS/socket write if the process is suspended after the final check. A measured, deadline-aware egress runtime that owns networking remains required for that guarantee.

Run `make verify-custody-response-proof` to create a uniquely named disposable Compose project, hold an atomic host-wide lock for that project identity, publish only loopback ephemeral ports, reject any pre-existing project-labeled container, volume, network, or image plus every exact Compose-generated local image tag before mutation, bind provenance to the exact merged six-service custody topology, and prove successful signing, image-seeded ledger state, restart persistence, initial and final-boundary pre-dispatch denial, an unchanged upstream request counter during denial, signer-outage and stale-boot `503 {"error":"response_proof_unavailable"}` responses without upstream/proof metadata, coordinated recovery, and restoration of the ordinary local gate before complete teardown. Cleanup ignores repeated `INT`/`TERM` until restoration, resource removal, and lock release finish; an uncatchable process death can leave a stale lock that must be investigated and removed manually. The standalone proof clients mount only their CA, collector key when needed, and result files; they do not inherit the gate's state, socket, supplemental group, or service mounts. `bench-gate-rs` always generates a separate custody project even when the ordinary benchmark stack has an explicit `COMPOSE_PROJECT_NAME`.

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

That means a list result for one agent, Gmail user, policy hash, cutoff window, or credential generation cannot authorize a direct body read in another context. If a list item omits `internalDate`, the Rust gate performs a same-origin metadata child request whose policy limits are `maxMessages`, `perRequestTimeoutMs`, `totalTimeoutMs`, and `maxBodyBytes` (hard schema caps: 32, 3 seconds, 10 seconds, and 8 KiB). Missing messages, malformed responses, ID mismatches, and unproven dates are withheld; an authenticated out-of-window date fails the parent response closed. A post-dispatch transport or body-read error fails the parent closed and is audited as provider-outcome-unknown, because the gate cannot prove that Gmail observed no request. Each child uses a fresh lease for the parent's exact credential generation, and neither released IDs nor proof-cache entries are committed until the complete projected response and digest-only fanout audit succeed. A direct `GET /gmail/v1/users/{user}/messages/{id}` therefore remains `403` unless that exact scoped proof was established. After validation, `response.allowedFields` is enforced on list and direct message JSON so upstream echo fields, credentials, raw bodies, and non-allowlisted Gmail fields are removed before release. The credentialless Python mitmproxy path performs no Gmail hydration or credential dispatch; production enforcement is the Rust gate, whose request deadline is capped by both policy and the original credential lease expiry.

## JIT Grants

JIT approval is server-side. The agent never receives a token. For a sensitive request, Serverware computes a canonical request object containing version, principal, client IP, route, credential version, policy hash, method, authority, path, selected headers, body hash, and adapter operation fields. `request_digest` hashes that complete object. `operation_digest` separately hashes the projection that omits only top-level `v` and `client_ip`, keeping the principal, route, credential, policy, complete canonical request, and operation fields. The buffered and streaming response-proof `client_request_digest` values are separate domain-specific commitments over the client-observable safe request preimage. `POST /v1/decide` evaluates the authorization object as a non-mutating preview; the first actual proxied request sends it to the control-plane release authority.

If no matching grant exists, Serverware returns:

```json
{"error":"serverware_approval_required","approval_id":"...","approval_url":"/approvals/...","retry_after_seconds":3,"request_digest":"sha256:..."}
```

When that first real request has no matching grant, the release authority verifies every route, identity, credential-version, policy, request, and operation binding. It leaves no quota or grant reservation behind, atomically creates or reuses the exact pending approval, and returns `428` with its bounded status, expiry, creation flag, retry interval, and exact operator portal path. The agent gives that URL to the operator, waits, and retries only the identical request after approval; `403` and `5xx` responses are terminal for the attempt and never authorize proxy bypass. Approving is a separate atomic pending-to-approved transition. It rejects expired or already-decided approvals, and the approval row plus its digest-bound grant are committed in one metadata-store transaction; a grant insertion failure leaves the approval pending and no orphan grant. PostgreSQL issuance fails closed unless the metadata and grant stores use the same DSN/transaction.

The identical approved retry reserves the one-use grant and every shared quota in one release-authority transaction. A failure proven before dispatch cancels that still-`reserved` attempt and refunds both controls. Immediately before network dispatch, the data plane advances the exact attempt to `dispatching`; from that point completion records `forwarded` or conservatively commits every failed or ambiguous result as indeterminate. An attempt ID, flow ID, and binding digest correlate every transition. Credential injection and upstream contact cannot occur without a live matching reservation. A successful grant defaults to `maxUses: 1`, so a later identical request requires a fresh approval.

The demo NPM policy now sets `jit.approvers.authn.webauthnRequired: true`. Approval requires:

- the caller has the `approver` role;
- the caller user ID is listed in `jit.approvers.users`;
- the caller first retrieves the exact redacted review, then signs a WebAuthn assertion over a server-issued challenge bound to approval ID, request digest, operation digest, credential ref/version, policy hash, grant TTL/max uses, display digest, review-receipt ID/digest/expiry, and challenge expiry;
- the registered authenticator class is allowed by policy.

For policies with `requireHardwareAttestation: true`, authenticator class is not inferred from AAGUID alone. Registration accepts `packed`, `fido-u2f`, and `none` attestation formats, but only a valid attestation signature and certificate chain anchored in the active signed WebAuthn trust bundle can set enrollment trust and classify a credential as `yubikey` or `hardware`. Every assertion rechecks the stored root digest, AAGUID restriction, and class against the current valid bundle. A withdrawn root therefore removes the credential's effective hardware class immediately; missing, self, untrusted, withdrawn, or unsupported attestation cannot satisfy hardware-only approval policies. Production additionally requires hardware attestation and limits mutation authenticators to `yubikey,hardware`.

WebAuthn trust roots are packaged as signed bundles validated by [schemas/webauthn-trust-bundle.v1.schema.json](schemas/webauthn-trust-bundle.v1.schema.json). The bundle carries sequence, rollback epoch, validity window, root certificates, allowed AAGUIDs, and authenticator class. `SERVERWARE_WEBAUTHN_TRUST_BUNDLE` points to the active bundle; `SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE` stores the highest accepted sequence/epoch and digest. Different content at the same epoch/sequence and any lower sequence are rejected. A signed bundle with an empty `roots` array is the emergency withdraw-all operation. API publication commits the exact signed bundle, monotonic sequence/epoch, approval consumption, registration-challenge invalidation, affected credential revocations, and derived-authority invalidation to a database-authoritative publication journal. Only after that transaction commits are the state and bundle files durably replaced with file and parent-directory fsync; startup reconciles any interrupted projection idempotently and refuses unrecognized disk state. Re-adding a root does not reactivate historical rows; the operator must complete a fresh, separately authorized registration with a new credential ID. Legacy `SERVERWARE_WEBAUTHN_TRUST_ROOTS` PEM loading remains only as a development fallback when no signed bundle exists.

Credential IDs are insert-only, including after revocation. The portal lists active and revoked passkeys without returning their COSE public keys, development private material, or raw credential IDs. Revocation requires a reason and uses the same payload-digest-bound mutation WebAuthn and production two-person controls as registration. It atomically revokes unconsumed JIT authority and every browser session bound to that credential. First enrollment through a pending OIDC session is allowed only when no credential history exists. Revoking the last active credential does not reopen bootstrap. Instead, the portal prepares a short-lived canonical statement bound to the pending OIDC session, subject, roles, complete credential history, trust generation, deployment audience, candidate attestation/key, policy digest, expiry, and the offline root's next per-user sequence. The operator signs it outside Serverware and pastes only the Ed25519 signature. If the last key is lost but still active, a separate domain-bound statement must first decommission that exact credential; its signature cannot authorize the replacement. Both ceremonies advance a replay-protected high-water mark atomically with the audit event, retain signed evidence, and leave the browser session pending until the replacement key performs a normal assertion. Production mounts only the offline root public key and requires it to be distinct from every online/setup/release trust key.

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

REVIEW_RECEIPT_ID="$(
  curl -fsS -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
    "http://localhost:3000/api/approvals/$APPROVAL_ID/review" |
    jq -r '.review_receipt.id'
)"

curl -H "X-Serverware-Admin-Token: $SERVERWARE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"reviewReceiptId\":\"$REVIEW_RECEIPT_ID\"}" \
  "http://localhost:3000/api/approvals/$APPROVAL_ID/webauthn/options"
```

Use the portal or another WebAuthn-capable browser client to create the assertion. Submit that assertion and the same `reviewReceiptId` to `/api/approvals/$APPROVAL_ID/approve`; the one-use review receipt is consumed atomically with the grant.

Docker e2e enables `SERVERWARE_DEV_AUTHENTICATOR=1` and uses `/api/dev/webauthn/*` only to produce a deterministic software assertion. That path is disabled unless the env var is explicitly set and is not a production approval mechanism.

The 2026-07-27 source returns a typed HTTP `403` response with `{"detail":"no currently eligible WebAuthn credential is available"}` when a hardware-only approval has no currently eligible credential. The denial occurs before issuing an approval challenge or consuming JIT, quota, release, or upstream authority. This is source-only behavior in the current batch; it has not been executed and does not prove a successful physical YubiKey ceremony.

The same source batch expands the policy model with closed conditional adapter configuration; strict generic REST credential/no-credential modes; provider, subject, OAuth client/app, scope, and operation binding; adapter-wide `requestValue`; canonical IPv4/IPv6 and verified private mTLS selectors; true sliding-window counts; weighted canonical-integer budgets; durable traversal page/lifetime/record/byte budgets with one-use cursor lineage; exact response-envelope status, content-type, and physical-header uniqueness checks; nonvacuous response/date/JSON proofs; and X recent-search alternate-path isolation. Shared state is reserved atomically and post-dispatch uncertainty charges count/weight and poisons traversal rather than releasing a continuation cursor. These features and their examples are source-only in this batch; no build, interpreter, test, live provider, or production deployment has exercised them.

## Attestation

The production claim is deliberately narrow:

> For this fresh TLS session, the peer possessed a TLS private key held by an AWS-attested enclave running release R; release R maps reproducibly to source S; KMS released credential material only to that enclave; and an off-host witness confirms that R is current and not revoked.

Serverware does not claim that the whole parent machine only ever ran this code. Nitro attestation covers the measured enclave and the fresh attested interaction, not the complete history or integrity of the parent host.

The authoritative production chain is:

1. exact clean Git commit and recursive tree;
2. isolated builder with SLSA v1.2 provenance;
3. digest-pinned OCI images with CycloneDX or SPDX SBOMs;
4. Cosign/KMS signatures with independently verified transparency inclusion evidence;
5. independent source-to-OCI and OCI-to-EIF reproducibility;
6. a signed release record binding the source, provenance, OCI, SBOM, EIF, expected PCR0/PCR1/PCR2, policy bundle root, configuration root, verifier version, release sequence, and witness checkpoint;
7. a fresh verifier nonce in the raw AWS Nitro attestation document, with the enclave-owned TLS public key and release identity bound into signed claims;
8. TLS termination and the complete credential proxy, including policy enforcement, credential decryption/injection, response validation, and response authorship, inside the measured enclave;
9. AWS KMS Recipient ciphertext releases only, so plaintext credentials and private key material are recovered only by the attested enclave recipient;
10. off-host monotonic witness, compare-and-swap finalization, current revocation state, and rollback rejection before the client treats the result as actionable.

Coder/catchplate-host output can help reproduce and test source, but it is not authoritative SLSA provenance and cannot sign, promote, witness, or attest a production release. The experimental OCI Manifest v6 lanes may supplement the release with conformance evidence; they cannot establish production completion.

The production bridge is implemented only as source contracts in the 2026-07-27 batch. It requires fresh one-use challenges, raw Nitro COSE/certificate/CRL/PCR verification, one exact detached-proof-header schema, completion-identity binding, KMS Recipient custody evidence, and `pending-state-commit` until an independently signed rollback-resistant CAS receipt finalizes witness state. This batch has not been built or executed. No real EIF, enclave-owned TLS endpoint, KMS policy, independent builder/reproducer, transparency service, witness/CAS service, revocation service, or physical YubiKey ceremony has yet produced current acceptance evidence.

### Development Attestation

The prototype exposes a dev-signed quote attestation shape:

```bash
curl 'http://localhost:3000/attestation?nonce=test'
```

It returns runtime manifest digest, policy bundle digest, policy signature, policy signing public key, CA SPKI hash, release-pinned data-plane binary digest, rollback epoch, release channel, release provenance digest, image-signature bundle digest when present, and the caller nonce. The default `quote` is an Ed25519-signed development quote whose claims bind those same values plus authorized key-release materials: `broker-kek` and `decision-gate-ca`. Setting `SERVERWARE_TEE_QUOTE_PROVIDER=external-command` switches quote production and verification to `SERVERWARE_TEE_QUOTE_COMMAND` and `SERVERWARE_TEE_QUOTE_VERIFY_COMMAND`; setting `SERVERWARE_KEY_RELEASE_COMMAND` adds an external KMS/HSM release policy gate after claim validation. For the AWS Nitro path, use `SERVERWARE_TEE_QUOTE_PROVIDER=aws-nitro-enclaves`, `SERVERWARE_TEE_PLATFORM=aws-nitro`, and `scripts/aws_nitro_tee_provider.py quote|verify|release`; production deployments set `SERVERWARE_NITRO_ATTESTATION_COMMAND` to a Nitro NSM helper that returns a fresh attestation document for the exact Serverware `user_data`, pin the Nitro trust root and PCR allowlist, and require `SERVERWARE_NITRO_KMS_RELEASE_COMMAND`, while Docker uses fixture roots and [scripts/nitro_attestation_fixture.py](scripts/nitro_attestation_fixture.py) plus [scripts/nitro_kms_fixture.py](scripts/nitro_kms_fixture.py) to exercise the same verifier and command contracts.

The installed `serverware-attestation` command, implemented by [scripts/verify_attestation.py](scripts/verify_attestation.py), implements the client trust flow:

1. create `/api/ca/install-sessions` to get a one-use install token and nonce;
2. request `/attestation` with that install-session nonce;
3. verify the nonce and runtime manifest digest;
4. verify the quote signature or call the configured external TEE verifier, then check claim parity with the attestation document;
5. verify the policy signing public key hash;
6. fetch the signed policy bundle through `/api/policy`;
7. verify the Ed25519 policy signature and canonical policy hash;
8. verify the attested policy digest and policy signature match the bundle;
9. fetch the install-session CA URL with `X-Serverware-CA-Install-Token`, verify its SPKI hash matches attestation, then write the CA.

The installed trust client accepts only one exact `Content-Length` response frame, rejects transfer encoding, duplicate or malformed headers, truncation, and trailing bytes, and parses JSON with duplicate-key, non-standard-number, and non-finite-number rejection. Verified CA publication is descriptor-relative on supported POSIX systems: every parent is opened without following symlinks, the leaf is created once with `O_EXCL|O_NOFOLLOW` and mode `0600`, and parent/file identity, ownership, link count, mode, write completion, and durability are rechecked before success. Existing output paths are never replaced. This prevents a hostile path from redirecting the privileged write, but a process with the same OS identity can still replace the file after publication returns unless the destination directory is protected by a separate installation boundary.

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

The following clean-room enrollment commands belong to the historical experimental consolidated lane. They are retained for compatibility and source-contract work, not as current Coder provisioning or production release instructions:

```bash
export AGENT_ENROLLMENT_CLEAN_ROOM_IMAGE='docker.io/library/python:3.11.15-slim-bookworm@sha256:28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941'
export AGENT_ENROLLMENT_CLEAN_ROOM_IMAGE_ID='sha256:7e666cfcc7bd4c47b26b7a5ec0116d80e9bc5415ea06c0dc0bd117a50e9fa6c6'
export AGENT_ENROLLMENT_DOCKER_HOST="unix://${XDG_RUNTIME_DIR:?set XDG_RUNTIME_DIR}/serverware-build-docker.sock"
export PORTAL_BROWSER_PLAYWRIGHT_BROWSERS_PATH="$PWD/.tmp/consolidated-test/playwright-browsers"
export PORTAL_BROWSER_CHROMIUM_INSTALLATION_SHA256='sha256:<authenticated-version-directory-digest>'
make build-consolidated-test-artifacts
make verify-consolidated-no-build
```

After the consolidated phases succeed, publish the complete prepared target wheelhouse and separately publish the lowercase SHA-256 digest of its `SHA256SUMS` through an independently authenticated release channel. A fresh artifact-consumer host does not run the repository Make targets. It starts with a trusted CPython 3.11 environment, authenticates `SHA256SUMS`, verifies the closed artifact set, and installs the published package without a repository checkout:

```bash
cd /trusted/serverware-agent-enrollment
EXPECTED_SHA256SUMS_SHA256=<digest-from-authenticated-release-channel>
test "$(shasum -a 256 SHA256SUMS | cut -d ' ' -f 1)" = \
  "$EXPECTED_SHA256SUMS_SHA256"
shasum -a 256 -c SHA256SUMS

/trusted/cpython-3.11/bin/python3.11 -m venv /opt/serverware-enrollment
/opt/serverware-enrollment/bin/python -m pip install --no-index \
  --find-links /trusted/serverware-agent-enrollment \
  --require-hashes \
  -r /trusted/serverware-agent-enrollment/requirements.lock
/opt/serverware-enrollment/bin/python -m pip install --no-index --no-deps \
  /trusted/serverware-agent-enrollment/serverware_enrollment-0.2.0-py3-none-any.whl
test "$(/opt/serverware-enrollment/bin/serverware-enrollment --version)" = \
  "serverware-enrollment 0.2.0"
```

Use `sha256sum` instead of `shasum -a 256` where that is the trusted platform tool. The prepared Linux wheelhouse under `.tmp/consolidated-test/` contains the exact minimal `serverware_agent_trust` wheel, its hash-locked target dependency wheels, the copied lock, the closed wheelhouse manifest, and deterministic `SHA256SUMS`; the checksum set covers every other transferred file and rejects missing or extra artifacts. It does not contain the Serverware control plane or generic repository scripts. Preparation builds the package reproducibly, checks the wheel archive and `RECORD` closure, performs the offline install into the sealed clean-room environment, and records every resulting identity. The later no-build lane only remeasures and exercises that sealed environment in a read-only, non-root, capability-free, seccomp-filtered Linux amd64 container selected by exact image ID with `--pull=never`, `--network none`, bounded CPU/memory/PIDs, bounded output, and bounded tmpfs. The container's deterministic name and labels commit to the frozen manifest and clean-room lane, allowing both the child and the external supervisor to clean it through the dedicated socket and prove it is absent even when execution fails. `make verify-agent-enrollment-wheel-clean-room` remains a compatibility target that runs the same consolidated preparation and verification phases; do not use it between incremental edits. The separate fresh-host installation above is a downstream artifact-consumption procedure, not part of `make verify-consolidated-no-build`. These results are checksum-closed local validation, not source or image provenance, independent execution, supply-chain proof, or TEE attestation.

Authenticating the checksum-file digest through the independent release channel is essential: replacing both the wheelhouse and its co-located checksum file otherwise defeats this check. The host Python, virtual-environment tooling, checksum executable, builder, container image, Docker daemon, and release channel remain trust roots. `serverware-enrollment --version` only confirms compatibility with the signed packet tooling contract; it does not authenticate executable bytes. The installed package exposes `serverware-enrollment` for packet generation, exact packet verification, authenticated-instruction emission, and independent setup-receipt signing; `serverware-attestation` for scoped CA installation; and `serverware-evidence` for the exact packaged `serverware.onboardingEvidence/v3` verifier. The evidence verifier deliberately labels its result `local-integrity-only`: it checks a caller-supplied artifact set but does not authenticate source, server or response authorship, execution, or a TEE. Generate an agent enrollment packet after policy publish and CA verification:

```bash
serverware-enrollment \
  --principal-id agent:demo \
  --proxy-url http://10.42.0.10:8080 \
  --proxy-egress-cidr 10.42.0.10/32 \
  --selector app=demo-agent
```

The packet contains no plaintext credentials or proxy bearer tokens. It gives the agent runtime the proxy/CA environment, policy and attestation pins, safe route canaries, write previews, and a deny-by-default egress policy. The signed `agentHandoff.authenticatedInstructions` renders every required sequence step, proxy environment and header requirement, Kubernetes and `nftables` enforcement requirement, and canary. `agentHandoff.instructionsText` is only a bootstrap template that requires the separately authenticated download path and raw-file digest; the portal uses a fixed verifier command rather than copying that field as trusted text. `POST /api/agents/enrollment` serializes the packet once, returns those exact canonical ASCII bytes with `X-Serverware-Enrollment-Packet-SHA256`, and marks the response `no-store`; the portal rejects a body/header mismatch and downloads the retained response bytes without reserialization. Every packet is bound to a caller-generated base64url nonce, expires after 30-900 seconds, and carries an Ed25519 signature from the response key pinned by attestation. Verification mode requires an independently precommitted raw-file SHA-256, expected principal, and expected nonce; the digest commits the proxy URLs, egress CIDRs, selectors, authenticated handoff, and every attestation pin. The CLI fetches fresh attestation with that nonce, verifies the quote, runtime manifest, measurement pins, expiry, packet digest, and signature, and only then emits the authenticated handoff or a packet with `verificationReceipt`. Production readiness requires a verified packet, a successfully verified egress table, every available bodyless allow canary, the deny canary, and explicit manual approval when no safe allow canary exists.

The control plane exposes `GET /api/key-release/status` and admin-only `POST /api/key-release/verify`. The verifier checks quote signature, material authorization, policy digest, CA SPKI, data-plane binary digest, rollback epoch, release channel, and optional provenance digest, then records key-release events in the audit chain. Docker enables this gate by default for the broker KEK and the Rust data-plane CA private-key handoff.

The Rust data-plane gate exposes agent proxy traffic and `GET /attestation?nonce=...` on port `9090`. Its direct `POST /v1/decide` and `POST /v1/grants` management API is isolated on port `9091`, requires `X-Serverware-Data-Plane-Token` with the high-entropy `SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN`, and rejects unauthorized requests from the parsed request head without waiting for or reading the remaining declared body. Credential leases, audit ingestion, JIT grant consumption, shared rate-limit consumption, and Rust management each use a different required token; production rejects missing, weak, or equal values. Audit callers cannot submit `actor_id` or `actorId`; the control plane derives the stored data-plane actor from its configured instance identity. These remain scoped bearer credentials, not authenticated SVIDs. The header parser may retain only bytes already coalesced into its bounded final header read. Production publishes only proxy port `9090` as host port `8080`; the management listener is reachable only on the internal Compose network. Development additionally maps it to loopback-only `127.0.0.1:9091`. Missing or incorrect tokens receive `401`, management paths on the public listener receive `404`, proxy requests on the management listener receive `404`, and all Serverware service-auth headers are stripped from forwarded requests and response-proof request bindings. [scripts/verify_decision_gate_attestation.py](scripts/verify_decision_gate_attestation.py) verifies nonce binding, runtime manifest digest, SHA-256 digest of the running gate executable, policy hash/signing-key consistency with the control plane, the control-plane quote's pinned data-plane digest, image-signature digest parity, and the declared zero SQLite/filesystem hot path. When `SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID` or `SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID` is set, the Rust gate refuses to boot unless the quote signer and signed bundle key match those pins. `make bench-gate-rs` verifies listener isolation, management authentication, attestation, startup failure for tampered policy signatures, wrong policy-key pins, and wrong control-plane quote-key pins, raw CONNECT preflight allow/deny behavior, CONNECT MITM with dynamic leaf issuance, absolute-form HTTPS forwarding with credential injection, policy-declared request-body streaming, binary response streaming, JSONL, JSON-array, JSON-SSE, nested JSON, form-urlencoded, and CSV request/response streaming redaction, Gmail response validation/redaction, shared JIT grant consumption, dev/external-command/Nitro key release for `broker-kek`/`decision-gate-ca`, release provenance generation, image-release signing, and latency.

[scripts/generate_release_provenance.py](scripts/generate_release_provenance.py) creates `.tmp/release-provenance.json`, signs the canonical provenance with an Ed25519 release key, writes it into `/data/release-provenance.json`, verifies both attestation endpoints expose the provenance digest, and anchors the record in the signed transparency log. Development uses `release.provenance.v1`; production uses `release.provenance.v2`, which binds `serverware.productionImagesBuild/v2`, `serverware.productionImagesPublished/v2`, `serverware.reproducibleBuildVerification/v3`, the compiled launch-authority key identity, and the exact trust-root source digest. [scripts/sign_release_images.py](scripts/sign_release_images.py) creates `.tmp/image-signatures.json`, signs per-image in-toto statements through `SERVERWARE_IMAGE_SIGN_COMMAND`, verifies them through `SERVERWARE_IMAGE_VERIFY_COMMAND`, requires the verifier to bind the same statement digest/key provider/transparency evidence, requires Sigstore-style transparency evidence when `SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1`, writes the bundle into `/data/image-signatures.json`, verifies both attestation endpoints expose the image-signature digest, and anchors a `release.image_signatures.v1` record:

```bash
make release-provenance
make image-signatures
```

The provenance includes the `serverware.sourceTree/v3` manifest and digest, Python requirements and Rust `Cargo.lock` SBOM entries, a CycloneDX 1.5 SBOM digest, Compose config digest, Docker image IDs, container hardening inventory, pre/post-publish attestations, audit/transparency-log state, the transparency-log append response, and a verified inclusion proof for the release record. Production source identity is a deterministic, clean-commit archive of all tracked regular files, including opaque names; a missing tracked file, changed index, dirty worktree, symlink, or submodule is rejected rather than represented as a release-eligible snapshot. There is no production Git fallback. Explicit development filesystem identity works without Git but is a separate, production-ineligible mode with a fixed source/build/config selector and runtime-secret/cache exclusions. The image-signature bundle binds each image statement to that provenance digest, SBOM digest, Compose config digest, source tree digest, and transparency inclusion proof. Docker exercises the production cosign command path through [scripts/cosign_sigstore.py](scripts/cosign_sigstore.py) and the local [scripts/cosign_fixture.py](scripts/cosign_fixture.py); the adapter signs the exact canonical statement bytes, and the completion verifier rejects Sigstore bundles whose embedded message digest, signature, Rekor log entry, or inclusion proof differs from the exposed signing response. Production release channels must set `SERVERWARE_COSIGN_BINARY=cosign`, a KMS/HSM-backed `SERVERWARE_COSIGN_KEY`, `SERVERWARE_COSIGN_KEY_ID` equal to the SHA-256 SPKI digest of the pinned ECDSA/RSA key in `SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY`, and `SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID` for the expected Sigstore transparency log. Keyless Fulcio identity verification is not yet implemented by release completion, so production readiness rejects keyless-only and mixed key/keyless configurations.

The `audit-anchor` service also supports external checkpoint publication through `SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND`. Docker sets this to [scripts/transparency_checkpoint.py](scripts/transparency_checkpoint.py) in fixture mode with `SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED=1`, so every local signed tree head must be published to a managed-log fixture before the append is accepted. The same adapter can publish to an HTTPS managed-log endpoint with `SERVERWARE_TRANSPARENCY_LOG_URL`; it sends a canonical `serverware.externalTransparencyCheckpointRequest/v1` document, requires the response to bind the checkpoint digest, request digest, tree size, tree head, provider, and log ID, and verifies an Ed25519 signed receipt by default. `make verify-transparency-checkpoint` covers the fixture path, TLS fail-closed behavior, digest mismatch rejection, missing receipt rejection, and signed HTTP managed-log success path. Production release channels can either point that URL at a public/managed log implementing this receipt contract or replace the command with a log-specific publisher that returns the same normalized checkpoint response.

The default Compose file applies the custom seccomp profile. Linux hosts that support AppArmor can also install the checked-in AppArmor profile and run Compose with the override:

```bash
make install-apparmor
make verify-apparmor-contract
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up -d --build
make verify-apparmor-runtime
```

`verify-apparmor-contract` checks the profile and Compose override everywhere, including Docker Desktop. `verify-apparmor-runtime` is intentionally Linux-only: it checks that the profile is loaded, starts the full override stack, verifies each container's Docker `security_opt`, reads `/proc/self/attr/current` inside every service, and proves AppArmor denies a normally readable `/proc/sys/kernel/hostname` probe.

`make production-release-proof` only finalizes independently prepared final-v1 evidence. Build, publication, signing, and deployment use separate explicit targets documented in [docs/release-stages.md](docs/release-stages.md); no aggregate target crosses those stages. The release owners must still supply isolated SLSA provenance, independent source-to-OCI and OCI-to-EIF reproduction, the signed release record, real Nitro deployment, and off-host witness/CAS evidence. Coder participates only in the engineering phase. `make run-production-readiness` remains a developer/readiness entry point, not a trusted final bootstrap.

Production deployment is an evidence pipeline, not `docker compose up` with different environment variables:

1. Freeze a clean reviewed commit and replace the checked-in non-operational launch-authority public-root sentinel with the independently controlled production root. Commit that source change before building anything.
2. Configure Google, X, and operator OIDC clients with their exact HTTPS callbacks; provision owner-only client-secret files, TLS keys, the WebAuthn trust bundle, recovery root, and distinct metadata/grant/audit/recovery-witness PostgreSQL roles.
3. Copy `ops/production-readiness.env.example` to a private `ops/production-readiness.env`, replace every placeholder, pin every executable/image/key/SPKI/fault-domain identity, and keep the file and secrets out of Git.
4. Publish and externally verify the signed PolicyBundle, candidate activation/canary evidence, audit checkpoint, and two independent signed build captures. A developer signature or two labels on one reused build does not count as independence.
5. Initialize the off-host launch-authority ledger once, enroll the exact release and relay leaf certificate in its monotonic registry, and operate its signing key in HSM/KMS custody with an external high-water witness.
6. On the target Linux/TEE host, install AppArmor and the measured helper binaries, provision KMS Recipient material, immutable release storage, registry credentials, systemd, the exact production trust keys, and the independently authenticated canonical nonce-rollback-assurance pin contract below `/etc/serverware`.
7. Run each release stage separately in its owner's environment with the complete evidence paths. Retain exact independently signed reports when transferring them; do not regenerate a signed report in a later stage. Do not promote a release for which preflight, build, publication, signing, deployment, launcher authorization, response proof, or final verification is skipped.
8. From an independently administered verifier, pin the release/image/hardware/final-authority keys, verify the completion and response-proof artifacts, then issue short-lived enrollment packets and install the CA on each agent through the verifier-mediated flow.

The following invocation prepares deployment from already built, published and signed artifacts. It is separate from Coder engineering checks and from final-v1 verification:

```bash
cp ops/production-readiness.env.example ops/production-readiness.env
make production-release-deploy \
  PRODUCTION_POLICY_BUNDLE=/evidence/policy-bundle.json \
  PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY=/evidence/policy-signing.pub.pem \
  PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT=/evidence/policy-identity.json \
  POLICY_ACTIVATION_VERIFICATION_OUT=/evidence/policy-activation-verification.json \
  POLICY_ACTIVATION_VERIFICATION_SIGNATURE=/evidence/policy-activation-verification.signature.json \
  POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY=/evidence/policy-activation-verifier.pub.pem \
  REPRODUCIBLE_BUILD_VERIFICATION_OUT=/evidence/reproducible-build-verification.json \
  REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE=/evidence/reproducible-build-verification.signature.json \
  REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY=/evidence/reproducible-build-verifier.pub.pem \
  PRODUCTION_RELEASE_ROOT=/opt/serverware/releases/sha256-<source-digest> \
  PRODUCTION_SOURCE_TREE_DIGEST=sha256:<64-lowercase-hex> \
  PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS=/etc/serverware/nonce-rollback-assurance-pins.json \
  PRODUCTION_EXPECTED_NONCE_ROLLBACK_ASSURANCE_PINS_SHA256=sha256:<independently-authenticated-64-lowercase-hex>
```

The checked-in [v3 launch-manifest example](ops/production-release-launch.json.example) is documentation-only placeholder material. Generate the deployed manifest from measured files and an independently authenticated canonical pin contract; do not install the example as production input. The launch manifest and bootstrap receipt carry the verifier-state/store trust-pin projection. The complete mTLS endpoint, fixed paths, client/server SPKI pins, response/deadline limits, and service-configuration digest belong to [public attestation config v2](schemas/public-attestation-config.v2.schema.json), not to the launch manifest.

Before starting production Compose, provision one unencrypted Ed25519 PKCS#8 response-signing key and its SPKI public half. Set `SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE` to a canonical-path, single-link regular file owned by production control-plane UID `65532` with mode `0400` or `0600`, and set both response-signing public-key settings to the same protected public file. Host preflight no-follow reads bounded stable snapshots, validates secure ancestors, private-key type and ownership, and exact private/public/key-ID equality before deployment. Compose mounts only the private file into the control plane, read-only; the runtime repeats single-link, mode, owner, type, and identity checks without following the final path. The pinned health program uses explicit failures that remain active under optimized Python, derives the live public identity, compares the published custody trust, and then requires authenticated HTTPS health. This is pre-enclave host custody. A hardware deployment must generate or unwrap that key inside the measured TEE instead.

The native bootstrap is trusted-host readiness only. `serverware-production-launcher` consumes `serverware.productionReadinessLaunch/v3`, sends `serverware.launchAuthorizationRequest/v2`, verifies `serverware.launchAuthorization/v2`, and passes a sealed `serverware.bootstrapReceipt/v3` on exact descriptor `198`. The release wrapper requires a fresh successful systemd invocation receipt: the unit must have run rather than been condition-skipped, report a new invocation identity, exit normally with status zero, and produce fresh output identities matching that invocation. The launcher samples authorization expiry once and projects it onto Linux `CLOCK_BOOTTIME`. Its child completes setup and then waits behind an exact one-byte plus EOF barrier until the parent validates the process group and deadline. Expiry uses `SIGKILL` against the process group, leader, and adopted descendants; a nonzero phase result is returned before any later revalidation can erase it. Host preflight and `run_production_readiness.py` reject final mode.

Successful readiness writes the closed [completion proof v6](schemas/completion-proof.v6.schema.json) as exact compact canonical JSON followed by one LF, with `verification_mode:"readiness"`, `actionAuthorization:null`, and `okForAction:false`. Final-v1 parsing validates the complete nested v6 shape and recomputes its canonical core and bindings; it does not trust a shallow digest or an indented reserialization.

Production fixes `stateDirectory` at `/var/lib/serverware/production-proof`; both manifest generation and the native launcher reject any substitute. The v3 manifest also fixes `launchAttemptJournal.path` at `/var/lib/serverware/production-proof/launch-authorization-attempt.v1.json` and `launchAttemptJournal.lockPath` at `/var/lib/serverware/production-proof/launch-authorization-attempt.v1.lock`. That journal supports exact readiness-attempt recovery only. Its rollback authority remains the external monotonic witness, not the host filesystem.

The v3 manifest binds both rollback systems. Its `nonceRollbackAssurance` block pins the verifier-state service and independently signed store assurance. Its authorization block pins an independently administered monotonic launch witness, a separately signed witness-store-assurance document, both public keys, both identities, and both administrative domains. The launch authority's registry v2 and ledger schema v7 remain necessary, but they are not sufficient: production authorization fails closed without the external witness transition and exact witness/store trust pins. Coordinated rollback of the local registry and ledger is therefore not accepted as current state.

Ledger v7 is a deployment migration boundary. Existing v5 or v6 ledgers require an explicit offline migration that preserves the witness high-water, sticky revocation, and exact prepared-operation state, or deliberate reinitialization and reprovisioning. Regenerate the v3 launch manifest and independently authenticated global-role-registry file and digest pins after migration. Drain or explicitly migrate every nonterminal operation created under an older launch or role contract before enabling the v7 authority.

The launch authorization is a short-lived, idempotent `trusted-host-readiness` capability using `trusted-host-wall-clock`; it is not secure TEE time and does not claim one-use action redemption. The manifest's `globalRoleRegistry` binds the canonical `serverware.productionLaunchGlobalRoleRegistry/v1`, its independently pinned root-owned file digest, the ten roles present in the native launch contract, and the explicit roles outside that claim. Every in-claim SPKI must be distinct. Final verification separately enforces global separation across its complete role registry. The checked-in launch-authority root remains a non-operational sentinel; production requires independently controlled HSM/KMS-backed authority, witness, and store-assurance keys plus off-host TLS identities.

The native launch path measures and binds host inputs, but the kernel, root, systemd, loader/DSO graph, Docker daemon/socket, release mount, and host wall clock remain trusted. A hostile root can still alter or impersonate host execution. The native launcher is therefore non-authoritative context, not proof that the whole codebase or responding server ran in a TEE.

Final authority is the independent Manifest-v6 public Nitro verifier. Its persisted result is the closed [release completion verification v1](schemas/release-completion-verification.v1.schema.json), which binds fresh Nitro evidence, release and response identity, protected verifier state, current-head authorization and redemption evidence, the fully revalidated and recomputed nested canonical completion-v6 artifact, and the explicit non-authoritative host-bootstrap boundary. The result is not self-digest-only: `serverware.releaseCompletionResultSignature/v1` authenticates the result core under a dedicated, globally separated `releaseCompletionResult` Ed25519 role. A caller must independently pin the expected provider, signing key ID, signing-key SPKI digest, and final role-registry digest; co-located fields are not their own trust anchor. Production custody for that authorship key belongs in an independently operated HSM/KMS or measured TEE, and no such execution or custody is proved by this batch. Even a valid final v1 artifact is historical evidence with `actionAuthorization:null` and `okForAction:false`. An external stateful action gate must recheck the live final head and atomically consume the redemption-receipt identity while performing an idempotent action.

The public-attestation path uses a service-issued verifier challenge, durable prepared operations, exact idempotent recovery for the identical request, signed nonce and verifier-state receipts, signed store assurance, a literal-IPv4 verifier-state endpoint, one total deadline, and signing-role separation. The public Nitro live-result signature preimage begins with the exact domain `serverware.publicNitroLiveVerificationResultEnvelope/v1\x00signatureAlgorithm=Ed25519\x00`. Every external integer is bounded to signed-64 range `0..9223372036854775807`, and provider names match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. A terminal result records `responsePending`; it never claims downstream delivery. Terminal journals serialize pruning, no-replace publication, and capacity under one directory-global inventory lock before taking an identity lock. Those are source contracts, not current runtime proof. Crash/restart closure still depends on the independently administered durable service and identical-operation recovery; do not infer it from the reference local store.

The current wire schemas are [launch manifest v3](schemas/production-launch-manifest.v3.schema.json), [launch request v2](schemas/launch-authorization-request.v2.schema.json), [launch authorization v2](schemas/launch-authorization.v2.schema.json), [bootstrap receipt v3](schemas/bootstrap-receipt.v3.schema.json), [trusted-host completion proof v6](schemas/completion-proof.v6.schema.json), and [final release verification v1](schemas/release-completion-verification.v1.schema.json). The generator, Make target, launcher, readiness verifier, and final verifier consume the current authority, attempt-journal, witness, witness-store, global-role-registry, exact compact-v6-plus-LF, and full nested-v6 recomputation bindings. The old `final_completion` result and prior public/final `public_verifier_bridge`, live-result, final-identity, and missing-schema forms remain only as rejected compatibility cases.

The current v3/v2/v3, v6, and final-v1 source contracts have not been built or executed in this batch. Real independently administered TEE, KMS/HSM, witness, action-gate, live-provider, and physical-YubiKey evidence is still absent.

Production enrollment accepts only `serverware.enrollmentVerifierReceipt/v3`. The independent verifier must bind the quote provider, exact quote and verified-claims digests, quote-verifier and evidence identities, assurance/debug/self-rooted state, and launcher-signed proof that deny-by-default egress was installed in the recorded agent network namespace with complete allow and deny canary results. Development, debug, self-rooted, incomplete-assurance, fixture-egress, and legacy v2 receipts are rejected on the production channel. `make build-agent-enrollment-wheel` creates a `SOURCE_DATE_EPOCH`-controlled package wheel plus an offline runtime wheelhouse from the repository-owned, hash-locked `serverware_agent_trust/requirements.lock`; canonical `SHA256SUMS` closes the exact artifact set within one build, but reproducibility across independent environments must be demonstrated separately and the checksum-file digest must arrive through a trusted release channel. Installation uses a fresh trusted CPython 3.11 environment, verifies every checksum, applies the copied lock with `--require-hashes`, and installs the exact package wheel with `--no-deps`. The signed tooling version is a compatibility constraint, not executable-byte attestation. The CLI's local PEM receipt signer and development evidence exercise the contract but do not establish production custody. The production receipt signing key belongs behind an independently operated KMS/HSM or equivalent service, which this repository does not implement or prove.

```bash
make verify-production-config
make generate-production-readiness-claims
make collect-nitro-kms-evidence
make verify-production-readiness
# run-production-readiness emits trusted-host completionProof/v6 readiness only.
# Independent final verification emits releaseCompletionVerification/v1.
```

`verify-production-config` rejects dev/fixture settings and checks that control-plane admin auth uses an explicit high-entropy token, OIDC bearer verification and browser login are enabled with pinned issuer/audience/JWKS/role claim, browser sessions require WebAuthn with bounded pending/challenge TTLs, HTTPS authorization/token endpoints use the issuer origin, the HTTPS callback is exact, scopes are bounded and include `openid`, the token endpoint client authenticates, and the client-secret file is owner-only. It also requires complete Google and X providers, exact provider callbacks on `SERVERWARE_PUBLIC_URL`, OAuth state and pending-credential TTLs within their bounds, bounded pending capacity, and `credential.oauth.activate` in the two-person action set. The mandatory production host preflight requires all three OAuth/OIDC client-secret files to be owned by the explicit distroless control-plane UID `65532`, so a host-readable but container-unreadable bind mount cannot pass deployment. It also checks the production WebAuthn origin, disables direct CA download in favor of bounded install sessions, requires hardware-attested mutation WebAuthn restricted to `yubikey,hardware`, and requires two-person approval for high-risk credential/route/policy/RBAC/token/break-glass mutations plus WebAuthn registration, revocation, and trust publication. It requires route-selection dry runs and configured staged-candidate thresholds, but configuration alone is not activation evidence: only the authenticated durable authority path may accept measured candidate evidence, and neither active-policy baseline events nor direct audit rows satisfy the gate. It also requires Nitro NSM attestation, KMS/HSM release, stable public-key cosign/Sigstore identity plus pinned Rekor log ID, external transparency checkpointing, AppArmor, Postgres-backed metadata/grant/audit stores including `oidc_browser_sessions`, the shared rate-limit consume endpoint, required agent enrollment plus egress enforcement, and immutable production image refs with required no-shell verification. `verify-production-readiness` additionally signs and verifies a live Sigstore probe with required transparency evidence, expected key identity, and expected Rekor log ID, publishes and verifies an external transparency checkpoint probe, checks the metadata/grant/audit Postgres stores are reachable with the required tables, runs live Nitro quote/release probes from `SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON` or `--claims-file`, verifies the configured production image root filesystems contain no shell binaries, and requires the Linux AppArmor runtime probe to pass.

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
# Both entry points are trusted-host readiness only and reject final mode.
make production-host-preflight PRODUCTION_READINESS_ENV=ops/production-readiness.env AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json
make run-production-readiness PRODUCTION_READINESS_ENV=ops/production-readiness.env AWS_KMS_MATERIALS_OUT=/etc/serverware/kms-materials.json
```

`make production-release-proof` invokes `finalize-production-final-v1` with the same independently supplied inputs as the finalization command above. It does not prepare the signing request or run the legacy host-readiness service.

[Dockerfile.production](Dockerfile.production) builds the Python control-plane/audit-anchor image on a distroless Python nonroot base, and [data-plane/decision-gate-rs/Dockerfile.production](data-plane/decision-gate-rs/Dockerfile.production) builds the Rust data plane on a distroless cc nonroot base plus the static production-launcher artifact. Production installs only the control-plane requirements and starts `serverware.control_plane_runner`; the control plane serves TLS from `serverware.crt` and `serverware.key` in `SERVERWARE_CONTROL_PLANE_TLS_DIR`, while `ca.pem` in the same directory pins that channel for Rust. `SERVERWARE_ATTESTATION_HELPER_DIR` must contain the executable basenames configured by the six attestation/proof command settings plus the response-proof collector, mounted read-only as `/opt/serverware/bin`. Host preflight checks the pinned certificates, helpers, images, Compose model, and release artifacts, but its signed result remains trusted-host readiness context. Local image IDs and host measurements are not accepted as final Nitro authority.

The production image helper, Python runtime export, static launcher build, and publication gate are fixed to `linux/amd64`; another platform is rejected rather than silently producing a mixed-platform proof set. `production-release-proof` runs `verify-agent-enrollment` and then `verify-setup-session-api` before production policy validation or any build/publish mutation. Its benchmark step removes `.tmp/decision-gate-rs-bench.json` immediately before regeneration, so an existing ignored `.tmp` file is never accepted as current evidence after a failed or interrupted run.

Production dependency resolution is split from production building. On a connected staging host, set `SERVERWARE_PRODUCTION_DEPENDENCY_SNAPSHOT_URL` to the credential-free HTTPS URL of the immutable snapshot named by the committed manifests, then run `make fetch-production-dependency-cache`. The fetcher accepts no redirect and installs the CPython wheelhouse, Cargo vendor tree, and launcher APKs only when every artifact matches its committed SHA-256. Updating those manifests and publishing a replacement snapshot is a separate, explicitly reviewed dependency-release operation; this checkout intentionally has no target that refreshes trust pins. Every production image, Python runtime, and launcher build runs `make verify-production-dependency-cache` first, passes `--network=none` to Docker, and uses only `pip --no-index --require-hashes` or Cargo `--frozen` inputs inside the Dockerfiles. `make build-agent-enrollment-wheel` is a compatibility name for the consolidated preparation phase. That phase produces distinct CPython 3.11 host and `manylinux2014_x86_64` wheelhouses under `.tmp/consolidated-test/`; each closed manifest records the package wheel, dependency wheels, lock files, sizes, SHA-256 digests, and exact Python/platform target.

The `production-release-deploy` stage requires externally supplied `PRODUCTION_AGENT_*` inputs and checks them before deployment. Those checks remain readiness gates; they do not turn the native launcher into the independent Manifest-v6 final verifier.

For two independently produced image builds, capture and compare normalized rootfs contents and the extracted Rust binary:

```bash
make capture-reproducible-build PRODUCTION_IMAGES_BUILD_FILE=/builder-a/production-images-build.json REPRODUCIBLE_BUILD_BUILDER_ID=builder-a REPRODUCIBLE_BUILD_SIGNING_KEY=/builder-a/attestor.key.pem REPRODUCIBLE_BUILD_CAPTURE_OUT=/evidence/builder-a.json
make capture-reproducible-build PRODUCTION_IMAGES_BUILD_FILE=/builder-b/production-images-build.json REPRODUCIBLE_BUILD_BUILDER_ID=builder-b REPRODUCIBLE_BUILD_SIGNING_KEY=/builder-b/attestor.key.pem REPRODUCIBLE_BUILD_CAPTURE_OUT=/evidence/builder-b.json
make validate-reproducible-builds REPRODUCIBLE_BUILD_LEFT=/evidence/builder-a.json REPRODUCIBLE_BUILD_RIGHT=/evidence/builder-b.json REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT=builder-a=/trust/builder-a.pub.pem REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT=builder-b=/trust/builder-b.pub.pem
```

The historical comparison normalizes archive ordering, timestamps, and Docker-generated runtime files while preserving file bytes, paths, types, permissions, ownership, links, devices, security extended attributes, image/source metadata, and the Rust executable digest. Capture removes any pre-existing build artifact, runs an exact shell-free build command from a clean checkout, verifies the source remains unchanged, and then exports the generated images. Each capture contains both a signed manifest and a separately signed `serverware.buildExecutionStatement/v1` binding the clean source/revision, command and Dockerfile digests, operator-pinned isolated-environment identity, unique execution nonce, generated build-v2 artifact, and completed capture. Verification requires exactly two distinct operator-pinned builder identities, keys, and nonces and rejects preloaded-image-only, unsigned, forged, swapped, replayed, same-builder, and same-key evidence. This is experimental reproducibility coverage: it does not independently measure the environments, establish SLSA provenance, authorize production, or establish TEE execution, and it always reports `hardware_proof:false`.

After a real staged policy activation, validate the complete PostgreSQL/HA audit slice containing candidate-bound shadow evaluations, candidate dry-runs, explicit activation/publish records, and post-activation allow and denial canaries:

```bash
make validate-policy-activation-evidence \
  POLICY_ACTIVATION_EVIDENCE_FILE=/evidence/policy-activation.json \
  POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY=/trust/policy-signing.pub.pem \
  POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY=/trust/audit-checkpoint.pub.pem \
  POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR=spiffe://prod.serverware/decision-gate/instance-01
```

This verifier runs the canonical PolicyBundle schema, semantic compiler, signature check, and production identity gate; rejects candidate-hash data-plane traffic before explicit activation and all fixture/synthetic production markers; and verifies the full audit slice against a separately pinned Ed25519 checkpoint key. It validates evidence already collected from the deployment; it does not synthesize production traffic or hardware proof. Before the one-shot release, an external CI/HSM attestor signs the exact deterministic activation and reproducibility verification report bytes as `serverware.externalArtifactSignature/v1`; input preflight, host preflight, and final completion all re-verify those detached signatures and current file digests.

`make production-handoff` writes `.tmp/production-handoff.json`, a redacted machine-readable handoff manifest for host readiness. It verifies local release artifacts and records remaining host-bound work without claiming completion. Do not invoke a native runner final mode: the independently pinned Manifest-v6 public Nitro verifier consumes the real enclave evidence and emits `serverware.releaseCompletionVerification/v1`.

Use `make sign-production-images` after publishing production images. It loads the strict production readiness env, reads `.tmp/production-images.env` without shell evaluation, and passes the digest-pinned refs to `scripts/sign_release_images.py`; `scripts/verify_release_completion.py` rejects completion proofs whose signed image digest set differs from the no-shell production image set verified by readiness.

## Audit

Proxy decisions, response validation results, Rust data-plane decisions, JIT approval decisions, control-plane approval decisions, credential changes, route changes, log clearing, and demo policy seeding are written to the hash-chained audit store. Docker uses Postgres as the authoritative audit store with `pg_advisory_xact_lock` serializing chain appends across control-plane instances; SQLite remains the local fallback. Ordinary redacted telemetry uses a bounded Rust spool. Batches are capped at 1.5 MiB before send, split while preserving order, and split again after a signed `413`; a single oversized event is rejected instead of poisoning the queue. Every event receives a random stable `eventId` that survives requeue and retry. The control plane derives its immutable row ID from that ID plus the server-configured instance identity: an exact lost-ACK retry is idempotent, while partial or mismatched history returns `409`. Before every credential-bearing upstream send, Rust synchronously posts `data_plane.credential.release_started` and requires a nonce-bound signed control-plane acknowledgement after the event is durably appended. The gate verifies the response signature with the response key and context pinned by its attested policy snapshot, then requires `serverware.dataPlaneAuditAck/v1`, the configured instance identity, exact accepted count, and SHA-256 digest of the exact outbound request bytes; a bare or incorrectly signed `2xx` is rejected. Missing configuration, stale trust, transport failure, signature/ACK mismatch, or ingest failure returns local `503` before release. JIT use additionally requires its authoritative grant-consume record. The control plane ingests data-plane events as `actor_type=data-plane`, derives `actor_id` from `SERVERWARE_DATA_PLANE_INSTANCE_ID`, rejects caller-supplied actor fields, and appends the event to the same chain. Until mTLS/SVID authentication and measured producer signatures are implemented, that actor is protected by the narrowly scoped audit-ingest token rather than a peer certificate. Each event includes the previous event hash and its own canonical hash:

Rate-limit audit and metadata rows store typed operation commitments instead of clear operation values. When upgrading an older store, Serverware replaces the visible legacy value with its commitment while retaining the exact canonical preimage in a versioned AES-GCM envelope bound to the row and active master-key ID. This preserves historical chain verification and quota state without leaving the sensitive value in the current logical row. The audit-chain migration validates its complete candidate set before mutation. The metadata migration performs updates and complete postcondition validation in one rollback-safe transaction. Both take schema and legacy compatibility locks, use `ACCESS EXCLUSIVE` table locks on Postgres, install triggers that reject rolling plaintext writes, and atomically record their exact v2 gates. Each store transactionally rewraps its own envelopes during key rotation; the audit and metadata commits are independently restart-convergent, not one cross-store atomic transaction. Production historical keys must come from a one-open, no-follow, owner/mode/size-checked authenticated keyring receipt bound to the broker release receipt. Full audit verification loads historical key material lazily and fails closed when an encrypted preimage cannot be authenticated or the migration gate is unsupported. This is logical redaction, not physical erasure: MVCC history, WAL, journals, snapshots, and backups must be expired or re-encrypted under the deployment's separate retention procedure.

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

The production and normal credential-bearing allow/inject/response path is Rust. Mitmproxy remains credentialless development compatibility only; the Rust path keeps the expensive parts in process:

- plaintext credentials are unwrapped only for purpose-bound v3 `dispatchSecret` leases scoped by principal, route, credential, policy, executable, expected generation, and applicable release authority instead of being decrypted from SQLite on every request or published through marker files;
- the Rust gate synchronously singleflights missing or expired secret-free generation checks, tracks only successful authenticated request scopes as hot for 30 seconds, and polls that bounded set every `0.25` seconds with a one-second renewal margin; cold scopes create no background traffic, and JIT background work never requests a secret;
- Gmail message IDs from validated recent responses are held in an in-memory proof cache scoped by principal, credential version, policy hash, Gmail user, and cutoff bucket;
- ordinary request/response audit events are queued to a bounded background spool, while `data_plane.credential.release_started` is posted synchronously and must receive a durable control-plane acknowledgment before release;
- other Rust-originated CONNECT, request, response, grant, and JIT consume telemetry is queued in the data plane and batch-ingested by the control plane;
- verified Postgres audit chain heads are exported off-path to a signed Merkle log; Compose uses a local fixture, while production requires an independently managed and witnessed backend;
- policy matching uses the signed compiled policy snapshot.

Docker uses Postgres as the authoritative release-authorization store; SQLite is a development fallback. The Rust production proxy uses the reserve/dispatch/complete protocol. Python parity helpers exercise the same state semantics but the Python transport rejects credential-bearing routes and is not a production forwarding path. Reserve locks and reserves the matching one-use JIT grant and every shared rate-limit counter in one transaction, or commits neither. A first real JIT request without a grant creates or reuses its exact pending approval only after the denied reserve has left no partial state. Pre-send dispatch and terminal completion are exact, idempotent state transitions; a request proven not to have been forwarded refunds its reservation, while an uncertain result after dispatch is committed conservatively. Lifecycle events use a durable outbox before hash-chain audit delivery. If the release authority is unavailable, malformed, or returns a mismatched binding, the proxy returns `503` without credential injection or upstream contact. Local Rust `POST /v1/grants` entries require the scoped data-plane management token and are non-authoritative when atomic release authorization is enabled.

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

The Rust data plane in [data-plane/decision-gate-rs](data-plane/decision-gate-rs) isolates policy evaluation from mitmproxy and FastAPI. It verifies an attested policy trust root, signed snapshot, and persistent policy high-water; authenticates principals and CONNECT authorities before TLS leaf issuance; retains only digests of the CONNECT identity material; and revalidates principal existence, identity-policy equality, source CIDRs, required-header commitments, proxy-token binding, and token expiry against the current signed snapshot before every inner request on an open tunnel. Identity changes close the tunnel before credential, JIT, quota, or upstream work. Canonical uppercase methods and unique query keys are required before policy evaluation; duplicate query keys are denied rather than allowing provider-specific first/last-value semantics to diverge from a sorted request commitment. The gate validates upstream TLS; fetches exact purpose-bound v3 credential material inside the signed/encrypted v2 envelope; classifies adapter operations; enforces shared JIT and quotas; and applies bounded status-specific response projection. Credentialless opaque streams and declared structured redacting stream modes use backpressure and size caps. Credential-bearing opaque/non-redacting response streams and credential-bearing mutating request streams are rejected at policy admission. Cold policy scopes are not prefetched. A real request or authorized preview synchronously singleflights `generationMetadata`, which structurally contains no secret, does not load the broker master key, performs no decrypt or OAuth refresh, and contacts no provider. Rust independently enforces the closed typed metadata allowlist before either metadata or secret cache insertion. Only successful authenticated non-preview use makes the exact scope hot for bounded metadata renewal. Non-JIT hot scopes may renew five-second secret leases, but JIT background work never requests `dispatchSecret`: the control plane atomically claims the exact attempt/request/recipient/nonce/generation/policy/grant/approval issuance before decrypt or refresh, caps the lease to reservation expiry, and revalidates after encryption. A lost response strands that claim and requires fresh approval. Expired or invalid secret leases are removed and zeroized. In-memory request-only decisions without a metadata miss, shared JIT, or shared rate limit make no SQLite, Postgres, or filesystem call, and no decision response contains plaintext credentials.

Historical verified post-gate Docker benchmark, measured on an earlier source snapshot over the Compose network from the control-plane container after `100` warmups and `1000` decision calls:

```json
{
  "p50_ms": 0.421,
  "p95_ms": 0.643,
  "p99_ms": 1.337,
  "max_ms": 2.53,
  "mean_ms": 0.459
}
```

The full `make bench-gate-rs` matrix must pass on the final source tree before release evidence is regenerated. The benchmark runs inside the Docker network so Docker Desktop host-port bridge jitter is not attributed to the gate. Its pre/post nonce-bound documents are unsigned runtime self-reports in development, not vendor attestations; they require the executable, policy, and immutable runtime-manifest digests to remain unchanged, while mutable health counters are reported outside that manifest. Production release evidence must rerun the path on the target host and bind it to a verified vendor quote.

Historical integrated local checkpoint, 2026-07-16: the Rust main suite passed 243 tests, the custody library 43, custody runtime 14, and proof client 29. Python credential constraints with schema validation, portal static contracts, OIDC, OAuth, policy canary, desktop/mobile Playwright journeys and refreshed screenshots, control-plane response identity, and credential-lease delivery also passed on that snapshot. These counts are retained as history and do not describe the current worktree. No hardware-backed production claim follows from them.

Rust is the current implementation track because it already carries the required policy, CONNECT, credential-lease, and response-validation behavior. The `/v1/decide` microbenchmark alone does not establish production scalability or prove Rust superior to an unbuilt Envoy candidate. Release builds use the lockfile, strip non-runtime symbols, and omit the nondeterministic GNU linker build ID. The measured executable digest is authoritative only when the generated Compose pin, nonce-bound attestation, key-release result, benchmark, provenance, image signatures, and independent reproducibility evidence all agree within one source-bound evidence generation. Narrative documentation does not pin a current digest. The local provenance and image-signature artifacts are development fixtures; production images, signatures, benchmark bindings, and hardware quotes must be regenerated together from one exact checkout on the target host. Any replacement must prove the same explicit HTTPS CONNECT interception, dynamic attested leaf issuance, response mutation/validation, no hot-path DB/filesystem calls, and an acceptable TEE TCB under comparable full-proxy load.

## TEE Path

The current Docker build still stores dev materials locally, but their use is gated by signed attestation claims: the broker KEK is not used until `broker-kek` key release succeeds, and the Rust data-plane CA private key is not published until `decision-gate-ca` key release succeeds with the release-pinned Rust binary digest from `SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST`. The default development quote is self-signed by `/data/dev-tee-quote-ed25519.pem`; its software lease recipient protects disk and network delivery, not process memory from host root. The AWS Nitro-compatible provider verifies Nitro CBOR/COSE documents and can require KMS recipient ciphertext, but Docker fixtures do not prove hardware PCR enforcement, enclave key custody, CA-key custody, or parent-host ciphertext-only observation.

For eligible buffered successful HTTPS responses, a client nonce can request a `serverware.proxyResponseProof/v3` artifact. The external capture and signed v2 runtime statement bind the exact atomic authorization snapshot historically observed at upstream dispatch: grant and approval IDs when present, credential ID/version, request and operation digests, attempt and consumption identity, reservation expiry, raw upstream status/body/policy-header digests, projected emitted status/headers/body digest, policy, runtime manifest, executable, release, SPIFFE server instance, and TLS exporter. Rust sends a fresh nonce in the actual dispatch request and embeds the canonical `serverware.controlPlaneAuthorizationReceipt/v1` request, signed response, and signature in the runtime statement. Production verification pins the control-plane response-signing SPKI, verifies that embedded signature independently, and requires its complete authority tuple and millisecond dispatch timing to match the proxy statement. There is no separate receipt file to substitute or cross-wire. The artifact retains only the canonical client-request digest, not raw path, query, or header values; recomputation requires later disclosure of the complete canonical safe preimage. The inline proof deliberately makes no current-authorization, forwarding-completion, or downstream-delivery claim; the client proves receipt by possessing the verified response and proof. It requires `GET`, CONNECT TLS, and a buffered route; `HEAD` fails closed. Legacy authority-free proof versions fail closed.

Eligible successful streaming `GET` routes use the separately domain-separated `serverware.streamingProxyResponseProof/v1` contract and `EXPORTER-Serverware-Proxy-Stream-v1`. The gate hashes and counts raw upstream bytes separately from projected released entity bytes, scans the body and every policy-selected upstream header for credential reflection, and writes exactly `X-Serverware-Stream-Proof-B64` and `X-Serverware-Stream-Proof-SHA256` trailers only after normal EOF, final validation, policy-snapshot recheck, atomic release-authority verification, signing, and attestation. Truncation, validation failure, revocation, or signing failure closes without the terminal zero chunk or proof trailers. The strict collector rejects ambiguous HTTP framing and malformed chunks/trailers, keeps unverified bytes in an unlinked `0600` staging file, publishes the durable verified body first, and publishes the no-replace proof last as the completion marker. It traverses every output-directory component with descriptor-relative `openat(..., O_DIRECTORY|O_NOFOLLOW)`, rejects `..` and intermediate symlinks, and requires body and proof descriptors to identify the same owner-owned exact-mode `0700` directory. Concurrent collectors serialize through a descriptor-relative sidecar lock; final outputs become `0400`, losing collectors never delete reused bodies, and bounded lock-held scavenging removes only exact client temporary names older than 24 hours. Suspicious substitutions are retained for manual review. A retry can recover a crash-orphaned body only when its private, same-owner, single-link regular-file identity, mode, size, and digest still match immediately before proof commit; conflicts and inode substitutions are never overwritten. These controls assume a dedicated collector UID and local POSIX filesystem: every same-UID process is inside the trusted-writer boundary, and proof presence alone is not an integrity seal. Consumers must verify the committed proof and its exact body digest and byte count. Terminal proof publication serializes against snapshot replacement and gives the write plus required flush one shared, non-retried, absolute one-second socket I/O deadline. [scripts/test_response_proof_capture.sh](scripts/test_response_proof_capture.sh) validates buffered and streaming proofs in Docker against [schemas/streaming-response-proof.v1.schema.json](schemas/streaming-response-proof.v1.schema.json), including separate HTTPS CONNECT cases for JSON Lines, top-level JSON arrays, JSON SSE, nested JSON, form-urlencoded, and CSV with exact projection and secret-removal assertions. That JSON Schema validates structure and bounded syntax only; the Rust verifier must still verify signatures, attestation, equality bindings, digest, and size. Production release completion supports independently pinned buffered v3, streaming v1, and observation v1 contracts; it reopens, hashes, and validates each contract's evidence before acceptance. Proof bundles are sensitive artifacts rather than public digest-only metadata because authorization receipts and selected response-header preimages can contain grant, approval, quota, ETag, or authentication-challenge values. Both local proof paths use development TEE fixtures; a real TEE claim still requires evidence collected on deployed Nitro/SEV-SNP/TDX hardware.

Create the collector key separately and keep it owner-readable only. A streaming collection uses distinct final body and proof names in one exact-mode private directory:

```bash
install -d -m 0700 .tmp/stream-proof
serverware-proof-client --stream \
  --proxy localhost:8080 \
  --url https://provider.example/v1/events \
  --ca .tmp/serverware-ca.pem \
  --collector-key .tmp/collector-ed25519.pem \
  --control-plane-response-key .tmp/control-plane-response-signing.pub.pem \
  --expected-principal-id agent:example \
  --proxy-header "X-Serverware-Agent: example-agent" \
  --header "X-Serverware-Agent: example-agent" \
  --max-stream-bytes 1048576 \
  --body-out .tmp/stream-proof/events.body \
  --out .tmp/stream-proof/events.proof.json
```

For a TEE deployment:

1. Boot Serverware inside AWS Nitro Enclaves or another selected TEE.
2. Produce a Nitro attestation document whose signed `user_data` binds the Serverware claims digest: image/runtime digest, policy bundle digest, data-plane binary digest, CA SPKI, rollback epoch, release channel, provenance digest, and public sealing key.
3. Release or unwrap the broker KEK and CA intermediate only after vendor quote verification, PCR allowlist checks, and KMS/HSM policy pass.
4. Seal refreshed OAuth tokens, wrapped DEKs, and approval grants to the TEE identity.
5. Log policy decisions externally with redacted URLs and route IDs, not raw credentials.

The proxy/policy boundary is already isolated enough for that migration: in development the Rust process owns route policy and decrypted credential material, and agents only receive normal upstream responses. Ordinary Docker, a `/dev/nsm` device mount, a valid quote helper response, KMS Recipient-shaped ciphertext, and passing release-readiness checks do not prove that the executing Rust path or its private keys lived inside an enclave. They remain pre-enclave evidence. Final hardware-backed completion requires moving the recipient, unwrap, CA, response-proof, and credential-use boundary into the measured enclave and supplying fresh independently signed EIF/PCR, CID/vsock, key-custody, and parent-host observation evidence bound to the current release and host.
