# Serverware

Keep upstream credentials out of your applications. Control how they are used.

Serverware is a credential-control HTTP(S) proxy for applications, backend
services, scheduled jobs, CI pipelines, and AI agents. Instead of distributing
provider API keys and OAuth tokens to every workload, you store them centrally
and give each workload a scoped Serverware identity. Serverware checks policy,
injects the authorized upstream credential, and validates the response.

This is for ordinary application authentication as well as agentic workflows.
The application asks to use an API; it does not need possession of that API's
long-lived credential.

For example, an application or CI job can publish an updated version of
`@acme/widgets` with `npm publish`, while policy permits that package's releases
only **09:00–17:00 UTC daily**. The workload authenticates to Serverware, not with
the upstream npm token. The default workflow credential shown in both examples
is `username:password`. This is an example value, not a built-in authentication
default; real deployments use an explicitly provisioned, scoped identity. Serverware
consumes that credential at ingress and uses the protected provider credential
on the upstream request only after authorization succeeds. The credential swap
does not forward the workload credential to the provider.
These diagrams illustrate intended production flows, not deployed integrations.

### Example: time-limited npm publishing

![An application sends npm publish with the default example workflow credential username:password. Serverware checks the package and time window, removes the workflow credential and attaches its protected npm token before forwarding to npm. A denied request never reaches npm; the validated result returns without the npm token.](docs/images/npm-time-window-flow.svg)

<details>
<summary>Equivalent Mermaid sequence (editable)</summary>

```mermaid
sequenceDiagram
    participant APP as Application / CI
    box Serverware trust boundary
        participant SW as Serverware proxy
        participant STORE as Protected credential store
    end
    participant NPM as npm registry
    Note over APP: Default example workflow credential: username:password
    APP->>SW: Publish @acme/widgets via npm + username:password
    SW->>SW: Authenticate and consume workload credential; never forward it
    SW->>SW: Check package and 09:00–17:00 UTC
    alt Wrong package or outside allowed hours
        SW-->>APP: Deny; no request to npm
    else Authorized
        SW->>STORE: Select authorized npm token
        STORE-->>SW: npm token (inside Serverware only)
        SW->>NPM: Publish request with protected npm token
        NPM-->>SW: Registry response
        SW->>SW: Validate response
        SW-->>APP: Publish result; no npm token
    end
```

</details>

The time window authorizes requests; it does not schedule or queue releases.
`npm publish` releases a new package version; `npm update` updates installed dependencies.

### Example: YubiKey-approved AWS TEE image update

A build pipeline publishes an updated TEE container image to
[Amazon ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html),
but the pipeline **attempts the action first**. Serverware holds that action
and only then asks an authorized developer to approve it using a
**YubiKey with FIDO2/WebAuthn**. Once the fresh, one-use approval is verified,
Serverware replaces the workload credential with its protected AWS/ECR
credential and resumes that exact publication. Rejection, timeout or a mismatch
blocks it. Approval is bound to the AWS account, region, repository and image
digest—not blanket permission to push arbitrary images. The pipeline never
receives the upstream AWS/ECR credential.

![A pipeline attempts an ECR image update using the default example workflow credential username:password. Serverware holds the action and then challenges the developer, who approves with a YubiKey. Only after verifying fresh approval for that exact action does Serverware replace the workflow credential with its protected AWS/ECR credential and resume publication. Denial or timeout blocks the update.](docs/images/ecr-yubikey-flow.svg)

<details>
<summary>Equivalent Mermaid sequence (editable)</summary>

```mermaid
sequenceDiagram
    participant CI as Build pipeline
    box Serverware trust boundary
        participant SW as Serverware proxy
        participant STORE as Protected credential store
    end
    participant DEV as Developer / approval UI
    participant KEY as YubiKey
    participant ECR as Amazon ECR
    Note over CI: Default example workflow credential: username:password
    CI->>SW: Attempt TEE image publication + username:password
    SW->>SW: Authenticate and consume workload credential; never forward it
    SW->>SW: Check policy; bind exact publication intent
    alt Policy denies this action
        SW-->>CI: Deny; no publication to ECR
    else Policy requires human approval
        Note over CI,SW: Action is held; no upstream credential injected yet
        SW-->>DEV: Request approval now for account, region, repository, image digest
        DEV->>KEY: Review action; authenticate with YubiKey
        KEY-->>DEV: WebAuthn assertion
        DEV->>SW: Return request-bound approval
        alt Fresh matching one-use approval verified
            SW->>SW: Consume one-use approval for this exact action
            SW->>STORE: Select scoped AWS/ECR credential
            STORE-->>SW: Upstream credential (inside Serverware only)
            SW->>ECR: Resume this image publication with upstream authentication
            ECR-->>SW: Publication result
            SW->>SW: Validate response
            SW-->>CI: Result; no AWS/ECR credential
        else Rejected, timed out, stale or mismatched
            SW-->>CI: Block; no image publication
        end
    end
```

</details>

ECR publication is not enclave deployment or attestation: Nitro separately
[builds an enclave image file (EIF) from a container image](https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-build-enclave.html).
The YubiKey approves the publication; it does not replace enclave measurements,
KMS policy or deployment authorization. This ECR-specific approval integration
still needs implementation and end-to-end verification.

## Production status

Checkpoint: **2026-10-01 — pre-production, pilot assembly.**

**36/46 source checkpoints landed · 10 active · 0 todo.**

**Production acceptance: 0/6 verified.** Both service images and the operator tool build from `04cf155a`; the corrected sidecar export builds from `facdb895`. Both Python runtime artifacts build from `7193b2a1`. All four exported prerequisites pass file staging. These are engineering builds using the unpublished dependency candidate, not approved release packages or a deployed pilot. [Build results](docs/native-pilot-build.md#current-engineering-assembly).

[![Project checkpoints, one segment per task: 36 of 46 source-landed; 10 active and 0 todo. Evidence handoff 10/10; historical recovery 4/5; permissions and grants 10/10; finalization and sessions 8/8; workloads and native 3/6; providers and operations 1/7. H05, N04, N05, N06 and O01 through O06 are in progress. Production acceptance remains 0/6. Engineering assembly is not an accepted pilot or production deployment.](docs/images/project-progress.svg)](docs/production-status.md#next-source-milestones)

The [startup coordinator](docs/native-pilot-coordinator.md), separately approved
input installation and runtime packaging are connected in source. Signing keys
stay outside the conductor. The [independent approval supervisor](docs/native-pilot-supervisor.md)
has **164 of 164 current jobs handled** and **113 signing selectors**. This
includes service histories, delivery/generation grants, endpoint authorizations,
launch bundles and public material. Explicit policy/v15 connects eight
[request-bound approval intake jobs](docs/native-pilot-current-head-intake.md),
which await independent decisions instead of generating their own approval.
Focused checks pass; live pause/resume remains unverified. The earlier
[fresh-helper startup path](docs/native-pilot-helper-initial.md) passes focused
checks and native compilation, but live initialization remains unverified.

Policy/v18 connects the [final release, publication and shutdown decisions](docs/native-pilot-final-continuations.md).
All current jobs are now connected in source; this batch passed all 25 focused
controls ([evidence and limits](docs/native-pilot-final-continuations.md#focused-verification)). The new
[supervisor executable and package](docs/native-pilot-supervisor-executable.md)
passed 29 focused controls and an engineering artifact build. The
[current dispatch work](docs/native-pilot-dispatch-fence.md) fixes v11 effect
selection and interrupted-request ownership; its verification is pending.
[Real terminal cleanup](docs/native-pilot-operation-ownership.md) and connected
runtime verification are still needed. These counts are not a percentage of
product readiness or permission to deploy.
Protected deployment is not provisioned. This is not
yet an interactive quickstart or running pilot.
The [persistent workload sidecar](docs/native-workload-sidecar.md) supports ordinary
HTTPS libraries without direct proxy mTLS; provider credentials stay out of the
application. Remaining pilot work includes native guest assembly with
approved inputs, service provisioning and the connected application allow/deny/cleanup run.
Broad testing follows that assembly.

The bar shows **committed source, not tested readiness or remaining effort**.
Green means source-landed; amber means partial implementation. No current pilot
release has passed end-to-end verification.

<details>
<summary>All 10 unfinished project checkpoints</summary>

| ID | Remaining checkpoint | Source status |
| --- | --- | --- |
| H05 | Historical authority across source, configuration and key changes | In progress |
| N04 | Workload identity provisioning and authenticated service channels | In progress |
| N05 | Native enrollment, verified CA installation and proxy setup | In progress |
| N06 | Enclave TLS/proxy execution and credential custody | In progress |
| O01 | OAuth ownership across deployments and applications | In progress |
| O02 | Measured provider issuance and interrupted-exchange recovery | In progress |
| O03 | Public revocation and authenticated recovery | In progress |
| O04 | Protected provider and filesystem side effects | In progress |
| O05 | Interrupted policy-publication recovery | In progress |
| O06 | Independent RBAC rollback witness | In progress |

These are open parent checkpoints; each can contain landed implementation.
The [detailed ledger](docs/production-status.md#remaining-work-breakdown) records
exact remaining work, completion criteria and commit evidence.

</details>

[Full 46-checkpoint ledger](docs/production-status.md#next-source-milestones)
· [Completed session-activation source, 26/26](docs/production-status.md#active-workflow-granular-source-steps)
· [Six independent production gates](docs/production-status.md#remaining-production-gates)

<!-- Keep current counts and the project SVG synchronized. Detailed subworkflow
history lives in docs/production-status.md. Source landing is not runtime proof. -->

## Why Serverware?

A typical secret manager delivers a secret to an application. Serverware moves
the credential's use into the proxy instead: the calling service receives the
permitted API response, not a credential lease. This reduces the places where
upstream credentials need to be stored and the number of workloads that need
access to them.

For example:

- A backend service can call an approved API without keeping the provider key in
  its environment, container image, or application configuration.
- A user can connect a Google or X account through the operator portal; workers
  use the permitted provider operations without receiving the refresh token.
- A CI job can be restricted to a particular package-publishing operation, with
  human approval required before the credential is used.
- An automation or AI agent can receive narrowly scoped access to the same APIs
  without being given the underlying account credentials.

The workload still needs to authenticate to Serverware. This is reduced
credential distribution, not a claim that all clients become secretless.

## Architecture

```mermaid
flowchart LR
    W["Applications, services, jobs, and agents"]
    O["Operators"]
    U["Upstream APIs"]

    subgraph S["Serverware logical components"]
        C["Control plane: portal and API"]
        P["Policy compiler"]
        B["Secret broker and encrypted storage"]
        J["JIT approval service"]
        D["Rust data plane: HTTP(S) proxy"]
        C --> P
        C --> B
        C --> J
        P -->|Signed policy| D
        D <-->|Scoped credential leases| B
        D <-->|Approval when required| J
    end

    O --> C
    W -->|Authenticated proxy requests| D
    D -->|Authorized requests with injected credentials| U
```

These are five logical roles, not a claim that five independently deployed
services are already available. The Python/FastAPI control plane manages
configuration and operator workflows. The Rust data plane is the production
implementation track for credential-bearing traffic; the legacy Python
mitmproxy path is development-only and rejects credential-bearing routes.

Clients use proxy-capable HTTP libraries and normal upstream URLs, configured
with Serverware proxy authentication and its verified CA for HTTPS interception.
SDK-specific configuration may still be needed. Workload egress controls must
prevent bypassing the proxy where enforcement is required.

For libraries without HTTPS-proxy mTLS support, the [workload sidecar](docs/native-workload-sidecar.md)
accepts authenticated CONNECT requests only on loopback inside an explicitly
selected workload network namespace. It owns the native mTLS connection; the
application retains its scoped local token and verified interception CA, not
the upstream provider credential. Namespace provisioning and egress restrictions
are separate deployment requirements.

## Three separate authentication relationships

| Relationship | Purpose | Credential boundary |
| --- | --- | --- |
| Workload → Serverware | Identify the calling service, job, or agent and its allowed routes. | A scoped Serverware identity, not the provider's API key. |
| Operator → control plane | Manage credentials, policies, approvals, and audit. | Operator OIDC, role-based access, and WebAuthn controls. |
| Serverware → upstream API | Perform the approved operation as the connected provider account. | Centrally stored API credentials or OAuth tokens, used by the trusted credential path. |

Operator OIDC login and provider OAuth account connection are different flows.
Serverware is not a general-purpose identity provider or a replacement for every
application's end-user login system.

## Policies govern credential use

A signed policy binds a principal, route, credential reference, and API adapter.
An unrecognized or unauthorized request is denied by default. Policies can
constrain:

- **Where:** destination host and port, HTTP method, and path.
- **What:** recognized API operations, allowed request fields, and value bounds.
- **When and how much:** time windows, request counts, and shared budgets.
- **Who approves:** optional short-lived, request-bound human approval.
- **What comes back:** response shape, permitted fields, date bounds, and
  request-to-response bindings supported by the selected adapter.

For example, a credential can be assigned to a read-only integration with a
bounded date window, or to a publishing workflow that requires approval. The
upstream account's broad permissions do not have to become the caller's policy.
Enforcement depends on a supported, explicitly configured operation; merely
rewriting a request does not prove the response satisfies the policy.

The source includes generic REST, Gmail, X, and npm adapters, plus static
credential injection and Google/X OAuth onboarding. See the
[constraint reference and examples](docs/credential-constraints.md) and
[example policy bundle](policies/demo.policy.json) for exact supported behavior.
Policies are typed, bounded data—not arbitrary executable policy code.

## Request lifecycle

```mermaid
flowchart TD
    R["Client request"] --> A["Authenticate principal and match route"]
    A --> P{"Request and policy allowed?"}
    P -->|No| X["Deny locally"]
    P -->|Yes| G["Obtain approval and reserve budget when required"]
    G --> L["Authorize scoped lease and prepare credential injection"]
    L --> Q["Durably audit release and recheck policy and lease"]
    Q --> U["Dispatch upstream; verify TLS for HTTPS"]
    U --> V{"Response satisfies configured validation?"}
    V -->|No| E["Block response or terminate stream"]
    V -->|Yes| F["Project permitted fields and return response"]
```

A missing approval, exhausted budget, unavailable required authority, or stale
policy/lease stops the request before upstream dispatch. Audit records bind
decisions to the relevant principal, policy, and credential version without
logging raw secrets. Response validation is adapter-specific: a blocked response
does not undo an upstream action, and already-released stream bytes cannot be
recalled. Streaming therefore has separate restrictions.

## Security and deployment boundaries

Credentials use envelope encryption at rest and short-lived, recipient-bound
leases for the data plane. Plaintext still exists in the trusted credential-use
path and is sent to the intended upstream provider. Ordinary Docker does not
protect that memory from the host administrator.

The production target places TLS termination and the complete credential-handling
proxy inside an attested enclave, with independently operated release signing,
Nitro/KMS verification, and a rollback-resistant witness. This production chain
still needs implementation, independent provisioning, and verification; the
required current dependency snapshot is also not ready. Local signatures,
development quotes, and historical test results do not establish that guarantee.

One deployment currently represents one administrative trust domain, not an
isolated multi-tenant vault. Support is HTTP(S)- and adapter-specific: arbitrary
database/SSH authentication, client TLS credentials, and request-signing schemes
are not automatically supported. See the [security review](docs/security-review.md)
for the threat model and production acceptance gates.

## Development and documentation

There is no working production quickstart for the current source. Read the
[development reference](docs/development-reference.md) for the intended local
Compose workflow, configuration, and diagnostic recipes. It uses development
credentials and is not a production deployment. Before running builds or tests,
follow the [source-freeze and verification workflow](goal.md#resource-conscious-engineering-workflow).

| Read next | Covers |
| --- | --- |
| [Operator and OAuth guide](docs/portal-oauth-agent-guide.md) | Portal login, provider connection, credential assignment, approvals, and client enrollment. |
| [Credential constraints](docs/credential-constraints.md) | Policy language, supported authentication modes, adapters, and response restrictions. |
| [Rust data plane](data-plane/README.md) | Proxy implementation and transport contracts. |
| [Project requirements](goal.md) | Architecture, implementation roadmap, and acceptance criteria. |
| [Successor implementation status](docs/webauthn-successor-transitions.md) | Current authentication integration and execution gaps; links to the historical startup diagnosis. |
| [Release stages](docs/release-stages.md) | Separate build, publish, sign, deploy, and independent verification responsibilities. |
| [Dependency snapshot](docs/production-dependency-snapshot.md) | Immutable offline dependency preparation and its remaining release boundary. |
