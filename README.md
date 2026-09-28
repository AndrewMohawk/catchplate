> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

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

## Production status

Checkpoint: **2026-09-28 — pre-production, source-only.**

**34/46 source checkpoints landed · 1 in progress · 11 todo.**

**Production acceptance: 0/6 verified.** Current source is unbuilt and unexecuted.

[![Project checkpoints, one segment per task: evidence handoff 10/10 landed; historical recovery 4/5; permissions and grants 10/10; finalization and sessions 7/8; workloads and native 3/6; providers and operations 0/7. Source status, not product readiness.](docs/images/project-progress.svg)](docs/production-status.md#next-source-milestones)

### Current workflow: session activation

**21/26 source steps landed · 1 active · 4 todo.** Step 22, public activation
dispatch, remains **partial**. The bar shows its named connections rather than
an estimated percentage.

The private-proof connection is source-landed in [c4270fd](https://github.com/example/private-deployment).
The `.191` post-intent grant/socket connection is **source-landed** in
[68d4235](https://github.com/example/private-deployment).
The `.192` issuer-policy, grant-production and transport foundation plus the
bounded public request contract are **source-landed** in
[18cf710](https://github.com/example/private-deployment).

The prior `.193` is **source-landed** in [0a46302](https://github.com/example/private-deployment): issuer cold delivery and a
one-shot service, plus public-only parent `/v12` [same-permission acquisition](docs/oidc-session-activation-release-grant-acquisition.md).
The `.194` exact-bootstrap delivery connection is **source-landed** in [849c74d](https://github.com/example/private-deployment):
explicit issuer launch `/v2` stages the original at an independently admitting
receiver before returning grants. A staged acknowledgement is not worker readiness.
Still open: resource creation/deployment, consume-input acquisition, per-request
proof provisioning, and public route/cookie, recovery and portal integration.
No service has been run.

[![Inside step 22: five facets are source-landed; RELEASE remains partial. Intent 30009db, proof c4270fd, direct grants 68d4235, issuer foundation 18cf710 and service/acquisition 0a46302 are source-landed. Current .194 exact-bootstrap staging is source-landed in 849c74d. Actual resource creation/deployment, consume/proof provisioning and public HTTP/cookie, recovery and portal remain open. Activation 21/26, project 34/46 and production 0/6 are unchanged. Source-only status is not runtime or session evidence.](docs/images/activation-dispatch-progress.svg)](docs/production-status.md#activation-dispatch-detail)

**Green = committed source · amber = in progress · blue/gray = open.**
Each connection has a [completion criterion and commit evidence](docs/production-status.md#activation-dispatch-detail).
Landed source does not mean tested, deployed, delivered, or a confirmed session.
Nested counts are not additive and are not effort estimates.

<details>
<summary>All 26 activation steps and the remaining public/portal work</summary>

[![Session activation: steps 01–21 source-landed; 22 public dispatch active; 23–26 recovery and portal todo. No runtime or production verification.](docs/images/activation-progress.svg)](docs/production-status.md#active-workflow-granular-source-steps)

| Step / stable ID | Deliverable | Status |
| --- | --- | --- |
| 21 · F08.5.1 | Fresh authorization for the exact user/session/credential target | [Landed · d3f8469](https://github.com/example/private-deployment) |
| 22 · F08.5.2 | Public activation with durable dispatch/outcome tracking and truthful responses | In progress |
| 23 · F08.5.3 | Separately authorized recovery; no automatic activation retry | Todo |
| 24 · F08.6.1 | Explicit portal activate/recover controls bound to the retained target | Todo |
| 25 · F08.6.2 | Fresh action-bound approval; discard prompts when actor or target changes | Todo |
| 26 · F08.6.3 | Confirm the session only after exact delivery and a fresh current-auth check | Todo |

Completed private foundations and their evidence: [protected release, 16/16](docs/production-status.md#token-release-implementation-detail)
and [release/handoff, 11/11](docs/production-status.md#exact-release-and-handoff-detail).
These do not close the public activation flow.

</details>

Beyond activation, unfinished checkpoints cover historical authority,
workload/native/enclave integration, provider operations and recovery, rollback
witnessing, and signed telemetry. The [46-checkpoint tracker](docs/production-status.md#next-source-milestones)
lists every remaining item and its evidence.

<details>
<summary>All 12 unfinished project checkpoints</summary>

| ID | Checkpoint | Source status |
| --- | --- | --- |
| H05 | Historical authority across configuration/key changes | Todo |
| F08 | Public session activation/recovery and portal/session flow | In progress |
| N04 | Workload identity provisioning and authenticated channels | Todo |
| N05 | Native enrollment, verified CA installation and proxy setup | Todo |
| N06 | Enclave TLS/proxy execution and credential custody | Todo |
| O01 | OAuth ownership across deployments and applications | Todo |
| O02 | Measured provider issuance and interrupted-exchange recovery | Todo |
| O03 | Public revocation and authenticated recovery | Todo |
| O04 | Protected provider and filesystem side effects | Todo |
| O05 | Interrupted policy-publication recovery | Todo |
| O06 | Independent RBAC rollback witness | Todo |
| O07 | Authenticated, signed and sequenced telemetry | Todo |

</details>

**Production gates remain separate.** Immutable dependencies, frozen verification
and independent release evidence are pending. Signing, Nitro/KMS and witness
services are not provisioned; live operator/hardware/provider acceptance awaits
deployment. Full verification follows source freeze.

[Full status and remaining-work criteria →](docs/production-status.md#remaining-work-breakdown)
· [Six production acceptance gates →](docs/production-status.md#remaining-production-gates)

<!-- Keep README, docs/production-status.md and progress SVGs synchronized. Preserve the 46 project / 26 activation / 16 token-release inventories. The dispatch SVG names seven facets and five RELEASE connections, not new milestones. Green requires an implementation commit; never add nested counts or equate source status with production acceptance. -->

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
