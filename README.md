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

Checkpoint: **2026-09-27 — pre-production, source-only.**

**34 of 46 tracked source checkpoints landed · 12 open, including F08 in progress.**
**Production acceptance: 0/6 verified.** Current source is unbuilt and unexecuted.

[![Project source checkpoints: evidence handoff 10/10 landed; historical recovery 4/5; permissions and grants 10/10; finalization and sessions 7/8; workloads and native 3/6; providers and operations 0/7. Every segment has a stable ID. Twelve checkpoints remain open, including F08 in progress. Source counts, not product readiness.](docs/images/project-progress.svg)](docs/production-status.md#next-source-milestones)

**Still to do across the project:** historical authority (1 checkpoint), session
activation (1), workload/native integration (3), and providers/operations (7).
The [remaining-work breakdown](docs/production-status.md#remaining-work-breakdown)
names each scope; the active session work is expanded below.

### Now building: protected token release

**10/16 implementation-detail units landed · 1 in progress · 5 other open.**
These are the pieces **inside activation step 20**, not 16 additional project
milestones. Each numbered segment below has a name and written status.

[![Protected token release, step 20: 01–10 landed in source. Row 11 private consume authorization and issuance is in progress, with authorization foundations committed in f6dd3cb; encrypted export, independent receiving replay and actual issuance/cold service remain within that row. Rows 12–16 are open. Ten landed, one in progress and five other open; not production verification.](docs/images/token-release-progress.svg)](docs/production-status.md#token-release-implementation-detail)

**New source:** [consume authorization foundations](https://github.com/example/private-deployment); row 11 remains **in progress**.
**Next within row 11:** first-exact encrypted export, independent receiving replay, and actual grant issuance/cold service.

**Done** means committed source, **in progress** includes unfinished/uncommitted
work, and **open** means its full criterion has not landed. The
[16-row checklist](docs/production-status.md#token-release-implementation-detail)
links each done item to its commit and states what closes every unfinished item.
Counts are not effort percentages or an ETA.

**After token release:** target-bound permission, public activation and recovery,
explicit portal actions, fresh portal permission, and truthful session confirmation
are still open. The full activation workflow remains **19/26 landed**.

<details>
<summary>All 46 project checkpoints and all 26 activation steps</summary>

[![Full source tracker: evidence handoff 10/10, historical recovery 4/5, permissions and grants 10/10, finalization and sessions 7/8, workloads and native 3/6, providers and operations 0/7. F08 is in progress: 3/6 direct children landed, with 19/26 finer steps shown below. Child counts do not add to the 46 parents. Source-only, not production verification.](docs/images/implementation-progress.svg)](docs/production-status.md#next-source-milestones)

**OIDC session activation — 19/26 landed; 1 in progress and 6 other open.**

[![OIDC activation: steps 01–19 landed, step 20 protected token release in progress, and 21–26 open. Step 20 has 2/5 diagnostic groups landed, expanded into 16 detail units: 10 landed, 1 in progress and 5 other open. Row 11 has committed authorization foundations, not completed issuance. Next within it: encrypted export, independent receiving replay and actual issuance/cold service. Nested counts do not add to the total. Source-only; no token release or production claim.](docs/images/activation-progress.svg)](docs/production-status.md#active-workflow-granular-source-steps)

Each segment maps to a
[named task, completion criterion and commit evidence](docs/production-status.md#active-workflow-granular-source-steps).
The 26 steps belong to F08; step 20's 16 detail units subdivide its existing five
diagnostic groups (**2/5 landed**). None is added to the parent counts.

</details>

**Production blockers — 0/6 gates verified:** integration is unfinished;
immutable dependencies, frozen verification and independent release evidence
are pending; signing, Nitro/KMS and witness services are not provisioned;
live operator/hardware/provider acceptance awaits deployment.

Full verification follows source freeze. No consumption execution or plaintext
release is claimed for the new protected path.

[Open the full tracker →](docs/production-status.md) for checkpoint evidence and
the [six separate production gates](docs/production-status.md#remaining-production-gates).

<!-- Update README counts/descriptions, production-status.md evidence/checklists, project-progress.svg, activation-progress.svg, implementation-progress.svg and token-release-progress.svg together. Activation has 26 fixed named F08 steps; token release has 16 detail units inside step 20, replacing c with twelve parts within the existing five diagnostic groups (5 - 1 + 12 = 16). Neither grouping parents nor diagnostic children are additive. Every segment needs a visible number, name, status and linked criterion/evidence. Uncommitted work cannot be landed. Keep source progress separate from exact-release evidence; reopen invalidated gates. -->

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
