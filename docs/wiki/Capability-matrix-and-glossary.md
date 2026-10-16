# Capability matrix and glossary

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Credentials and providers](https://github.com/AndrewMohawk/serverware/wiki/Credentials-and-providers) · [Clients and recipes](https://github.com/AndrewMohawk/serverware/wiki/Clients-and-recipes)

Serverware separates **what the software implements**, **what this instance is configured to offer**, and **what has succeeded against a real provider**. None is a substitute for the others. This page summarizes repository contracts and recorded verification; it does not report new live probes.

## Read the status correctly

- **Implemented:** a supported operation exists in the application and proxy contract.
- **Available here:** the instance advertises the matching capability, its provider is configured, and the operator has approved the destination. Your client still needs a permission.
- **Active permission:** the proxy confirms the matching saved policy is loaded. This does not verify provider credentials or network reachability.
- **Isolated verification:** real components may have run against a synthetic provider. This is not real-provider acceptance.
- **Real-provider verification:** the intended client job succeeded against the actual configured provider, with a matching recorded outcome.

Use the [project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md) and [deployment record](https://github.com/AndrewMohawk/serverware/blob/main/docker/serverware-operator-demo/README.md) for current release evidence. Real-provider jobs remain unverified; examples are not preconnected accounts.

## Capabilities

| Capability | Implemented scope | Configuration and verification boundary |
| --- | --- | --- |
| Ordinary client setup | Save a credential, create a client, grant access, configure the proxy, inspect audit and revoke access | The isolated full journey is recorded. No pilot or page-startup build is required; a real provider job remains a separate check. |
| Optional managed workload renewal | Explicit Ed25519 public-key enrollment for 1–90 days; 1–24 hour tokens clipped to that grant; old-token overlap at most five minutes and never past original expiry | Deployed at `b5cc5f6f` / normal Rust `116dc526`; all retained live clients remain manual and unenrolled. Isolated stock Requests 2.31.0/normal-proxy checks, the [helper's](https://github.com/AndrewMohawk/serverware/blob/main/examples/managed-client/README.md) actual default HTTPS transport with locked Requests 2.34.2 and pending-operation recovery, and deployed GET-only UI checks passed. An enrolled deployed workload and real-provider job remain open in the [project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md#default-managed-helper-https--isolated-connected-acceptance). This is not native/hardware-backed authority. |
| HTTPS proxy and CA | Authenticated proxy use, interception CA download, verified outer/inner TLS | Public synthetic-route allow/revoke verification is recorded. Trust the operator-supplied CA; this does not establish every SDK or provider job. |
| Custom Bearer/header credentials | Encrypted storage, automatic insertion or exact dummy replacement, supported bounded JSON permissions | Not arbitrary transparent HTTP forwarding: exact destination, path, method, content and response rules still apply. |
| Common app presets | OpenAI, Anthropic, Gemini, OpenRouter, Slack, Discord, Notion, Stripe, Resend, GitLab, Cloudflare and Sentry; explicit narrow operations and scopes | Existing exact-route JSON enforcement, not blanket service access. Static keys require operator-approved destinations; no provider consent/verification occurs on save. See the [operation matrix](https://github.com/AndrewMohawk/serverware/blob/main/docs/common-apps.md). No universal SDK, AI streaming, GraphQL read-only, live-provider or external-delivery claim. |
| GitHub PAT and GitHub App | Exact-repository issue/comment reads or read/create; server-side App installation-token renewal; Node/Python/Go recipes | An App must be installed with sufficient Issues rights. App verification contacts GitHub; PAT saving does not. Real GitHub use remains unverified. |
| Google / Gmail | Managed account consent/refresh; read-only Gmail list and metadata jobs in Node/Python/Go | All three current SDK jobs passed isolated proxy verification, including refresh. Google remains unconfigured in the recorded instance; real consent and a live job are still required. |
| npm metadata, installation and publication | Separate metadata, exact dependency-closure install/CI, and named-package/tag publication grants; optional publishing hours | Installation includes permitted dependency metadata, registry tarballs and default npm audit, not metadata alone. Isolated checks are recorded; real registry use/publication requires separate credentials and authorization. |
| Alchemy chain status | Mainnet or Sepolia: `eth_chainId` and `eth_blockNumber`; Node/Python/Go examples | Node uses Viem with an explicit Undici HTTPS proxy transport. The current three-language recipes passed [12-phase isolated proxy/TLS verification](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-alchemy-verification.md#current-sdk-through-proxy-acceptance), including credential replacement, audit, denial and revocation controls. No wallet, transaction, arbitrary RPC, batch or WebSocket access. Real entitlement/key use remains unverified. |
| X app-only username lookup | One exact lowercase username; Node/Python/Go examples | Uses an app-only bearer credential, not an account-posting grant. Isolated verification is recorded; real X access remains unverified. |
| X account posting and shared limit | Managed user-context posting; optional shared UTC daily posting-attempt limit; Node/Python/Go examples | Implementation and quota support are retained in the deployment, but X remains unconfigured and its capability is unavailable. Real account consent and posting are still required. |
| AWS credentials | Encrypted credential storage | Storage only for this operator workflow: no working AWS/ECR publication path. Signing/planning components are not end-to-end publication. |
| Audit logging and selected delivery | Stored request/outcome records, search, local chain verification and selected notification delivery | Use the actual outcome, not just a saved credential or healthy process. External audit delivery needs its own configured destination and verification; it is not a complete verified archive. |
| Slack and webhook notifications | Separate action-required and audit destinations, with independent Slack/webhook slots | Delivery configuration is separate from authority. Real receiver delivery remains to be verified; a receiver acknowledgement is not human approval. |
| Ordinary host-trusted approve/deny | Optional per-permission `host_review_v1`; exact-request review, expiring one-use approval and explicit client retry | Deployed at `ea5a5deb` / normal Rust `48953fea…`; connected synthetic approval/replay/denial checks passed. Existing permissions remain unchanged. Review shows metadata/body hash, not body contents. Full host control can bypass it; no real-provider, TEE or per-action YubiKey/WebAuthn proof. Initially incompatible with shared X daily quota. |
| Future hardware-backed approval enforcement | Supporting native authority/review components exist | Separate, unfinished TEE/hardware assurance target. Ordinary host-review decisions do not satisfy it. |

Provider contracts: [GitHub](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-github-client-compatibility.md), [Gmail](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-gmail-job-verification.md), [npm installation](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-npm-install.md), [Alchemy](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-alchemy-verification.md), [X posting](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-x-posting.md), [AWS](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-aws-client-compatibility.md), [notifications](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md).

## Restrictions worth noticing

The X daily limit is offered only when the instance advertises the exact compatible quota capability. It counts **attempts**, shared across clients/connections for the verified account, not confirmed successful posts. A committed attempt with an uncertain outcome stays charged; refresh, reconnect or a client restart is not a reset. This ordinary trusted-host limit is not native rollback-proof authority. [Quota contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-x-posting-quotas.md).

An npm metadata grant does not allow installation; an installation grant does not allow publication. List the complete permitted dependency closure explicitly. Publication hours restrict when requests may run; Serverware does not schedule the job. [Permissions](https://github.com/AndrewMohawk/serverware/wiki/Permissions-and-policies).

An uncertain write may already have happened. Do not automatically retry X posting, npm publication or another write after a lost response; inspect audit and provider state first. A local confirmation flag is not durable deduplication.

The Alchemy Node recipe now uses Viem instead of the archived Alchemy SDK. The npm registry example still has unresolved bundled dependency advisories. Use each recipe's documented runtime and locked dependencies; a pin or passed synthetic test is not a vulnerability-free or universally compatible SDK claim. [Dependency status](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md).

## Glossary

| Term | Meaning in Serverware |
| --- | --- |
| Credential | A provider account or key held by Serverware. Saving it alone grants no client access. |
| Client | Your script, service, agent or CI job's Serverware identity. Older API/source names may call it an application. |
| Application ID / `SERVERWARE_APP_ID` | The Serverware client's identifier. It is not a GitHub App ID, provider OAuth client ID or provider account ID. |
| Client token / proxy token | The private, expiring Serverware login used by a client, not a provider key. Manual creation/rotation display it once; the managed helper keeps its generated tokens locally. |
| Managed workload renewal | Optional signed token renewal under an explicitly enrolled public key and finite grant. The private key stays on one workload; renewal never extends the grant or adds permissions. Manual rotation is the default for unenrolled clients. |
| Provider application | An application registered with Google, X or another provider to configure provider-side consent/authentication. It is distinct from a Serverware client. |
| GitHub App / provider App ID | GitHub's installed integration and its provider-assigned identifier. Its server-held private key and installation form a GitHub credential; its ID does not identify the workload using the proxy. |
| Permission | One client's allowed use of one credential for an explicitly scoped operation. Provider-side rights and Serverware's permission must both allow it. |
| Policy | The signed proxy-enforcement configuration compiled from saved permissions and related state. Saving a change and loading it are separate checkpoints. |
| Activation | Confirmation that the proxy has loaded the matching saved policy. “Activation pending” is not permission enforcement or provider readiness. |
| Approved destination / upstream | A provider HTTPS origin the operator permits the proxy to contact. Approval does not grant every client access. |
| Dummy value | A public placeholder sent by an SDK instead of a real provider secret. Exact replacement requires the complete expected header value; it must never contain a real client token or provider key. |
| Interception CA | The public certificate authority certificate the client trusts for the proxy's intercepted provider TLS connection. Download and verify it through the operator's authenticated setup. |
| Outer proxy CA | Trust for the HTTPS connection to the proxy itself. Usually system/public roots; some deployments need a separate private CA. Follow the recipe's trust rules rather than swapping the two CA roles. |
| Provider-token refresh | Server-side renewal of a short-lived provider access token where supported. It does not extend the Serverware client's token lifetime. |
| Reauthorization | Fresh provider consent for an existing account when required. It is not client-token rotation, and need not mean deleting/recreating the account. |
| Rotation / key replacement | Explicitly replace a Serverware client token or a stored provider key, depending on the selected action. These affect different credentials; neither substitutes for required provider consent. |
| Revocation | Remove a client's or permission's authority. Confirm the updated policy is enforced; already-dispatched requests cannot be recalled. |
| Action-required alert | A notification that an operator needs to act. It neither performs that action nor grants approval authority. |
| Host-trusted review | Administrator review of an exact request in the ordinary instance. Expiry and one-use enforcement trust that host; this is not TEE custody or a per-action hardware assertion. |
| Audit notification | Delivery of recorded activity/outcomes to a separately configured destination; independent of action-required alerts. |

## Where to go next

- [Get started](https://github.com/AndrewMohawk/serverware/wiki/Getting-started) to connect a saved credential to a client.
- [Proxy and CA](https://github.com/AndrewMohawk/serverware/wiki/Proxy-and-CA) for transport and provider application setup.
- [Operations and maintenance](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance) for rotation, reauthorization and removal.
- [Troubleshooting](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting) for unavailable capabilities, pending activation and uncertain outcomes.
