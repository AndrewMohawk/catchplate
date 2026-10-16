> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Serverware

Let applications use your credentials without giving them your credentials.

Serverware is an HTTP(S) proxy for scripts, services, CI jobs and AI agents.
Store a provider key or connect an account once, then give each application its
own scoped Serverware login. The proxy checks its permissions, supplies the
provider credential and records the outcome. Supported permissions can also
restrict response data or require human approval.

## Start here

- **Administrator:** [open the running console](https://serverware.example.com/)
  with the homelab sign-in, then follow [your first client](docs/wiki/Getting-started.md).
- **Developer:** already have a private client configuration and CA? Follow the
  [developer quickstart](docs/developer-quickstart.md) to run a matching example.
- **AI agent:** use the [local MCP server](examples/mcp/README.md) with selected
  client permissions. Generate its launch configuration locally; no provider
  keys go into your MCP settings.
- **Reference:** the [operator guide](docs/wiki/Home.md) covers providers,
  policies, client libraries, notifications and maintenance.

The running instance is the product instance, not a separate demo. Opening it
does not build the proxy, start a pilot or require a security-key ceremony.
The versioned guides above work without a published GitHub Wiki.

## Three things, one setup flow

| Thing | What it is | Example |
| --- | --- | --- |
| Credential | A provider account or key kept in Serverware | GitHub App installation or npm token |
| Client | Your application, with its own expiring Serverware token | Issue triage worker or release job |
| Permission | What that client may do with a credential | Read issues in one repository |

To save a key: **Credentials → choose provider → paste key → Save credential**.
The provider settings and suggested name are filled in. Saving it does not
create a client or grant access. OAuth accounts and GitHub Apps have their own
provider-specific setup.

To use it: choose **Use with a client**, select or create the client, and choose
a scoped permission. Download its private client configuration and the public
CA from **Proxy setup**, then run the matching example. A new client token is
shown once: keep that page open until you have saved the configuration safely.
Never give the application the provider key.

**Saved**, **policy active** and **request succeeded** are different checkpoints.
Finish setup with the intended client request and its outcome in **Audit log**.
No permission is granted just by opening setup or downloading instructions.

## Connect an application

Use the provider's existing library with the supported proxy recipe. Choose the
example that matches the saved permission; these are scoped integrations, not
unrestricted access to every endpoint a provider offers.

| Need | Start with |
| --- | --- |
| GitHub issues/comments, using a PAT or GitHub App | [Node.js](examples/github-issues-node/README.md), [Python](examples/github-issues-python/README.md), [Go](examples/github-issues-go/README.md) |
| Gmail, npm, X or Alchemy | [Client recipes and exact limits](docs/wiki/Clients-and-recipes.md) |
| OpenAI, Anthropic, Gemini, OpenRouter and common service APIs | [Common-app clients](examples/common-apps/README.md) and [supported operations](docs/common-apps.md) |
| A custom Bearer-token or API-key JSON API | [Custom API setup](docs/wiki/Custom-API-credentials.md) |
| A GitHub Actions job | [CI setup](docs/wiki/Clients-and-recipes.md#github-actions) |
| An MCP-capable agent | [MCP setup and local configuration export](examples/mcp/README.md) |
| A reviewed AWS ECR image publication | [ECR workflow](docs/operator-ecr-publication.md) |

Dependency installation happens once in the example project, before supplying
its private configuration. The configuration contains a Serverware client
token, not the upstream credential: keep it out of Git, prompts and logs.
TLS verification stays enabled; use the downloaded CA in the intended client.
Posting, publishing and other actions require explicit inputs and confirmation.

## Administer the instance

- [Credentials and providers](docs/wiki/Credentials-and-providers.md): save
  keys, connect OAuth accounts and configure GitHub Apps.
- [Permissions and policies](docs/wiki/Permissions-and-policies.md): select
  supported operations and scope them to the intended resources.
- [Proxy and CA](docs/wiki/Proxy-and-CA.md): find the proxy endpoint, download
  the CA, and manage approved destinations and provider application settings.
- [Notifications and audit](docs/wiki/Notifications-and-audit.md): configure
  action-required alerts separately from audit delivery, using Slack or HTTPS
  webhooks. Notifications do not approve or execute requests.
- [Operations](docs/wiki/Operations-and-maintenance.md) and
  [troubleshooting](docs/wiki/Troubleshooting.md): rotate client access,
  disconnect accounts and recover uncertain saves without accidental retries.

The console and forward proxy have different addresses. The running proxy is
`https://serverware-proxy.example.com/`; use the configuration downloaded
from the console, not the console address, in your client.

## Current scope and trust

This release trusts the server administrator and uses local encrypted custody.
Someone with full control of the host can bypass its controls. It is one
administrative trust domain, not an isolated multi-tenant vault. TEE-backed
enforcement and independent hardware custody are future work, not prerequisites
for using the current instance.

Optional human approval uses the authenticated console. For ordinary requests,
the original attempt stops; approval allows one explicit identical retry.
The ECR workflow separately reviews a staged image before explicit publication.
Neither is a per-action YubiKey ceremony or protection against host root.

Provider presets are setup templates, not preconnected accounts. Supported
operations depend on the deployment's capabilities, approved destinations and
your provider-side permissions. Synthetic acceptance and a healthy proxy do
not establish access to your real account. See the
[capability guide](docs/wiki/Capability-matrix-and-glossary.md) and
[acceptance tracker](docs/project-completion.md) for verified boundaries and
remaining real-provider work.

## Self-hosting and contributing

The running instance is available now. A new
[standalone installer](docker/serverware-standalone/README.md) packages
the app, proxy and authenticated TLS edge without homelab dependencies.
**Isolated installation and lifecycle verified:** both build paths and fresh
starts passed, with separate browser, persisted-state restart and TLS replacement
checks. Public deployment and real-provider use remain separate. See the [verification record](docs/standalone-installation-verification.md)
and [self-hosting/activation guide](docs/self-hosting.md).
The [retained deployment](docker/serverware-operator-demo/README.md)
records the existing instance and is **not** a new-install command.
Do not apply its state paths, identity or credentials to another installation.
The older [development reference](docs/development-reference.md) covers a
different engineering stack, not the current instance's onboarding path.

For implementation details, see the [Rust proxy](data-plane/README.md),
[credential constraints](docs/credential-constraints.md) and
[current usability review](docs/usability-review.md). Historical architecture,
pilot requirements and deployment observations are preserved in
[project history](PROJECT_HISTORY.md); they are not the ordinary setup flow.
