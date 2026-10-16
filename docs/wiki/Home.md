> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Serverware operator guide

Serverware lets your scripts, services, agents and CI jobs use provider credentials without receiving those credentials. You save the provider account or key once, give each workload its own Serverware login, and decide what that workload may do.

This guide is maintained with the application source. Its versioned pages work
in this repository and a local checkout; a separate GitHub Wiki is optional. See
[Wiki publication status](https://github.com/AndrewMohawk/serverware/blob/main/docs/wiki-publishing.md)
only if you maintain the documentation.

[Open the Serverware console](https://serverware.example.com/) using the homelab sign-in. This is the persistent product instance, not a separate demo. Ordinary setup does not require starting a pilot, building the proxy or enrolling a security key. [Instance walkthrough](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-demo.md).

## The three things you manage

| Section | What belongs here | Example |
| --- | --- | --- |
| **Credentials** | Provider accounts and keys held by Serverware | A GitHub App installation, Google account or npm token |
| **Clients** | Your workloads, each with an expiring Serverware proxy token | Issue triage script, inbox worker or release workflow |
| **Permissions** | What one client may do using one credential | Read issues in one repository; publish one named package |

**Set up access** connects those three things in one guided flow. It is an action, not another kind of account. To save a key, choose its provider directly on **Credentials**, paste the key and save. The name and provider settings are prefilled; no client, proxy token or permission is created. A **GitHub App** is a provider credential; it is not a Serverware client.

## Choose your task

### Set up or administer Serverware

- [Get your first client working](Getting-started.md): save a credential, grant access, download the client configuration and check the result.
- [Add or connect a provider](Credentials-and-providers.md): GitHub App/PAT, Google, npm, X, Alchemy, custom keys and AWS/ECR.
- Follow a worked setup: [GitHub App](GitHub-App-setup.md), [Google/X OAuth](OAuth-provider-setup.md), or [custom Bearer/header API](Custom-API-credentials.md).
- [Choose and restrict permissions](Permissions-and-policies.md): provider presets, exact API paths, optional filtering and publishing hours.
- [Set the proxy address and trust its CA](Proxy-and-CA.md): client settings, destination review and provider application configuration.
- [Configure alerts or inspect activity](Notifications-and-audit.md): separate action alerts and audit delivery.
- [Rotate, reauthorize or remove access](Operations-and-maintenance.md): day-two operations without recreating everything.

### Use Serverware from your code or agent

- [Run an existing library or CI job](Clients-and-recipes.md): use the administrator-provided private client configuration with Node.js, Python, Go, curl, npm or GitHub Actions. You do not need the provider key.
- [Connect an MCP-capable agent](Clients-and-recipes.md#connect-an-mcp-capable-agent): select downloaded permissions for the local stdio server without exporting provider keys.
- [Fix a failed or uncertain operation](Troubleshooting.md): expired tokens, unavailable providers, TLS problems and saved-state recovery.
- [Check supported features and terminology](Capability-matrix-and-glossary.md).

## What a successful setup means

**Saved credential → saved permission → policy active → client request succeeded** are separate checkpoints. Saving a key is usually not a provider test. A loaded policy is not proof that a client can reach the proxy or that its provider account has permission. Finish with the intended client request and its recorded outcome in **Audit log**.

Available controls depend on the instance's configured providers, destinations and compatible proxy capabilities. A recipe in the repository is not a preconnected account. The ordinary instance trusts its administrator and uses local encrypted custody: someone with full host control can bypass its controls. Optional [host-trusted request review](Permissions-and-policies.md#optional-host-trusted-approval) is deployed in this same app and passed connected synthetic-provider checks; existing permissions remain unchanged. Individual-request review shows metadata/body hash, not body contents. The separate [ECR workflow](Clients-and-recipes.md#aws-ecr-publication) reviews an entire staged image before explicit publication. Real-provider use and future TEE-backed enforcement remain separate; host review does not establish hardware custody.

This guide covers operator and developer tasks. For implementation and acceptance status, use the [project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md), [current UI source](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/index.html), and [deployment runbook](https://github.com/AndrewMohawk/serverware/blob/main/docker/serverware-operator-demo/README.md). Older engineering documents may retain historical UI names such as “Applications” or “Accounts and keys”; this guide calls them **Clients** and **Credentials**.
