> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Serverware operator guide

Serverware lets your scripts, services, agents and CI jobs use provider credentials without receiving those credentials. You save the provider account or key once, give each workload its own Serverware login, and decide what that workload may do.

[Open the Serverware console](https://serverware.example.com/) using the homelab sign-in. This is the persistent product instance, not a separate demo. Ordinary setup does not require starting a pilot, building the proxy or enrolling a security key. [Instance walkthrough](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-demo.md).

## The three things you manage

| Section | What belongs here | Example |
| --- | --- | --- |
| **Credentials** | Provider accounts and keys held by Serverware | A GitHub App installation, Google account or npm token |
| **Clients** | Your workloads, each with an expiring Serverware proxy token | Issue triage script, inbox worker or release workflow |
| **Permissions** | What one client may do using one credential | Read issues in one repository; publish one named package |

**Set up access** connects those three things in one guided flow. It is an action, not another kind of account. **Credentials → Add credential** uses the same editor but stops after saving: it creates no client, proxy token or permission. A **GitHub App** is a provider credential; it is not a Serverware client.

## Choose your task

- [Get your first client working](https://github.com/AndrewMohawk/serverware/wiki/Getting-started): save a credential, grant access, configure the client and check the result.
- [Add or connect a provider](https://github.com/AndrewMohawk/serverware/wiki/Credentials-and-providers): GitHub App/PAT, Google, npm, X, Alchemy, custom keys and AWS storage.
- Follow a worked setup: [GitHub App](https://github.com/AndrewMohawk/serverware/wiki/GitHub-App-setup), [Google/X OAuth](https://github.com/AndrewMohawk/serverware/wiki/OAuth-provider-setup), or [custom Bearer/header API](https://github.com/AndrewMohawk/serverware/wiki/Custom-API-credentials).
- [Run an existing library or CI job](https://github.com/AndrewMohawk/serverware/wiki/Clients-and-recipes): Node.js, Python, Go, curl, npm and GitHub Actions examples.
- [Choose and restrict permissions](https://github.com/AndrewMohawk/serverware/wiki/Permissions-and-policies): provider presets, exact API paths, optional filtering and publishing hours.
- [Set the proxy address and trust its CA](https://github.com/AndrewMohawk/serverware/wiki/Proxy-and-CA): client settings, destination review and provider application configuration.
- [Configure alerts or inspect activity](https://github.com/AndrewMohawk/serverware/wiki/Notifications-and-audit): separate action alerts and audit delivery.
- [Rotate, reauthorize or remove access](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance): day-two operations without recreating everything.
- [Fix a failed or uncertain operation](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting): expired tokens, unavailable providers, TLS problems and saved-state recovery.
- [Check supported features and terminology](https://github.com/AndrewMohawk/serverware/wiki/Capability-matrix-and-glossary).

## What a successful setup means

**Saved credential → saved permission → policy active → client request succeeded** are separate checkpoints. Saving a key is usually not a provider test. A loaded policy is not proof that a client can reach the proxy or that its provider account has permission. Finish with the intended client request and its recorded outcome in **Audit log**.

Available controls depend on the instance's configured providers, destinations and compatible proxy capabilities. A recipe in the repository is not a preconnected account. The ordinary instance trusts its administrator and uses local encrypted custody: someone with full host control can bypass its controls. Optional [host-trusted request review](https://github.com/AndrewMohawk/serverware/wiki/Permissions-and-policies#optional-host-trusted-approval) is deployed in this same app and passed connected synthetic-provider checks; existing permissions remain unchanged. Review shows metadata/body hash, not body contents. Real-provider use and future TEE-backed enforcement are separate. Host review does not establish hardware custody or enable the unfinished AWS publication path.

This wiki covers operator tasks. For implementation and acceptance status, use the [project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md), [current UI source](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/index.html), and [deployment runbook](https://github.com/AndrewMohawk/serverware/blob/main/docker/serverware-operator-demo/README.md). Older engineering documents may retain historical UI names such as “Applications” or “Accounts and keys”; this guide calls them **Clients** and **Credentials**.
