# Permissions and policies

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Credentials](https://github.com/AndrewMohawk/serverware/wiki/Credentials-and-providers) · [Remove or rotate access](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance)

A permission answers: **which client may use which credential, for what operation?** The saved permissions are compiled into the proxy's signed policy. A destination being approved by the operator does not grant every client access to it.

## Prefer a provider preset for a supported job

Use **Set up access**, select the saved credential and client, and choose the operation. Review the displayed scope before saving.

| Job | Scope you select | Not included |
| --- | --- | --- |
| GitHub issue reads or read/create | One exact repository; read-only or read/create | Edits, deletes, merges, GraphQL or workflow-management APIs |
| Read Gmail | The connected account; SDK or custom-client contract | Sending, modifying messages, attachments or other Google services |
| npm metadata | Exact package names | Tarball downloads, installation or publication |
| npm installation | Exact packages including every dependency | Implicit dependency grants or publishing |
| npm publication | One exact package and tag; optional UTC hours | Unpublish, tag administration, provenance or provider 2FA |
| X username lookup | One exact lowercase username | Search, account posting or DMs |
| X account posting | The connected account; optional shared attempt limit when available | Media, replies or general X API access |
| Alchemy chain status | Mainnet or Sepolia; two fixed read methods | Transactions, arbitrary RPC, batches or WebSockets |

Preset support still requires the matching instance capability, approved destination and provider-side rights. See [the capability matrix](https://github.com/AndrewMohawk/serverware/wiki/Capability-matrix-and-glossary) for source contracts.

## “I only want the credential replaced; I do not need response filtering”

For a new supported JSON permission, use the offered whole-JSON request/response modes and leave optional field restrictions unused. Provider presets already choose their compatible defaults. You do not need to invent response fields just to store a key or use a common job.

This means **no optional content filtering**, not unrestricted forwarding. Destination, path/method, body format/size, admitted headers/query parameters, credential-reflection checks and response validation still apply. Existing restricted permissions keep their restrictions; closing **Add restrictions** does not remove choices. [JSON compatibility contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/ordinary-client-compatibility.md).

## Set up a custom JSON endpoint

Use the advanced form in **Permissions** when no provider preset matches your supported JSON API:

1. Choose the exact client and saved Bearer/custom-header credential.
2. Select the approved HTTPS origin and one literal path beginning with `/`, such as `/v1/status`. Do not put a query string, wildcard or fragment in the path.
3. Allow only the methods the client needs.
4. Choose **automatic insertion** if the client sends no provider-authentication header, or **exact dummy replacement** if its library insists on one.
5. For replacement, enter the full public header value exactly as the client sends it. For example, `Bearer SERVERWARE_DUMMY` includes the scheme; `X-API-Key` values do not. This value must never be a real provider secret or Serverware client token.
6. Review supported content modes. Under **Query parameters and client headers**, admit only the names the request needs. Empty query allowances mean no query parameters. Content-Type is controlled by the JSON policy, not that header list.
7. Review the effective summary, save, and wait for activation before testing.

Credential placement comes from the saved credential; this form does not change its header name. Unsupported forms, binary payloads, streaming or request signing need a defined compatible profile, not a more permissive generic rule. [Actual permission form](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/index.html), [input validation](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_catalog_inputs.py).

## Publishing hours and shared attempt limits

For npm publication, a window such as **09:00–17:00 UTC** is daily: start inclusive, end exclusive. Metadata reads remain allowed outside it. It authorizes requests; it does not schedule or queue a release. Overnight/equal-endpoint windows are not offered. [Publishing contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-npm-publish.md#operator-workflow).

Where the X posting quota capability is available, the UTC-day limit counts posting **attempts** across all clients/connections for the verified account. Active permissions must agree on the restriction. An uncertain committed attempt is not refunded or automatically replayed, and the UI is not a live usage/reset dashboard. This ordinary trusted-host quota is not native rollback-proof authority. [Quota contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-x-posting-quotas.md).

## Optional host-trusted approval

The accepted ordinary model is **host-trusted review**, selected per permission
as `approval_mode: host_review_v1`. It belongs to this same Serverware instance,
not a separate demo. Deployment and connected verification are still pending;
check the [project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md)
before relying on it.

The intended flow is: the client receives HTTP 428 and a review link, the existing
authenticated administrator reviews the exact request and chooses **Approve
once** or **Deny**, then the client explicitly retries the same request. Approval
expires and is one-use; decisions and consumption are audited. It does not allow
arbitrary subsequent requests or automatically replay writes. Initially, do not
combine this mode with the shared X daily posting quota.

The review displays request metadata and a hash binding the submitted body, not
the body contents. Approve only requests you recognize. Pending requests expire
after five minutes; an approval lasts at most sixty seconds within that window.

This trusts the server administrator: full host control can bypass the checks or
alter local state. It does not require a per-action YubiKey/WebAuthn ceremony or
provide TEE protection. Future hardware-backed enforcement is separate. See
[review operations](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance#host-trusted-request-review).

## Check activation and revocation

**Saved · activation pending** means the permission is retained but not yet confirmed loaded by the proxy. **Active** confirms the matching policy, not provider health. Similarly, revocation may be **enforcement pending** until the updated policy loads. Use **Refresh activation** and investigate a persistent mismatch rather than recreating the permission.

Revoking one permission retains its client and credential. Revoking a client also revokes its active permissions but retains shared credentials and other clients. Already-dispatched requests cannot be recalled. [Permission lifecycle](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_resources.js), [client lifecycle](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_applications.js).

The files under [policies/](https://github.com/AndrewMohawk/serverware/tree/main/policies) are engineering examples, not a catalog to import wholesale. Some require authority unavailable in the ordinary workspace. Ordinary host review is not a generic “require YubiKey” switch and does not complete the separate protected-approval integration.
