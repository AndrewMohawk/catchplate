# Troubleshooting

[Home](Home.md) · [Proxy and CA](Proxy-and-CA.md) · [Operations and maintenance](Operations-and-maintenance.md)

Start with the checkpoint that failed: **console load, credential save, permission activation, proxy connection, provider operation, or response release**. A failure at one stage does not prove failure—or success—at another.

If a write may have been sent, stop before retrying. For a local “Nothing was
sent” error, fix the named local problem first; recreating credentials or
rotating a shared client token is not the normal fix.

## Common symptoms

| Symptom | What to check next |
| --- | --- |
| The console redirects to sign-in | Complete the expected homelab login. A login page is not the forward-proxy endpoint. |
| Page load returns 503 or remains unavailable | Record the route and time; ask the deployment owner to check the actual app/proxy health and pairing. Ordinary page load should not require a pilot or build. Do not reset the store to “initialize again.” |
| The private JSON is rejected before a connection | Use the complete download for this example's family, not just `client_recipe`. A GitHub/Gmail config cannot be passed to common-app `request.py`. Check the source release matches the deployment; do not manually replace old public markers. |
| Python reports missing or mismatched packages | Run the example's `.venv/bin/python` (or `.venv-ai`/`.venv-services`) and prepare its pinned requirements separately, without supplying the client token. Do not reinstall all examples or build Catchplate. |
| A CA file cannot be found | Relative `ca_file` and optional proxy-CA paths start beside the private JSON, not the current directory. Keep the original filenames or update only the intended local path; never replace the CA with a private signing key. |
| A provider button is disabled or missing | Review its advertised capability and approved destination in **Proxy setup**. Google/X account flows additionally require the configured provider application and matching readiness. |
| Google account is saved but **Use this credential for a client** is unavailable | The saved account does not establish support for its exact Gmail access bundle. Check instance readiness; do not paste its OAuth tokens into a manual key. |
| A saved permission says activation pending | Use **Refresh activation**. Saving and proxy policy loading are separate; do not create duplicate grants. |
| Client login is denied | Check the selected client ID, token expiry/revocation, advertised login mode and loaded policy. The provider secret is not the proxy password. |
| HTTP 401 or 407 | Determine from the client error/audit whether authentication failed at the proxy or provider. For standard proxy login, use the client UUID and its unexpired token; the operator checks provider credentials separately. |
| HTTP 403 | Inspect the matching audit reason and exact permission/scope. Do not broaden a grant, change the dummy token or disable TLS as a diagnostic shortcut. |
| HTTP 428 / approval required | Open the validated approval path on your instance's console, or ask the operator to review it. Approval does not send the request: explicitly repeat the identical request before its deadline. Do not poll by resending a write. |
| The token disappeared after reload | One-time tokens cannot be retrieved. Rotate the client's token deliberately, save it and update the workload. |
| TLS verification fails | Check the proxy hostname/default outer trust and the downloaded interception CA separately. Use the selected recipe's supported trust options; never disable verification. |
| A request is refused despite an active permission | Compare exact origin, path, method, query/header names, dummy value, provider preset and provider-side rights. “Active” does not mean arbitrary API access. |
| npm install fails on a dependency or advisory call | Use **Install packages and run npm audit**, not metadata-only. Explicitly list every transitive package and inspect the example's audit result; do not silently disable audit to call the job successful. |
| A write times out or its response is withheld | Treat provider completion as uncertain. Inspect saved/provider state and audit; do not replay automatically. |
| Notification says queued but nothing arrived | Check that exact slot's delivery and worker/source status. A queued receipt is not delivery, and a synthetic test is not a live action-source check. |

Sources: [workspace walkthrough](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-demo.md), [proxy/client UI](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/index.html), [npm installation](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-npm-install.md), [notification recovery](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-notifications.md#outbox-retry-and-recovery).

## Check locally before involving the provider

For a **common-app** download, run this from the repository root after preparing
that example's environment:

```sh
examples/common-apps/.venv/bin/python -I -B examples/common-apps/request.py \
  --config /private/catchplate-client.private.json --check-config
```

This checks local format, token expiry, pinned dependencies, CA files and query
arguments with no DNS or provider request. `configuration_ready` is not proof
of server activation, network reachability or a valid provider key. It is not a
universal checker for GitHub, Gmail, npm, ECR or managed-client configs. MCP has
its own local `--check`; use the [MCP guide](../../examples/mcp/README.md).

If you have an older Serverware download, keep it with the matching client
release until the operator confirms that instance's Catchplate cutover. The
renamed repository does not update the retained main deployment. The
[local migration guide](../../examples/client-config-migration.md) describes
supported conversions; never rewrite signed state, policy hashes, tokens or
provider selectors by search-and-replace.

## A save returned no clear result

A timeout or lost acknowledgement does not prove rollback. If the page offers **Check operation result**, **Check saved status** or **Refresh Google status**, use that read-only recovery action for the existing operation. Otherwise refresh and review the saved resources before making another change.

Do not repeat a create, rotation, provider verification, consent start or notification test just because the receipt is missing. The UI may hold further writes until the saved state is reviewed. Preserve the displayed public operation reference; do not capture secrets, callback codes or authorization URLs in a support ticket. [Managed configuration recovery](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-provider-configuration.md#operator-configuration-workflow), [key replacement recovery](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-key-replacement.md#transaction-and-api).

The save-review repair in `07d54103` keeps a public warning across reloads in the
same tab. After refreshing, inspect **Credentials**, **Clients** and
**Permissions** for the saved change, then select **I reviewed the saved state**.
If the credential already exists, use that credential instead of creating it
again. This acknowledgement clears only the ordinary warning, not a provider's
pending consent or operation-recovery hold. A lost one-time client token still
requires deliberate rotation; the warning does not retain the token or request.
If session storage is unavailable, the page refuses new writes rather than
sending an untracked save. Do not clear browser storage to bypass recovery.
This repair passed the isolated full-flow check and was deployed on October 14;
check the [current deployment record](https://github.com/AndrewMohawk/catchplate/blob/main/docs/project-completion.md#current-live-deployment)
for the installed version.

## Google setup appears to block other changes

A selected pending/exchanging consent attempt holds changes while its state is checked. Reopen the existing setup panel and use its status action. **Leave Google setup** is an explicit navigation action; it does not cancel consent at Google or prove an uncertain operation failed.

An unsaved one-time client token deliberately blocks leaving for Google: record it, then use **I've saved it; clear token**. Provider-key fields are cleared when entering/leaving provider flows; public draft labels can be preserved, but secret drafts must be reentered when needed. [Google controller](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/workspace_google.js), [shared setup flow](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/workspace_connect.js).

## “Blocked response” is not necessarily “request never sent”

Catchplate can withhold an unsafe or unsupported reply after the provider has received the request. For a possible write, the provider may already have committed its effect. Where recorded, `upstreamDispatch`, `providerOutcome`, `providerOperationMayHaveCommitted` and `retryProviderRequest` explain this uncertainty.

Do not change client retry settings to force a write through. Check the provider's actual state using an appropriate authorized read before deciding whether another write is safe. A blocked-response audit entry or local HTTP error cannot undo a published package, created issue or post. [Response and retry contract](https://github.com/AndrewMohawk/catchplate/blob/main/docs/ordinary-client-compatibility.md#a-withheld-response-is-not-a-denied-request).

## When to involve the deployment owner

Escalate persistent policy mismatch, 503/readiness failure, missing provider configuration, destination changes, quota-store unavailability, audit backpressure or retained-state errors. The console does not restart services or repair authority/storage automatically. Do not disable checks, extend expired tokens, remove history or run an initializer against retained state.

Send a concise, secret-free report: time, route/action, client/credential/permission public IDs, displayed status, public operation reference and relevant audit event. Include the example directory, source release, language/runtime, which stage failed and whether it reported “Nothing was sent” or an uncertain result. If you lack console access, ask the operator to locate the audit event rather than requesting administrator access. Exclude provider keys, client tokens, webhook URLs, private configs, OAuth codes/state and raw private request/response content. [Deployment runbook](https://github.com/AndrewMohawk/catchplate/blob/main/docker/catchplate-operator-demo/README.md), [project capability/acceptance tracker](https://github.com/AndrewMohawk/catchplate/blob/main/docs/project-completion.md).
