# Operations and maintenance

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Credentials](https://github.com/AndrewMohawk/serverware/wiki/Credentials-and-providers) · [Troubleshooting](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting)

Keep the credential, client and permission identities when changing only a secret. This avoids rebuilding assignments and makes the audit trail easier to follow.

## Replace a static provider key

1. Obtain the replacement key through the provider's normal process.
2. In **Credentials**, choose **Replace key** on the saved credential and review its affected clients.
3. Enter the new value and save. The form does not retrieve the old secret.
4. Check the saved result, then test a permitted operation from the intended client.
5. Retire the old key at its provider separately when appropriate.

The credential ID, authentication placement, client tokens and permissions stay unchanged. **Replacement saved** does not mean every in-flight request or issued proxy lease has switched, and does not prove the new key works at the provider. A lost response needs a fresh saved-state review, not an automatic repeat. [Replacement contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-key-replacement.md).

## Replace a GitHub App private key without losing assignments

When the capability is offered, generate a replacement PEM for the same GitHub App, then open **Credentials → Replace GitHub App private key**. Review the saved repository and affected clients before submitting it.

Serverware verifies the candidate against the saved App, installation, account, repository and permission ceiling before committing it. The credential identity, assignments, permissions and client tokens remain the same. Inspect the saved result and verify a client request before deleting the old key in GitHub. Replacement here does not remotely revoke already-issued installation tokens or recall in-flight requests. [GitHub key replacement](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-github-client-compatibility.md#replace-an-app-private-key-without-rebuilding-permissions).

## Renew Google consent for an existing account

If an account requires fresh consent and **Reauthorize Google** is available:

1. Open the saved Google account under **Credentials** and select **Reauthorize Google**.
2. Review the exact account, Gmail permission and affected clients.
3. Save and clear any one-time client token still held in the page before leaving for Google.
4. Continue through the consent flow using the same account, return, and check the exact saved result.
5. Test the intended Gmail read separately.

Reauthorization preserves the account identity and its assignments; it does not create a new client or renew that client's proxy token. Use **Check saved status** after an interrupted result. Temporary provider errors and operator configuration problems are not automatically reasons to renew consent.

Do not disconnect an account merely to reauthorize it. Disconnected/quarantined accounts have separate lifecycle constraints; generic disconnected-Google reconnect is not advertised by the current capability. Do not assume a new consent attempt will restore old grants. [Reauthorization procedure](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-google-reauthorization.md), [lifecycle capabilities](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_catalog_capabilities.py).

## Rotate an expired, lost or exposed client token

Open **Clients**, select a replacement lifetime and choose **Rotate client token**. Save the new token when shown once, update the workload's private secret store and wait for the matching policy to load. The previous token stops working after the proxy loads the update; coordinate the change with the workload owner.

Rotation preserves the client identity and assignments. It does not refresh an OAuth account or replace a provider key. Manual tokens expire automatically: one hour, one day, seven days, 30 days or 90 days are offered, with 30 days the default. There is no unlimited token. Manual rotation also invalidates any workload-renewal enrollment and previous-token overlap. If you lose the one-time display, explicitly rotate again rather than expecting the console to retrieve it. [Client lifecycle source](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_applications.js).

## Manage workload renewal

Optional **Clients → Managed workload renewal** is deployed; clients remain manual-only until an administrator explicitly enrolls a workload public key. Use the [enrollment walkthrough](https://github.com/AndrewMohawk/serverware/wiki/Clients-and-recipes#optional-renewal-for-a-long-running-workload) and [managed-client README](https://github.com/AndrewMohawk/serverware/blob/main/examples/managed-client/README.md) for initialization, configuration and worker commands. Keep the private key local and use one client/renewal owner per workload or replica.

Choose a finite 1–90 day enrollment and 1–24 hour token lifetime. Neither renewal nor restart extends the grant. Old-token overlap ends at the earlier of its original expiry and five minutes after rotation; the worker must refresh its SDK connections within that window. Enrollment can shorten the current token's expiry, not extend it. Review grant expiry separately from token expiry and provider consent.

To stop renewal, select the client and choose **Cancel renewal enrollment**, then confirm the saved policy has loaded. Cancellation removes the enrollment and previous-token overlap but leaves the current finite token available for manual use until its existing expiry. To stop the workload's access entirely, revoke the client instead. Replacing enrollment, manually rotating its token or revoking the client invalidates the previous renewal authority and overlap.

After an uncertain renewal, preserve the helper's private journal and follow its exact-operation recovery instructions; do not delete state or automatically replay provider writes. Re-enrollment may require a new private helper directory. Saved state and the deployed read-only UI check are not a verified enrolled workload or real-provider job. [Renewal contract and acceptance boundary](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-workload-renewal.md).

## Host-trusted request review

Host-trusted review is deployed in the ordinary instance and passed a connected
synthetic-provider check. Existing permissions have not been changed; opt in only
for the intended permission. This is not real-provider or hardware acceptance.

1. Explicitly enable `host_review_v1` on the intended permission and wait for the
   matching policy to load. Do not combine it with the shared X daily quota.
2. Run the intended client request. HTTP 428 means review is required; keep its
   review link and exact request, rather than repeatedly sending it.
3. Sign in as the existing administrator and open that exact pending request.
   Review its client, permission, destination, operation and request details.
   The page shows a body hash, not the request body contents; approve only a
   request you recognize from the client that submitted it.
4. Choose **Approve once** or **Deny**. A copied link, notification or page refresh
   cannot approve. Do not repeat a decision after an uncertain result without
   checking its saved state.
5. After approval, explicitly retry the same client request before approval
   expires. The approval is consumed once. Check the decision, consumption and
   request outcome in **Audit log**.

Approval does not mean the provider operation succeeded. After a dispatched write
times out or its response is withheld, inspect the audit and provider state;
never automatically replay it. This is administrator review without per-action
YubiKey/WebAuthn, and the host administrator can bypass its local controls.
Future TEE enforcement has a different trust boundary.

## Stop access at the right scope

| You want to stop… | Action | What remains |
| --- | --- | --- |
| One client operation | **Permissions → Revoke access rule** | The client and saved credential |
| All access by one workload | **Clients → Revoke application** | Shared credentials and other clients |
| Future token renewal only | **Clients → Managed workload renewal → Cancel renewal enrollment** | The current token until its existing expiry, client identity and permissions |
| Future local use of a provider credential | Remove referencing permissions, then **Credentials → Revoke credential** | Audit history; no claim of provider-side revocation |
| A managed provider account connection | Use its explicit account disconnect review | Follow its result; local denial and provider cleanup are distinct |

The current client-card button still says **Revoke application**; it refers to the Serverware client, not a GitHub App. For policy changes, wait until revocation is enforced. Already-dispatched requests cannot be recalled. A local credential revoke does not uninstall a GitHub App or revoke a static key at its provider. [Resource lifecycle](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_resources.js), [client revocation](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_applications.js).

## Review expiry and health separately

Provider-token renewal, provider credential expiry, client-token expiry and policy activation are different states. A GitHub installation token or Google access token can renew server-side while a client's Serverware token still expires. Imported AWS sessions and static keys are not automatically renewed. A saved account or active policy is not a health check of the provider; use the intended read and its audit result.

## Backups, restoration and deployment

These are deployment-owner operations, not console buttons. Use the current checkpoint and state-preservation procedure in the [retained deployment runbook](https://github.com/AndrewMohawk/serverware/blob/main/docker/serverware-operator-demo/README.md#approval-and-state-preservation-gate), not an old command block copied from a historical release.

The documented recovery copy is fresh and stopped-consistent, including the complete persistent state and SQLite sidecars, ownership/modes, credential custody, client-token verifiers/expiry, signed policy/high-water state, audit history, CA and keys. Copying only one database or restoring an old file into running writers is not that backup/restore procedure. The encryption material is part of recovery; a database export alone is not enough.

Keep backups private, preserve the retained publication lock and do not initialize over an existing store. Prepare a reviewed restoration/update plan with preservation checks before changing services. There is no one-click restore, automatic rollback or permission to delete audit/uncertain-operation history when storage fills. [Destination changes](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-proxy-destinations.md) and [Google first-configuration activation](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-provider-configuration.md) also require their specific retained-state procedures.
