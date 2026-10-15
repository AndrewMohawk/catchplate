# Notifications and audit

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Troubleshooting](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting)

**Action-required alerts** ask a person to do something. **Audit-log delivery** reports something that happened. Configure them independently; sending an audit message is not asking for or granting approval.

## Configure one destination

Open **Notifications**. There are four independent slots:

| Channel | Slack | Generic HTTPS webhook |
| --- | --- | --- |
| Action-required alerts | Team attention requests | An automation receiver for attention requests |
| Audit-log delivery | Selected activity summaries | Structured selected-event copies |

1. Choose the channel and destination type; give the slot a useful label.
2. Enter or replace its webhook URL in the authenticated form. Treat this URL as a secret; saved URLs are write-only.
3. Select its event filters, enable it when ready, and choose the attempt limit.
4. Choose **Save settings**. Review the saved result before leaving.

Each slot has its own enablement, filters, saved revision and delivery settings. Enabling Slack action alerts does not enable Slack audit delivery. An empty URL field means neither “delete” nor “replace”: use the explicit keep/replace/clear choice, and disable a slot before clearing its URL. Saving or refreshing settings sends no message.

Choose at least one event before enabling a destination. An enabled slot with no selected events receives no subscribed activity, even if a synthetic test succeeds. Keep the destination disabled until its event filters are ready.

Where offered, the audit-only preset buttons add proxy blocks/errors, credential/permission changes, or approval history to that slot's draft. They preserve existing selections, include only events advertised by the instance, and never enable, save or send automatically. Review the selected events and explicitly save. They do not change action-alert filters or make an unavailable approval source active.

The first saved configuration starts from the current committed audit head; it does not replay the whole historical log. Later filter changes do not silently expand another slot's selection. [Notification contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#two-channels-four-independent-destinations).

## Test the saved destination

After saving, use **Send synthetic test** for that exact enabled slot. It sends a clearly labelled test through the notification queue, not a provider action or approval request.

Check the delivery result: **queued** is not **delivered**. A receiver acknowledgement is not proof that a person acted, that a YubiKey ceremony completed or that an audit archive was verified. If the request's result is uncertain, use **Check operation result (read only)**. Do not repeat the test automatically.

Each slot supports one to three total attempts. Only known pre-dispatch DNS, connection or TLS failures are eligible for the documented automatic retry. HTTP errors and uncertain delivery are not automatically replayed. New configuration revisions suppress queued deliveries for the old revision rather than redirecting them to the new URL. [Retry and recovery](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#outbox-retry-and-recovery).

## Why an action alert might not arrive

An enabled destination does not create an actionable source. The optional native observation bridge needs separately admitted owner/readiness information and the original action deadline. Legacy ordinary approval/JIT alerts remain suppressed. The new host-trusted review workflow is being implemented separately in this same app; its action-alert source must be advertised and verified before relying on delivery. Configuring Slack neither enables approvals nor starts a pilot.

A real required action belongs on its authenticated review page. Notification links are locators, not bearer approvals, and delivery cannot extend the deadline. Check the source status as well as the destination/worker status. [Action-source boundary](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#what-messages-mean).

## Inspect a client's request

### Find a pending action

New workspace builds include **Pending actions** for saved request metadata.
Deployment status is recorded in the
[project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md#pending-actions--implemented-deployment-pending).
Choose **Select request** to inspect its ID, client, route, method, expiry and
policy. Reopening its exact link keeps that selection; a missing request never
silently selects another. The queue shows at most the first 100 visible pending
records, so an absent record is not proof of approval or denial.

An empty queue is different from a load or authentication failure. Refresh only
reads metadata. The planned `host_review_v1` flow adds **Approve once** and
**Deny** for the existing authenticated administrator reviewing an exact request;
it is not yet a deployed/verified capability or a security-key ceremony. The
client explicitly retries the same request after approval; the approval expires
and is one-use. A saved unknown decision outcome or uncertain provider write is
not automatically retried. Notification delivery grants no authority and does
not change these rules. See [host-review operations](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance#host-trusted-request-review).

### Inspect audit history

1. Open **Audit log → Refresh log**.
2. Filter for **Allowed responses** or **Blocked / withheld responses**, or search by client, credential, permission or event.
3. Match the recorded identity and outcome to the request you actually ran. Use **Load older events** if needed.
4. For integrity checking, choose **Verify audit log**.

A verification result is a point-in-time check. After refreshing, changing the
search or filter, or loading older events, verify again before treating the
current view as checked. Wait for the history request to finish first.

A blocked response can follow an attempted provider request; it does not always mean the request was denied before dispatch. If a write may have reached the provider, do not automatically retry it. See [uncertain outcomes](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting).

Local chain verification checks the stored chain, not an independent external witness or hardware attestation. Notifications contain selected safe summaries/references, not raw request/response bodies or a complete independently verified audit archive. Keep the original audit store as authoritative. [Audit UI](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_proxy_audit.js), [notification projections](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#what-messages-mean).

## Serverware alerts are not proxied application webhooks

These settings configure messages sent by Serverware itself. They do not grant a client permission to call Slack or arbitrary webhooks through the credential proxy. Such application traffic needs its own supported credential, destination and permission; generic JSON support is not a universal webhook adapter.
