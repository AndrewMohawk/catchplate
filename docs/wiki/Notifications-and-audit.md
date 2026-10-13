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

The first saved configuration starts from the current committed audit head; it does not replay the whole historical log. Later filter changes do not silently expand another slot's selection. [Notification contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#two-channels-four-independent-destinations).

## Test the saved destination

After saving, use **Send synthetic test** for that exact enabled slot. It sends a clearly labelled test through the notification queue, not a provider action or approval request.

Check the delivery result: **queued** is not **delivered**. A receiver acknowledgement is not proof that a person acted, that a YubiKey ceremony completed or that an audit archive was verified. If the request's result is uncertain, use **Check operation result (read only)**. Do not repeat the test automatically.

Each slot supports one to three total attempts. Only known pre-dispatch DNS, connection or TLS failures are eligible for the documented automatic retry. HTTP errors and uncertain delivery are not automatically replayed. New configuration revisions suppress queued deliveries for the old revision rather than redirecting them to the new URL. [Retry and recovery](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#outbox-retry-and-recovery).

## Why an action alert might not arrive

An enabled destination does not create an actionable source. The optional native observation bridge needs separately admitted owner/readiness information and the original action deadline. Legacy ordinary approval/JIT alerts remain suppressed; configuring Slack is not an approval integration or a way to start a pilot.

A real required action belongs on its authenticated review page. Notification links are locators, not bearer approvals, and delivery cannot extend the deadline. Check the source status as well as the destination/worker status. [Action-source boundary](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#what-messages-mean).

## Inspect a client's request

1. Open **Audit log → Refresh log**.
2. Filter for **Allowed responses** or **Blocked / withheld responses**, or search by client, credential, permission or event.
3. Match the recorded identity and outcome to the request you actually ran. Use **Load older events** if needed.
4. For integrity checking, choose **Verify audit log**.

A blocked response can follow an attempted provider request; it does not always mean the request was denied before dispatch. If a write may have reached the provider, do not automatically retry it. See [uncertain outcomes](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting).

Local chain verification checks the stored chain, not an independent external witness or hardware attestation. Notifications contain selected safe summaries/references, not raw request/response bodies or a complete independently verified audit archive. Keep the original audit store as authoritative. [Audit UI](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_proxy_audit.js), [notification projections](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-notifications.md#what-messages-mean).

## Serverware alerts are not proxied application webhooks

These settings configure messages sent by Serverware itself. They do not grant a client permission to call Slack or arbitrary webhooks through the credential proxy. Such application traffic needs its own supported credential, destination and permission; generic JSON support is not a universal webhook adapter.
