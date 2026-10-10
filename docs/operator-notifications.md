# Operator notifications: action alerts and audit delivery

Specification only. Slack/generic notification settings, delivery workers and
end-to-end acceptance are **not implemented**. This describes Serverware's own
outbound notifications, not applications using webhook destinations through the
credential proxy. It does not authorize a live send or hardware ceremony.

## Independently configured channels

Operators need two separate channels:

- **Action required:** tell the appropriate operator that a specific live action
  needs attention, including an explicit security-key gesture when actually
  available.
- **Audit logs:** deliver selected copies/summaries of committed audit events.
  These are not action requests, and receiving them grants no authority.

The first version has four independently enabled destination slots:
`action_required.slack`, `action_required.webhook`, `audit_log.slack`, and
`audit_log.webhook`. Each channel can use Slack, a generic webhook, both or
neither. All slots default off; enabling one does not enable another.

Proposed settings—not existing UI—show each channel's event filters,
destinations, finite retry policy and delivery status separately. Each destination
has an operator-supplied label, write-only URL, saved revision and explicit
enable/disable control. Actions and audit copies may use different destinations
and filters. Saving or opening settings never sends a message.

An explicit **Send test** action targets the exact saved slot/revision and sends
only a clearly labelled synthetic message. It cannot accept an ad-hoc URL, act
as an approval, probe every destination, or retry after an uncertain response.
Show its retained result through a read-only lookup. Clearing or replacing a URL
is explicit; blank input does not silently delete or replace the saved secret.

## What messages mean

An action notice contains a bounded action label, source event ID, exact
operation/approval reference, relevant immutable source digest, original expiry,
and an authenticated review link. The link is a non-capability locator under the
configured console origin: no admin token, WebAuthn challenge/assertion, secret,
signed approval or one-click mutation. Opening it only observes current state.
The ordinary authenticated review and explicit gesture remain necessary.

"Prepare is available", "Use your security key", and "Confirm completion" are
different events. A preparation record, HTTP 412 or browser readiness poll does
not establish that a hardware gesture is ready. Suppress resolved or expired
action notices immediately before dispatch. Messages may arrive late; the
server remains authoritative and never extends an original wall/monotonic
deadline because a message was queued, delivered, clicked or retried.

Audit delivery exports a versioned, bounded safe projection: source event ID,
type, time, permitted actor/resource identifiers, outcome, and explicitly
approved fields. Unknown event payloads are not forwarded wholesale. No request
or response bodies, credentials, webhook URLs, challenge material or arbitrary
`request`/`event` objects are included. Slack gets a readable summary and an
authenticated audit link; the generic webhook gets the documented JSON envelope.
The source event hash is a reference to the authoritative record, not a claim
that a transformed/redacted message verifies the original hash chain. The local
audit log, its verification and audit anchors remain independent.

## Secret custody and safe delivery

Slack Incoming Webhooks accept JSON POSTs at a secret URL, bind their Slack
channel to that URL, and normally acknowledge with HTTP 200/plain-text `ok`.
They are not the existing bearer-token `chat.postMessage` example. See the
[official Slack contract](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).

Store the entire destination URL encrypted, including secret path/query
components, in notification-specific custody. Bind ciphertext to owner, slot,
adapter and configuration revision. Do not reuse the closed Google application
custody grammar or expose notification credentials as application proxy grants.
No URL, partial secret path, URL fingerprint, ciphertext, raw transport exception
or provider response body appears in public status, configuration audit, logs or
test receipts. Reads expose only safe labels, adapter, revision and presence.
Fresh-store key initialization must have its own admitted path; a read or send
must not silently create a missing key.

Delivery uses verified HTTPS, bounded payload/response sizes and total deadlines;
no redirects, environment proxies, cookies or arbitrary caller-selected headers.
Admit and pin resolved addresses while retaining hostname/SNI verification.
Default-deny loopback, metadata endpoints and unapproved private destinations;
an internal generic receiver requires a separate explicit operator egress policy,
not a per-message bypass. Never disable TLS verification. Slack destination and
acknowledgement grammars are adapter-specific; generic receivers have an explicit
JSON/HTTP acknowledgement contract. Escape message fields and disable unsolicited
mentions/unfurls rather than interpreting event content as Slack markup.

Use a bounded persistent outbox after the source event commits. Network calls
never run inside an approval, audit, publication or credential transaction.
Each delivery pins channel, slot, configuration revision, source event and a
stable delivery ID. Destination replacement cannot retarget queued history;
disabling a slot stops its pending sends. Keep action/audit scheduling fair and
report backlog or overflow instead of silently dropping events or blocking the
source operation on a remote webhook.

Each channel has independently bounded attempts/backoff and visible states such
as queued, sending, acknowledged, failed, outcome-unknown, expired or suppressed.
Do not claim exactly-once delivery: a lost acknowledgement can mean a message
was accepted. Generic receivers may deduplicate the stable delivery ID. Ambiguous
delivery requires an explicit configured duplicate-tolerant policy or operator
decision; it never authorizes replay of the underlying provider request or
ceremony. Delivery bookkeeping must not recursively generate notifications of
its own retries. Configuration changes remain audited without destination URLs.

## Existing seams and missing implementation

| Source | Reuse or required addition |
| --- | --- |
| `db.append_audit_event`, `record_audit_event`; `data_plane_audit_store._events` | Read committed audit records across all actual write paths. A hook in only one append wrapper misses direct/measured writes. Add an ascending, bounded reader with retained event/hash cursor checks; the UI's recent-event search is not a durable export cursor. |
| `db.create_approval_request`, `_ensure_jit_approval_request_on_connection`, control-plane approval creation | Existing `approval.requested` and `control_plane.approval.requested` are durable action candidates. Project only approved fields and recheck the exact source's live status/expiry. |
| `db.create_webauthn_challenge`; app MFA refusal | Challenge creation currently has no action-notification event. Add a typed event at the actual durable owner where needed; do not infer a new action from repeated HTTP failures or browser polling. |
| Native pilot retained browser owner | Verified `start-readiness.json`, `handoff.json` and `assertion-options.json` publications distinguish Prepare, key use and confirmation. This separately owned isolated, single-threaded ceremony needs a host-side observational bridge; do not add network workers/secrets to it or reinterpret readiness as authority. That bridge is not implemented. |
| `runtime.start_audit_anchor_worker` / `export_audit_anchor_once` | Existing service exports audit head/count checkpoints, not audit records. Its raw-URL/error status contract is unsuitable for secret webhook destinations; keep it separate. |
| `http_client.request_bytes` | Existing bounds, no redirects and no environment proxy are useful. Destination admission, DNS/address pinning, fixed secret-safe failures and adapter acknowledgements still need implementation. |
| Operator API/portal and app startup | Add authenticated, same-origin, bounded settings/test/status endpoints and two settings panels only after real storage/worker paths exist. Start the optional worker after existing profile/startup admission; no fake success UI. |

A minimal source split is notification settings/custody and outbox ownership;
typed source-event projections; bounded Slack/generic transport and worker;
then API/UI integration. Keep these outside the already-large `app.py`/`db.py`
except for narrow existing-owner hooks. Native/measured source integration needs
its owning profile's review; an operator-only fixture is not proof of that path.

## Acceptance required before claiming support

| Check | Required result |
| --- | --- |
| Independent configuration | Four slots and two filter/retry policies remain independent through save, reload, disable and replacement. |
| Explicit test | No send on page load/save; one click queues the exact saved revision; lost response is inspected without automatic resubmission. |
| Action authority | Real committed source event produces one deduplicated notice; its locator requires authentication; stale/expired/resolved source is suppressed; no approval, hardware call, new clock or automatic start occurs. |
| Audit delivery | Real committed proxy/control-plane events reach each selected adapter as documented projections; uncommitted events do not; restart/cursor and backlog behavior are proven. |
| Secret safety | Synthetic URL/token canaries are absent from public API/UI, database metadata, audit, logs and errors; encrypted custody is tested independently. |
| Egress and protocol | Isolated receivers prove TLS, exact destination, DNS/address restrictions, no redirects, size/deadline limits, Slack text acknowledgement and generic contract. No live webhook is contacted. |
| Failure/recovery | Crash/restart, timeout, lost acknowledgement, duplicate IDs, bounded retries, destination changes and disabled slots preserve recorded delivery outcomes without retargeting or source-operation replay. |
| Presentation | UI distinguishes configuration, queued delivery, receiver acknowledgement and human action; acknowledgement never means approval or audit-chain verification. |
