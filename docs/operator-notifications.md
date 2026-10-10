# Operator notifications: action alerts and audit delivery

An optional **operator-development source implementation** now includes four
destination settings, notification-only encrypted custody, a persistent outbox,
safe audit projections, Slack/generic HTTPS transport, administrator API routes
and a Notifications panel. It is **not deployed**, and source/fixture acceptance
does not establish delivery from the running demo or a real Slack workspace.

Real action-required delivery remains disabled by the internal
`ACTION_SOURCE_AVAILABLE = False` gate. Matching action candidates are retained
as suppressed; settings and clearly labelled synthetic tests remain usable when
the optional feature is admitted. Native security-key, measured-runtime and
PostgreSQL source integration are not implemented by this development slice.
Notifications cannot approve, prepare, start or extend a ceremony.

This feature sends Serverware's own notifications. It is separate from an
application calling Slack or another webhook through the credential proxy.

## Two channels, four independent destinations

The Notifications panel separates **Action-required alerts** from **Audit-log
delivery**. Each channel has its own Slack and generic-webhook slots:

| Slot | Intended use | Current source boundary |
| --- | --- | --- |
| `action_required.slack` | Human attention in Slack | Real source suppressed; explicit synthetic tests only |
| `action_required.webhook` | Human-attention receiver | Real source suppressed; explicit synthetic tests only |
| `audit_log.slack` | Readable selected audit summaries | Committed operator-development SQLite events |
| `audit_log.webhook` | Selected structured audit copies | Committed operator-development SQLite events |

Every slot defaults off and independently retains its label, enabled state,
event filters, maximum attempts, saved revision and latest delivery status.
Enabling one does not enable the others. A saved URL is write-only: reads reveal
presence, not the URL, its path/query, fingerprint or encrypted representation.

**Save settings** changes configuration and records a secret-free audit event;
the handler never sends a message. Opening or refreshing the panel never sends
one either. URL operations are explicit: **keep**, **replace**, or **clear**;
clearing requires the slot to be disabled. Empty input does not silently replace
or delete a saved URL. New revisions suppress queued deliveries for the old
revision instead of retargeting them.

**Send synthetic test** is a separate explicit action for the exact enabled,
saved slot/revision. It queues one labelled synthetic notification; HTTP 202
means queued, not delivered. The request accepts no ad-hoc destination URL and
cannot test every slot at once. Save draft changes before testing. A retained
operation ID supports read-only result lookup after a lost HTTP response; the
UI does not automatically resubmit an uncertain operation. Notification settings
and test routes use the existing administrator, same-origin and bounded-body
admission, not a public webhook relay.

## What messages mean

Audit notifications use `schema: "serverware.operatorNotification/v1"` and
contain a source event ID/hash/type/time, a fixed summary, an approved `details`
projection, and a review locator. Arbitrary event objects, request/response
bodies, credentials, destination URLs and challenge material are never copied
wholesale. Unrecognized payload shapes yield metadata-only projections where
the event type is supported. Notification bookkeeping is excluded from export
so retries and configuration changes cannot recursively notify themselves.

The worker adds a stable `delivery_id`, `slot`, saved `revision` and `review_url`.
The review URL is the configured HTTPS console origin plus `/#audit`; it is an
authenticated, non-capability locator, not an approval or one-click mutation.
The source event hash references the authoritative record. It does not make a
redacted notification an independently verified audit-chain record. Local audit
storage, verification and audit anchoring remain separate.

The source projection includes exact approval references/digests and original
expiry when an admitted action record can be recognized, but the current gate
**suppresses actual action delivery**. "Prepare available", "Use your security
key" and "Confirm completion" still require distinct typed events at their real
owners. A preparation row, HTTP 412 or browser readiness poll does not establish
that a key gesture is ready. A separate, guarded read-only phase observer now
exists in the common pilot repository. It distinguishes `prepare_available`,
`security_key_available` and `confirmation_available` while preserving each
original source expiry. It does not deliver notifications: the host-side bridge
to this outbox remains unconnected. This feature never adds network workers or
secrets to that ceremony.

An acknowledged notification is receiver acknowledgement only—not human
approval, completed action, verified audit archive, or renewed authorization.

## Adapter and egress contracts

Both adapters make one bounded JSON POST over verified HTTPS. No redirects,
environment proxies, cookies, caller-selected headers or TLS-verification
bypasses are supported. DNS results are bounded and checked in full before one
exact admitted address is selected; the TLS connection still verifies the
original hostname/SNI. DNS helpers have bounded concurrency and are killed and
reaped on timeout. The transport does not enable ambient `SSLKEYLOGFILE` export.

| Adapter | Destination | Acknowledgement |
| --- | --- | --- |
| Slack | `hooks.slack.com` or `hooks.slack-gov.com`, HTTPS port 443, bounded `/services/.../.../...` grammar | HTTP **200**, `text/plain` (optional UTF-8 charset), body exactly `ok` |
| Generic webhook | Canonical DNS hostname; public HTTPS port 443 by default, or an explicitly admitted private receiver | Complete, bounded HTTP **2xx** response with valid framing; response content is not interpreted as an approval |

Slack receives escaped `plain_text` blocks and a safe fallback summary/review
locator, with markdown and link/media unfurls disabled. The incoming webhook URL
selects its Slack channel; this is not the bearer-token `chat.postMessage`
example. See Slack's [incoming-webhook contract](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)
and [text escaping rules](https://docs.slack.dev/messaging/formatting-message-text/).

Generic receivers get the bounded notification envelope described above. They
can deduplicate using `delivery_id`; exactly-once delivery is not claimed.
Redirects and complete negative HTTP/Slack acknowledgements are terminal
failures, not reasons to automatically repeat the POST. Malformed, truncated or
lost acknowledgements after writing may have begun become `outcome_unknown`.

Current transport limits are 4 KiB URLs, 16 KiB JSON requests, 8 KiB response
bodies, 32 KiB total response framing/body bytes, a 10-second total deadline,
and at most 3 seconds each for DNS and TCP connection establishment. A bounded
owner callback rechecks the saved claim **after TLS and immediately before the
first write**. A disabled/replaced/suppressed claim sends no POST. A false check,
exception or expired transport deadline cannot trigger a retry or renew a
source deadline. No transaction or publication lock spans network I/O.

## Deployment admission and custody

This slice is default-off and limited to the admitted operator-development
profile: development image/channel, development quote mode, SQLite metadata and
audit stores, and no production/native release authority. Ordinary startup
admission must already have succeeded before the optional worker starts.
The following non-secret deployment variables are cold process configuration;
they are not settings that a message or browser request can override:

```dotenv
# Documentation example only; leave disabled until separately reviewed rollout.
SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED=0
SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR=/var/lib/serverware-notification-custody
SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON='{"bindings":[]}'
```

The custody directory must already exist, be owned by the application's effective
UID with mode 0700, and be outside—not an ancestor or descendant of—the ordinary
Serverware data directory. A deployment must mount it **only into the application**,
not the decision gate or other data-plane containers. Path admission is not proof
of container isolation; actual mount inspection is required before rollout.
No Compose configuration or running deployment is enabled by this document.

Only an explicit first Save, after proving no retained notification schema or
notification audit history, may initialize the separate notification key. The
key file is mode 0600 and durably written without overwriting an existing file.
Reads, tests and sends never create or regenerate a missing key. A valid orphan
from a failed first database commit can be recovered by another explicit Save;
malformed/partial records are not repaired or silently adopted. URL encryption
binds owner, slot, adapter and revision. This key is not the application master
key or Google custody, and notification URLs are never proxy credentials.

The optional private-destination variable is strict JSON, at most 4096 bytes,
with this shape (illustrative names only):

```json
{"bindings":[{"host":"audit.internal.example","port":8443,"cidrs":["10.20.30.0/24"]}]}
```

There are at most eight exact canonical DNS-host/port bindings, each with one to
four canonical RFC1918 or IPv6 ULA CIDRs. Every resolved address for a bound
receiver must fall inside its selected networks; public answers do not bypass a
private binding. This exception is only for generic receivers, never Slack.
Loopback, link-local, deprecated site-local, metadata, multicast, unspecified,
reserved and embedded/transition address forms remain refused. IP-literal URLs
and per-message egress exceptions are not supported. The default empty policy
does not admit a private receiver.

## Outbox, retry and recovery

The first Save records the current committed audit head as its starting cursor;
it does not replay historical audit rows. The worker reads bounded ascending
committed snapshots and pins the retained event/hash cursor, then atomically
records the next cursor and deduplicated deliveries. Destination configuration,
source ID and stable delivery ID are retained for each attempt. Action and audit
channels alternate when both have due work.

Each slot allows **one to three total attempts**, default one. Only positively
pre-dispatch DNS, connection or TLS failures may be retried, after 30 seconds and
then 120 seconds. HTTP errors, callback refusals, invalid payloads and
`outcome_unknown` are not automatically retried. No notification retry ever
replays an underlying provider request, approval or hardware action.

An abandoned `sending` attempt is not immediately reclaimed merely because a
different process started. After **60 seconds from its last update**—the
10-second transport bound plus 50 seconds of grace—it is recorded as
`outcome_unknown`, never put back into the queue. Finishing an attempt cannot
overwrite a durable suppression that happened during the pre-dispatch check.

The outbox permits at most **256 queued/sending deliveries**, **10,000 retained
delivery rows**, **10,000 operation receipts**, and **1,024 configuration
revisions**. Capacity failures retain the source cursor and report backpressure;
they do not silently drop selected events or block the source operation on a
remote receiver. Existing queued work can still drain when ingestion is full.
Status exposes queue counts, source backlog and capacity bounds. Automatic
history deletion/retention maintenance is not implemented; reaching a retained
limit requires a separately designed maintenance path, not deletion of audit
history or implicit loss of uncertain receipts.

## Source ownership and remaining work

| Owner | Implemented source slice | Still required |
| --- | --- | --- |
| `operator_notification_custody` / `operator_notification_store` | Independent encrypted settings, explicit initialization, durable operations/cursor/outbox and fixed public status | Deployed custody-mount isolation and operational retention path |
| `operator_notification_events` | Committed operator-SQLite reader, bounded safe projections, exact source comparisons | PostgreSQL/measured source owners and real action producers |
| `operator_notification_transport` | Slack/generic acknowledgement, pinned egress, TLS/deadlines, final pre-dispatch check | Real receiver acceptance after explicit authorized rollout |
| `operator_notifications` / `operator_notification_api` / Notifications UI | Optional worker, administrator settings/test/receipt routes and separate channel panels; isolated API-to-TLS and separate intercepted-browser acceptance | Running-console-to-API-to-receiver proof after reviewed rollout |
| Native pilot browser owner | Separate guarded read-only phase observer with original expiry; no new action authority | Connect the observational delivery bridge, authenticated review and exact current-source recheck without changing the ceremony |
| Existing audit-anchor worker | Remains separate and unchanged | Do not substitute head/count exports for notification event delivery |

## Acceptance boundary

| Check | Source/fixture evidence | Deployment or hardware proof still required |
| --- | --- | --- |
| Four slots and secret custody | **9/9** custody and **10/10** connected store checks pass, including independent slots/revisions, atomic changes, missing-key refusal and public secret canaries | Real app-only custody mount, restart and administrator save/reload |
| Save versus explicit test | **5/5** integration groups and **15/15** intercepted Notifications browser groups pass. Administrator/origin checks, Save without send, exact-revision queueing and read-only acknowledgement receipts are exercised | Exact saved revision queued from deployed UI and retained receipt inspected |
| Egress and acknowledgement | **31/31** isolated transport checks pass, including the final pre-dispatch hook: 20 pure and 11 loopback-TLS/process checks, no live webhook | Real configured receiver and actual deployment trust/egress configuration |
| Integrated audit delivery | **17/17** source-event checks pass. Actual administrator API handlers, encrypted store and worker send four explicit synthetic slot tests plus two adapter copies of one committed fixture application audit event to verified loopback TLS receivers | Real committed proxy/control-plane events through the supported deployed source owner; live browser and external receiver acceptance |
| Failure and backpressure | Connected fixtures pass default-off, worker lifecycle, unknown-outcome no-replay and final pre-dispatch-disable checks. Simulated ingestion-capacity failure still drains a real retained queue. Store fixtures cover bounded retries and 60-second uncertainty recovery | Real crash/restart, lost acknowledgement, saturation and operational retention in the deployed profile |
| Action-required and native key alerts | Synthetic tests deliver through both adapters; actual action candidates remain suppressed. Separate pilot read-only phase-observer inert checks pass; its delivery bridge remains disconnected | Real source bridge, exact pending/expiry revalidation, authenticated review, and authorized physical-key ceremony |

### Retained isolated verification checkpoints

The connected store suite completed **10/10** checks in **71.273 seconds**:
`serverware-operator-workspace-evidence/notification-store.TJK3m8ly/final-tests.log`.
The verified store SHA-256 is
`74a68c46dac401d738758fd40bc3e364fd18a5aebcdf6f016f69d8c5412d0931`;
custody SHA-256 is
`e205d27f127429192fbd1d2274ad7ea0d4adfc924882857d0d975372c318b9b5`.

The final integration suite completed **5/5** groups in **42.736 seconds**:
`serverware-operator-workspace-evidence/notification-integration-final.eFVUpZEx/tests.log`.
It uses real API admission and handlers, committed development SQLite storage,
the actual worker and verified local TLS. Four read-only test receipts and two
additional audit deliveries are acknowledged; none is human approval. Test-only
loopback routing does not widen production egress. Worker lifecycle and failure
controls use explicit test seams; they are not evidence of a live service crash
or complete native startup. Initial harness-only `TMPDIR` and missing-`httpx`
failures were retained; their harness corrections did not change production code.

Rendered-browser regression passed **15 Notifications**, **21 Catalog** and
**29 Connect** groups, with **10 asset checks**. These browser requests were
intercepted synthetic fixtures, separate from the connected API/TLS test above.
Screenshots are retained under `serverware-operator-artifacts/` in
`notifications-browser-synthetic-bVjTVO`, `catalog-browser-synthetic-w1eXlP` and
`connect-browser-synthetic-WmsxIj`. They prove rendered controls, recovery and
presentation behavior—not a browser connected to the running service.

The separate common pilot repository has pushed commit
`984b2753c31234644a84a04eb3a192d1dd0c9403`, preserving the original action expiry
in its guarded read-only phase observations. Its inert projector/GET-handler
checks do not start a guest, listener, delivery service or hardware. Neither that
commit nor these notification tests authorize a new pilot attempt or establish
physical-key/native acceptance.

The transport checkpoint ran in a root-owned, network-isolated container and
exited 0 without OOM in 1.098 seconds. Retained logs, container inspection and
source receipts are under the external evidence directory
`serverware-operator-workspace-evidence/notification-transport-final.U4WPDbfn`.
Its frozen production SHA-256 is
`716dd563d32b254eaadd7820da4a5556c35c2da9e446dbb2ab69aa3cd22a2a49`;
the transport-test SHA-256 is
`86b5a3c76ec1f6543e4d84306988d8f4d10baaadedd744c1f29a4d473ac73a67`.
The TLS fixture's private test-only resolver/admission seams map to synthetic
loopback receivers; they are not deployment egress exceptions.

No result in this document claims production acceptance, a completed native
pilot, a real Slack post, or a live notification rollout. Test results must be
reported with their exact frozen source and fixture scope; a synthetic test does
not establish that a real action producer is connected.
