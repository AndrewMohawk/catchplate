> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Operator notifications: action alerts and audit delivery

The **operator-development notification feature** includes four
destination settings, notification-only encrypted custody, a persistent outbox,
safe audit projections, Slack/generic HTTPS transport, administrator API routes
and a Notifications panel. A separately admitted, read-only native observation
bridge is implemented in source. The feature remains default-off for new
deployments; the running demo now enables it with all destinations unconfigured.
The deployed UI, private app-only custody, retained data and outbound TLS were
verified on October 10. No real receiver or native hardware source is configured.
See the [live checkpoint and verification limits](../docker/serverware-operator-demo/README.md#current-notification-enabled-deployment).

The mental model is simple: **action alerts mean "someone needs to do something";
audit alerts mean "this happened."** Configure either, both or neither. An action
alert can ask the operator to prepare, use a YubiKey/security key, or confirm a
native pilot action. It cannot perform, approve, start or extend that action.
An audit copy remains historical information even after the action has changed.

This feature sends Serverware's own notifications. It is separate from an
application calling Slack or another webhook through the credential proxy.

## Two channels, four independent destinations

The Notifications panel separates **Action-required alerts** from **Audit-log
delivery**. Each channel has its own Slack and generic-webhook slots:

| Slot | Intended use | Current source boundary |
| --- | --- | --- |
| `action_required.slack` | Ask someone in Slack to act | Separately admitted native observation bridge; legacy approval source suppressed |
| `action_required.webhook` | Send the same kind of attention request to an automation receiver | Same native source checks, independently configured destination |
| `audit_log.slack` | Show selected events in Slack | Committed operator-development SQLite events, including recorded native observations |
| `audit_log.webhook` | Export selected structured event copies | Same committed audit sources, independently configured destination |

Every slot defaults off and independently retains its label, enabled state,
event filters, maximum attempts, saved revision and latest delivery status.
Enabling one does not enable the others. A saved URL is write-only: reads reveal
presence, not the URL, its path/query, fingerprint or encrypted representation.
For example, send security-key attention requests to a team's Slack channel and
audit copies to a separate HTTPS log receiver. Turning off Slack action alerts
does not turn off webhook audit delivery. Every enabled slot also supports its
own clearly labelled synthetic test, without claiming its real source is ready.

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
Audit and synthetic-test review URLs use the configured HTTPS console origin
plus `/#audit`. Native action alerts instead use the fixed native HTTPS origin
and the exact attempt/readiness-bound review path from the admitted observation.
These are authenticated, non-capability locators, not approvals or one-click mutations.
The source event hash references the authoritative record. It does not make a
redacted notification an independently verified audit-chain record. Local audit
storage, verification and audit anchoring remain separate.

Native phase filters distinguish `native_pilot.prepare_available`,
`native_pilot.security_key_available` and `native_pilot.confirmation_available`.
Only the actual owner's closed observation can provide an actionable source;
a preparation row, HTTP 412, configured socket or browser readiness poll cannot.
The retained projection contains public phase/attempt/source identities and the
original expiry, never options, challenges, credential responses or captures.

The legacy approval/JIT source remains disabled by
`ACTION_SOURCE_AVAILABLE = False`; matching candidates are suppressed. The new
native branch does not enable that gate. PostgreSQL and measured-runtime
notification integration remain outside this operator-development slice.

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
source deadline. For native actions, that callback freshly reads the selected
observer, compares the exact source, checks the saved claim/configuration, and
then rechecks the original nanosecond expiry. No transaction or publication lock
spans network I/O. An expired, unavailable or changed native action is suppressed;
its independently selected historical audit copy can still be delivered.

## Native observation bridge: source capability, not a running pilot

The COMMON repository's dedicated relay is implemented at commit
`ea2811c6d83964934d38fe4fb45b1eb33ed347cb`; it is **not running or provisioned**.
It accepts only `GET /v1/observation` from app UID 10001 on a dedicated Unix
socket. The relay runs as UID 1000 and holds an immutable selection of the real
owner, source files, readiness identity and original clock anchors. Before its
fixed guarded HTTP GET, it verifies that the exact accepted loopback TCP
connection belongs to the selected owner. It cannot launch a pilot or forward
arbitrary methods, URLs, headers or ceremony requests.

The MAIN source client pins the selected socket, parent identity, relay UID,
attempt and selection once. Replacement files are not silently re-admitted.
Each read is limited to 8 KiB and two seconds, with no automatic retry. The
worker records an idempotent committed observation, then the ordinary outbox
selects action and audit copies independently. Final action dispatch performs
the fresh source/expiry checks described above; a matching historical row alone
is never proof that an action is still available.

The UI separates configuration, the last observation and current worker state.
"Source available" describes the last successful observer read, not live
hardware readiness. Displayed action availability expires with the original
source deadline or after 15 seconds without a new observation. Merely saving
settings, admitting a socket or acknowledging a webhook does not prove that a
person can complete the ceremony. No network sender or webhook secret is added
to the ceremony owner.

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
# Optional native source remains unset until separate owner/socket admission:
# SERVERWARE_OPERATOR_NOTIFICATIONS_PILOT_SOURCE_JSON=...
```

The custody directory must already exist, be owned by the application's effective
UID with mode 0700, and be outside—not an ancestor or descendant of—the ordinary
Serverware data directory. A deployment must mount it **only into the application**,
not the decision gate or other data-plane containers. Path admission is not proof
of container isolation; actual mount inspection is required before rollout.
No Compose configuration or running deployment is enabled by this document.

Optional `SERVERWARE_OPERATOR_NOTIFICATIONS_PILOT_SOURCE_JSON` is also cold
configuration, limited to 4096 bytes. Its exact fields are `schema`
(`serverware.operatorPilotNotificationSource/v1`), `socketPath`, `relayUid`
(1000), `selectionSha256`, `attemptSha256` and `nativeOrigin`
(`https://serverware.example.com`). The digests must identify a separately
admitted real selection; they are not generated from browser input. The host
relay's fixed socket is
`/run/user/1000/serverware-notification-observer/observation.sock`. A future
deployment must expose only its dedicated directory read-only to the app, with
parent UID 1000:GID 10001 mode 0750 and socket mode 0660. It must not expose the
ordinary backend socket, ceremony state or the rest of the host runtime
directory. This document neither provisions that mount nor authorizes another
pilot attempt or adoption of a retained terminal attempt.

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
| `operator_notification_custody` / `operator_notification_store` | Independent encrypted settings, explicit initialization, durable operations/cursor/outbox and fixed public status; app-only mount verified in the demo | Saved-key backup/recovery and operational retention path |
| `operator_notification_events` | Committed operator-SQLite reader, bounded safe projections, native observation event/filter mapping and exact source comparisons | PostgreSQL/measured source owners and legacy action producers |
| `operator_notification_transport` | Slack/generic acknowledgement, pinned egress, TLS/deadlines, final pre-dispatch check; deployed DNS/TLS verified without sending | Real configured receiver acknowledgement |
| `operator_notifications` / `operator_notification_api` / Notifications UI | Worker, administrator settings/test/receipt routes and separate channel panels; isolated full workflow and deployed read-only browser acceptance | Deployed administrator save/test and real receiver proof |
| Native pilot browser owner / COMMON relay / `operator_notification_pilot_source` | Guarded phase observer, separately selected GET-only Unix relay and strict client; immutable source identity, original expiry and final current-source recheck | Reviewed relay/mount provisioning, actual guarded-owner timing and end-to-end delivery/review during a separately authorized native attempt |
| Existing audit-anchor worker | Remains separate and unchanged | Do not substitute head/count exports for notification event delivery |

## Acceptance boundary

| Check | Source/fixture evidence | Deployment or hardware proof still required |
| --- | --- | --- |
| Four slots and secret custody | **9/9** custody checks; current **13/13** connected store checks pass; deployed app-only private empty mount survives restart | Deployed administrator save/reload and saved-key recovery |
| Save versus explicit test | **5/5** integration groups and **15/15** intercepted Notifications browser groups pass. Administrator/origin checks, Save without send, exact-revision queueing and read-only acknowledgement receipts are exercised | Exact saved revision queued from deployed UI and retained receipt inspected |
| Egress and acknowledgement | **31/31** isolated transport checks pass; actual deployment DNS and verified TLS 1.3 to Slack pass without HTTP or a webhook post | Real configured receiver acknowledgement |
| Integrated audit delivery | Current **21/21** source-event checks pass. The earlier API/TLS checkpoint sends four explicit synthetic slot tests plus two adapter copies of one committed fixture application audit event through actual handlers/store/worker | Real committed proxy/control-plane events through the supported deployed source owner; live browser and external receiver acceptance |
| Failure and backpressure | Connected fixtures pass default-off, worker lifecycle, unknown-outcome no-replay and final pre-dispatch-disable checks. Simulated ingestion-capacity failure still drains a real retained queue. Store fixtures cover bounded retries and 60-second uncertainty recovery | Real crash/restart, lost acknowledgement, saturation and operational retention in the deployed profile |
| Action-required and native key alerts | **17/17** source-client checks and **2/2** cross-UID synthetic-relay-to-worker-to-TLS cases pass. A phase change after TLS suppresses the action POST while preserving its historical audit copy. Legacy approval/JIT candidates remain suppressed | Actual COMMON relay and guarded native owner, authenticated review, external receiver and separately authorized physical-key ceremony |
| Connected browser workflow | Full isolated browser-to-API-to-worker-to-local-TLS story passes. Deployed read-only browser passes eight GETs and four independently disabled slots on desktop/mobile; **15/15** intercepted groups, **11/11** native UI checks and **10/10** asset checks also pass | Deployed save/test, actual receiver and operator workflow |

### Retained isolated verification checkpoints

The current native-aware source-event suite completed **21/21** checks in
**1.248 seconds**, and connected store suite completed **13/13** in
**95.952 seconds**, as verified by the root runner.

Current native evidence is retained under
`serverware-operator-workspace-evidence/notification-native.vDixx1QB/`:

- `pilot-source-client-tests.log`: **17/17** in **0.899 seconds**.
- `native-crossuid-final-tests.log`: **2/2** in **16.838 seconds**. A synthetic
  UID 1000 relay and real UID 10001 application exercise Unix ownership/peer
  admission, committed storage, worker and verified local TLS. Action/audit
  delivery and post-TLS phase-change suppression are checked independently.
- `rendered-notifications.log`: **15/15** intercepted browser groups against
  the current UI; screenshots are in
  `serverware-operator-artifacts/notifications-browser-synthetic-wDkWee/`.
- `assets-tests.log`: **10/10** in **0.080 seconds**. The separate native UI
  checks also pass **11/11**.

The cross-UID fixture uses a synthetic relay, not the actual COMMON relay or a
guarded hardware owner. The connected-browser story now passes; its receipt is
`notification-native.vDixx1QB/notifications-connected-pxUV1n/acceptance.json`.
It covers 32 actual application requests and six explicit browser mutations:
four independent destination saves, one labelled Slack-adapter test and one
application creation that produces the selected webhook audit event. Saving
alone makes zero outbound connections. Exactly two verified synthetic TLS
deliveries are acknowledged; the other two destinations receive nothing.
The worker starts and stops through the full application's actual lifespan,
the audit chain verifies, and the browser has no console, route or page errors.
Desktop/mobile screenshots and secret-free reload checks are retained beside
the receipt. Both browser and backend finish successfully; temporary containers
are removed after retaining their actual isolation inspections.

The frozen full-source digest for this connected run is
`443cfea9515efb735b88bd666808eb4220e27e1532c5c51e724e28ae2dfb375b`.
Chromium forwards exact HTTP bytes through a bounded stdin ASGI adapter into
the real application in a network-none container. Only synthetic notification
DNS/address/dial/trust-root seams are substituted. This proves the integrated
application workflow, not browser TCP ingress, reverse-proxy/SSO behavior, a
real Slack post, deployment or native hardware. Native observation is unset in
this story and is exercised separately by the cross-UID fixture.

Earlier harness failures remain retained, not rewritten as passes: private-file
creation needed the fixture's 0077 umask, the sanitizer needed bytearray support,
and HTTP header lookup needed case-insensitive semantics. These corrections do
not change production behavior or returned HTTP bodies/headers. The cross-UID
fixture also needed container-only KILL capability to reap its child relay.
The earlier results below remain distinct historical checkpoints.

The earlier connected store suite completed **10/10** checks in **71.273 seconds**:
`serverware-operator-workspace-evidence/notification-store.TJK3m8ly/final-tests.log`.
The verified store SHA-256 is
`74a68c46dac401d738758fd40bc3e364fd18a5aebcdf6f016f69d8c5412d0931`;
custody SHA-256 is
`e205d27f127429192fbd1d2274ad7ea0d4adfc924882857d0d975372c318b9b5`.

The earlier integration suite completed **5/5** groups in **42.736 seconds**:
`serverware-operator-workspace-evidence/notification-integration-final.eFVUpZEx/tests.log`.
The current native-aware worker also passes those **5/5** groups in
**43.665 seconds**; see `notification-native.vDixx1QB/api-integration-tests.log`
under the same external evidence root. Its network-none container exited 0
without OOM. This is still isolated API/TLS acceptance, not live delivery.
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

The separate common pilot repository previously pushed commit
`984b2753c31234644a84a04eb3a192d1dd0c9403`, preserving the original action expiry
in its guarded read-only phase observations. The later dedicated relay commit
`ea2811c6d83964934d38fe4fb45b1eb33ed347cb` adds the observational source bridge;
it does not provision or start it. Inert projector/GET-handler and mocked owner
checks do not establish actual native-owner timing or exercise hardware. Neither
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
