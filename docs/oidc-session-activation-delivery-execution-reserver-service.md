# Cold protected consume reserver service

This is source-only implementation: unbuilt, unexecuted, uninstalled and unprovisioned. The dedicated service connects the genuine consume reservation libraries and durable delivery owner. It does not execute SQL, release tokens, establish an independently current pending head or close the full reservation/pending criterion: the actual cold SQL pending consumer remains separate.

[`oidc_session_activation_delivery_execution_reserver_startup.py`](../serverware/oidc_session_activation_delivery_execution_reserver_startup.py) constructs and serves the fixed `oidc-session-activation-delivery-execution-reserver` role at UID/GID 65499. The root-created listener is `/run/serverware/oidc-session-activation-delivery-execution/reserver.sock`; requests require peer UID/GID 65532. The exact literal environment, empty supplementary groups, permanent drop, PID, sealed originals, listener identity, journal binding and actual owner configuration remain checked throughout the launch.

## Original cold admission and lifecycle

The [root delivery path](oidc-session-activation-delivery-execution-reserver-delivery.md) opens one actual construction work/window before trust, root-key or private-key I/O. After genuine [role bootstrap](oidc-session-activation-delivery-execution-reserver-bootstrap.md) admission and the permanent privilege drop, it directly continues in the same isolated PID. There is deliberately **no post-drop exec** and no standalone `--run` path that can manufacture a fresh construction allowance.

The private runner passes the same `work`, `live_window` and `transport_deadline_ns` to mandatory `initialize_from_environment(*, work, live_window, transport_deadline_ns)`. Startup reauthenticates the actual sealed originals; it does not accept a successful bootstrap result as authority. The original opening samples survive every policy narrowing. The launch freshness sample is an additional independent guard, not a replacement opening. The inherited construction lifetime remains active through idle and the one request.

Exactly twelve descriptors are inherited:

| FD | Purpose |
| --- | --- |
| 198 | Independent root public key |
| 199 | Signed reserver role bootstrap |
| 200 | Fixed listener |
| 201 | Signed reserve receiving-custody original |
| 202 | Original consume planner bootstrap |
| 203 | Original planning-history custody |
| 204 | Independent reserve receiving-history custody |
| 205 | Consume execution-bundle AES key |
| 206 | Historical activation-bundle AES key |
| 207 | Delivery-custody AES key |
| 208 | Actual enrolled computation signing key |
| 209 | Preprovisioned private reservation-journal directory |

The three AES keys have distinct admitted purposes and bindings; the signer is the enrolled computation key, not the grant authorizer key. No key is taken from a public request. Startup constructs the actual `for_reserve` receiving owner with all four independently pinned detached originals. It then opens an independently flocked `CurrentRootJournal` and the exact consume reservation delivery owner at `/var/lib/serverware/oidc-session-activation-delivery-execution-reservations`. Original enrollment, record recovery and independent local-checkpoint admission use the same cumulative construction work/window/deadline. No directory, key or checkpoint is provisioned here.

`require_started().serve_once()` idles briefly or consumes the launch's sole accepted connection. An accepted wrong peer, malformed frame, rejection, interruption or uncertain outcome is terminal. No startup restart or automatic request retry is available. The accepted socket closes before the final request guard; the guard still rejects expiry during cleanup. `close()` drops key/owner references and closes the actual receiving owner, delivery/journal owner, listener duplicate and all twelve adopted descriptors. Successfully allocated resources are retained for cleanup before a later callback or clock suffix can fail; durable records are never erased by cleanup.

## One original request and durable exchange

The [fixed transport](oidc-session-activation-delivery-reservation-transport.md) receives exact raw5: caller authorization, signed consume plan, encrypted consume originals, canonical closed expectations `{request, scope, journalDigest}`, and the signed consume grant. It returns raw3: signed reserve request, distinct consume computation snapshot and authentic state ACK. Lengths, field bounds, exact EOF and the header-inclusive 64 MiB exchange cap are enforced; no plaintext token or key is a transport field.

One separate request work/window opens **before peer checks or body reads**. Its deadline is already capped by the original startup lifetime. Incoming scope can only narrow the real opening. The service reauthenticates the original role/custody inputs, genuinely admits caller/root/enrollment bindings and verifies the actual signed grant control before journal lookup. Grant expiry immediately clips the remaining monotonic transport bound.

The stable lookup identity frames all five exact request originals under `serverware.oidcSessionActivationDeliveryReservationInputIdentity/v1`. Independent predecessor sequence/head/fence come from the root-admitted role bootstrap, never from an ACK. Lookup precedes signing:

1. If no retained entry exists, the actual [reservation producer](oidc-session-activation-delivery-reservation.md) genuinely replays the private consume originals once and signs with the enrolled computation key. The exact reserve/snapshot pair is durably enqueued before state network I/O.
2. If an entry exists, the original-based retained verifier genuinely replays once and binds the first-exact reserve/snapshot/optional-ACK to the same independent scope. No replacement signature is produced.
3. The service authenticates the actual signed reserve interval and clips state exchange and response sending to its expiry as well as the original grant, caller, plan, role and startup limits.
4. The actual [durable delivery owner](oidc-session-activation-delivery-reservation-delivery.md) returns an already retained exact ACK, or performs one explicitly requested state exchange and authenticates/fsyncs the ACK before return. The service compares all returned bytes and the original input association before sending raw3.

The genuine caller/custody guard remains active around storage, network, serialization, sending and final cleanup. Sending does not invoke a second private replay: the actual delivery owner has already authenticated and durably retained the exact ACK. The receiving side must still perform its own genuine original admission.

## State authority and uncertainty

The root-admitted state endpoint separates service identity 65516 from the root-created socket's kernel peer identity 0:0; the actual state client uses the latter. The [state-v8 peer](current-root-delivery-reserve-peer.md) admits UID/GID 65499 only for `reserve` on `oidc.session.activation-delivery.consume`, preserving older profiles. Its actual locked owner separately joins the full current vector, predecessor and fence and durably publishes before acknowledging.

A later explicitly invoked exact-original lookup/redelivery can recover historical acceptance only while the original controls remain live and the independently admitted predecessor/fence and local journal checkpoint still match. This is not automatic retry, replacement/resigning or a new currentness claim. Uncertain publication, a lost response or an absent ACK never means rollback or permission to regenerate a request. Expiry never renews execution authority.

An authentic ACK does not supply its own expected pending sequence/head/fence. The [independent pending API](oidc-session-activation-delivery-pending-admission.md) requires separately root-held current pins and the distinct SQL-issuer receiving purpose; its actual cold consumer is still unfinished. Protected one-use consume SQL, completion/recovery, committed-original plaintext release, cold response/handoff and public/portal permission remain separate work. No runtime reservation, deployed service or production acceptance is demonstrated by these source files.
