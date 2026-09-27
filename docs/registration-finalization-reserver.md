# Cold finalization reservation service

The dedicated `registration-finalization-reserver` accepts only original
finalization authorization, custody raw7, complete before-vector and grant.
It produces and durably retains the genuine current-root reserve computation,
delivers it through the actual state client, and retains the verified original
acknowledgment before responding. This is source-only, unbuilt, unexecuted and
unprovisioned; no unit has been installed or production gate passed.

It does not use the evidence-admission purpose or turn a local preparation ID
into permission. Reservation is not protected SQL execution, completed
credential finalization, completion delivery or OIDC browser-session activation.

## Fixed resources and independent bootstrap

| Resource | Fixed contract |
| --- | --- |
| Process identity | `65510:65510`, no supplementary groups or retained capabilities |
| Request peer | Actual Unix peer `65532:65532` before reading bodies |
| Root/bootstrap/listener FDs | `198`, `199`, `200` |
| Computation-key/journal FDs | `201`, `202` |
| Listener | `/run/serverware/registration-finalization/reserver.sock` |
| Root/bootstrap originals | `/run/serverware/registration-finalization-reserver-trust/root-public-key.pem` and `bootstrap.json` |
| Computation key | `/run/secrets/serverware-registration-finalization-computation-key` |
| Private journal | `/var/lib/serverware/registration-finalization-reservations` |
| State endpoint | `/run/serverware/current-root/state.sock`, accepting service `65516:65516`, root-created listener peer `0:0` |

The [bootstrap](../serverware/registration_finalization_reserver_bootstrap.py)
uses the separate root-signed schema
`serverware.signedRegistrationFinalizationReserverBootstrap/v1`, payload
`serverware.registrationFinalizationReserverBootstrap/v1`, and launch
`serverware.registrationFinalizationReserverLaunch/v1`. It authenticates the
complete configuration/generation/runtime scope and three original enrollments:
current-root, successor grant and **finalization caller**. Each enrollment has
exact `base64Url`, `byteCount`, `bytesDigest`, `identityDigest` fields. Genuine
finalization transition mapping supplies the planner and operation-key pins;
no evidence-only policy mapper or successful-admission object is substituted.

The independent root also pins:

- `statePredecessor`: exact `sequence`, `headDigest`, `nextFence` for this launch.
- `reservationCheckpoint`: exact local journal `sequence`, `headDigest`.
- `stateEndpoint`: fixed socket, integer timeout `1..30`, state service and
  root-listener UID/GID fields.
- Actual listener-FD/path and journal-directory device/inode identities,
  original computation SPKI/measurement, database/generation and runtime closure.

The journal maximum is exactly the current-root enrollment's `maxRecords`
(`2..1024`); both checkpoint sequences must fit that capacity. Sequence-zero
heads must equal the actual enrollment identity and predecessor fence must be
one. A later predecessor/head/fence is an independent expected precondition,
never learned from a returned acknowledgment or journal scan. Neither restart
nor receipt advances these root-pinned scopes automatically.

Bootstrap originals are bounded to 4 MiB, launch lifetime to 300 seconds and
requests to `1..30` seconds. `trustMode` is `trusted-host-local`; hardware,
native-stage-zero, HSM, TEE and external-witness fields are all false. A signed
root assertion does not manufacture currentness, independent provenance or a
live witness. Provisioners must establish those inputs and storage continuity.

## Real custody before serving

The [root entrypoint](../serverware/registration_finalization_reserver_entrypoint.py)
admits bootstrap and activated-listener identities before opening the fixed
private key or journal. Fixed no-follow paths use protected root-owned
ancestors. Original root/bootstrap/key files become sealed memfds; the key is
bounded root-owned mode `0400`, unencrypted Ed25519 PKCS8 PEM. The journal must
already exist as `65510:65510` mode `0700`, matching its signed device/inode.
Delivery creates no account, key, directory, checkpoint or permissive ACL.

After permanent identity drop, the [startup owner](../serverware/registration_finalization_reserver_startup.py)
authenticates the root/bootstrap again before loading the sealed computation
key and verifying its actual pair against current-root enrollment. It constructs
the real `CurrentRootJournal`, fixed-profile `FinalizationReservationDelivery`
at the independently pinned local checkpoint, and `CurrentRootDecisionClient`.
It checks PID, the exact eight-entry environment, sealed originals, listener and
journal identities, actual owner objects, descriptor inventory, sticky clocks
and the original launch bound throughout its finite serial lifecycle.

Source-fixed APIs are `initialize_from_environment`, `require_started`, `close`
and owner `serve_once`. The [launcher](../serverware/registration_finalization_reserver_launcher.py)
accepts only `--root-delivery` and `--run` from the fixed isolated runtime;
the [runner](../serverware/registration_finalization_reserver_runner.py) stops on
lifecycle failure. Closing releases owned listener/journal handles and key
references; borrowed inherited descriptors belong to the process lifecycle.
Fork, poisoned storage or custody drift cannot reinitialize the singleton.

## Original request, durability and historical lookup

The [transport](../serverware/authority_registration_finalization_reservation_transport.py)
uses `SWRFRQ01` / `SWRFRR01`, complete bounded lengths, at most 64 MiB request
originals and exact EOF. Request raw10 is authorization, raw7, before-vector,
grant; response raw3 is original reserve request, signed snapshot, acknowledgment.
Peer credentials precede body reads. One request work/window opens before body
intake and keeps the absolute pre-peer timeout clipped to the original launch;
there is no post-intake or post-replay replacement window.

For a new exact bundle, the [producer](../serverware/authority_registration_finalization_reservation.py)
authenticates the dedicated caller/grant, genuinely replays finalization raw7
and the full vector, and creates the actual computation with the independently
admitted predecessor/head/fence. [Delivery](../serverware/authority_registration_finalization_reservation_delivery.py)
retains its originals before the real state exchange and retains the genuinely
verified acknowledgment before response. Service readout compares the returned
receipt to the exact retained original. Signed configuration and enrollments
come only from the cold owner, never the posted request.

The local raw10 content digest is only a bounded lookup index. On an explicit
repeat call, a unique retained match must have the same independently admitted
predecessor/head/fence; it reuses the original reserve, never signs a replacement
or renews its expiry. Historical retrieval does not permit new SQL or automatic
checkpoint advancement. An uncertain state exchange is not automatically
resent; recovery remains governed by the actual delivery state machine and
original decision/acknowledgment verification. Any new state acceptance remains
subject to the original reserve's expiry. Missing response is not absence of
durable effects and authorizes no retry or deletion.

## Deployment and remaining authority

The uninstalled [socket](../ops/systemd/serverware-registration-finalization-reserver.socket)
and [service template](../ops/systemd/serverware-registration-finalization-reserver.service.in)
require separately admitted `@RESERVER_RELEASE_ROOT@`, `@RESERVER_TRUST_DIR@`,
`@RESERVER_KEY_FILE@` and `@RESERVER_JOURNAL_DIR@`. They do not render themselves,
install privileges or provision state. `Restart=no` preserves the finite cold
launch boundary. Signal handling and cgroup timeout escalation are cooperative,
not a hard kernel syscall watchdog.

UID `65510` also needs independently provisioned state-socket path access and
the explicit root-signed **state bootstrap/launch v2** with
`finalizationReservePeerUid` / `finalizationReservePeerGid` fixed to `65510`.
State v1 retains its old peer set and cannot serve this process. In v2, the
state owner must join UID `65510` to signed `webauthn.registration.finalize`
before historical return or durable publication; UID `65514` is restricted to
evidence admission, and completion/query remain with UID `65515`. A bind mount
or claimed `stateEndpoint` does not supply either; the accepting service UID and its
root-created listener's kernel peer are different identities. The state service
must select the source-fixed finalization profile, not widen a generic peer list.

[Production image source](../Dockerfile.production) includes the fixed isolated
launcher and both uninstalled unit inputs. The image remains unbuilt here;
immutable release admission, frozen verification and independent
service/key/storage provisioning remain required. This service does not provide a present-user
permission path, protected SQL attempt journal/execution, completion service,
credential-success wrapper or separate OIDC activation. A reserve acknowledgment
is not a witness that the pending state remains current afterward.
