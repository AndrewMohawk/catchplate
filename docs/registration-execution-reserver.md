# Cold registration execution reserver

This source-only service composes the existing [reservation producer and
durable delivery owner](registration-execution-reservation.md) for the fixed
`webauthn.registration.evidence.admit` operation. It is unbuilt and unexecuted;
packaging is not installation or deployment. No public caller is activated.
It does not execute SQL, finalize a credential or return a current-head lease.

## Fixed identities and cold authority

The service runs as UID/GID **65514**, separately from the control-plane caller
**65532**, current-root state owner **65516**, and completion peer **65515**.
The state startup and bootstrap explicitly admit 65514 for reserve and 65515
for completion; these roles are not interchangeable.

The root-activated reserver listener is fixed at
`/run/serverware/registration-execution/reserver.sock`. The client checks its
Unix peer as **0:0**, not 65514: the listener's root activation is distinct
from the service's execution identity. The state exchange likewise checks its
root-activated listener as 0:0, not the state process's UID/GID.

The [root-signed bootstrap](../serverware/registration_execution_reserver_bootstrap.py)
binds the admitted configuration/generation, three enrollment originals,
dedicated computation-key identity/measurement and independent current-root
predecessor sequence/head/fence. It separately pins the local reservation
journal's sequence/head. A recovered journal or incoming grant cannot appoint
either checkpoint. Its closed profiles are
`serverware.signedRegistrationExecutionReserverBootstrap/v1`,
`serverware.registrationExecutionReserverBootstrap/v1` and
`serverware.registrationExecutionReserverLaunch/v1`, bounded to 4 MiB.
This is explicitly trusted-host-local custody, not hardware, TEE or witness
admission. The private computation key is delivered separately, not in the
bootstrap. The signed launch lasts at most 300 seconds; each request has a
1–30 second bound clipped to the original launch and operation bounds.
Reading retained originals does not renew them.

Each launch admits **one predecessor sequence/head/fence**. Receiving an
acknowledgment does not advance that scope automatically. A later state step
requires independently admitted new launch/checkpoint material, not a local
increment or a claim copied from an incoming grant.

Provisioning must also grant the reserver access to the fixed state socket.
That socket remains owned by 65516:65516 with mode 0660, while the reserver has
no supplementary groups. A reviewed root-provisioned ACL or equivalent narrow
access arrangement is therefore required for UID 65514; the service does not
change permissions or broaden the completion peer.

## Actual cold entry and packaging

The fixed isolated [launcher](../serverware/registration_execution_reserver_launcher.py)
selects only `--root-delivery` or `--run`. The root
[entrypoint](../serverware/registration_execution_reserver_entrypoint.py)
authenticates the original bootstrap before opening the private key and journal,
joins the actual listener/journal identities, then permanently drops to
65514:65514 with no supplementary groups. It delivers exactly five descriptors:

| FD | Retained owner input |
| --- | --- |
| 198 | Independently provisioned root public key |
| 199 | Original signed bootstrap |
| 200 | Actual fixed activated listener |
| 201 | Dedicated computation-only private key |
| 202 | Actual protected reservation-journal directory |

The [startup owner](../serverware/registration_execution_reserver_startup.py)
performs cold admission; the [runner](../serverware/registration_execution_reserver_runner.py)
uses `initialize_from_environment()`, `require_started().serve_once()` and
`close()` under a finite serial lifecycle. The reserver holds no grant-authorizer,
current-root state-signing or completion private key.

The supplied [socket unit](../ops/systemd/serverware-registration-execution-reserver.socket)
and [service template](../ops/systemd/serverware-registration-execution-reserver.service.in)
are uninstalled deployment inputs. The socket pathname is owned by 65514:65532
with mode 0660; its root-created listener credentials are a separate check.
The template uses `Restart=no`, `RuntimeMaxSec=300s` and cgroup termination;
these are not cryptographic admission or hard blocked-syscall termination.
The [production image recipe](../Dockerfile.production) copies the fixed
launcher and templates without installing or activating the service.

## Original-only exchange

The [transport](../serverware/authority_registration_reservation_transport.py)
has no JSON parser, signing, work allowance or configurable operation. Its
closed request is the existing grant bundle, in this exact order:

1. Dedicated caller-authorization original.
2. Original planning request3: signed control, context, inputs.
3. Original planning response4: signed control, plan envelope, inputs,
   evaluation context.
4. Complete before-vector original.
5. Original signed execution grant.

The ten bodies are framed by `SWRRQ001`, ten unsigned big-endian 64-bit lengths,
then the exact bodies. All source-derived individual and planning-group limits
and the combined **64 MiB** ceiling pass before body allocation. There are no
posted expected roots, signer keys, predecessor/checkpoint overrides or
successful-verification objects.

The response is `SWRRR001`, three lengths, then exactly:

| Original | Maximum |
| --- | --- |
| Signed reserve request | 256 KiB |
| Computation snapshot | 16 KiB |
| Signed state acknowledgment | 16 KiB |

One absolute monotonic deadline covers connection, peer checks, framing,
request half-close and exact response EOF. The server requires request EOF
before processing. Extra bytes, partial frames and wrong magic fail closed.
There is no retry or alternate socket. A transport return alone authenticates
none of the three response originals.

## Replay, durability and redelivery

```text
raw10 originals + independently admitted cold configuration and checkpoints
    -> genuine caller authorization, signed planning exchange and grant replay
    -> computation-key-signed reserve request + snapshot
    -> durable local originals before the state exchange
    -> actual signed state acknowledgment, durably retained before raw3 return
```

The service recomputes the grant bundle's local content identity from the exact
originals. That value associates local records; it is neither a caller-selected
permission nor proof of a grant's signature. A new grant must pass the actual
producer's replay and dedicated authorization joins before reserve signing.
The delivery owner independently authenticates the signed reserve/snapshot
and state acknowledgment under the enrolled keys and fixed predecessor/fence.

An explicit same-original redelivery may recover an already accepted receipt.
It cannot revive an expired, never-accepted reserve or manufacture a newer
current root. A failure can occur after remote acceptance or local durability;
it is not proof that nothing happened and does not justify an automatic retry.
Historical originals and local inspection remain observations, not independent
currentness, one-use SQL authority or credential-finalization permission.
Across cold starts, same-original receipt recovery still needs an independently
current local-journal checkpoint and the same original predecessor scope. It
does not permit restoring an old journal prefix, resetting the local head or
adopting a new predecessor from the acknowledgment.

Filesystem barriers depend on the provisioned storage. The local journal does
not provide hostile-host rollback protection. Deadline checks do not interrupt
every blocked filesystem, socket or driver call; an external hard watchdog
remains a separate prerequisite.

## Remaining integration

Root/key/FD/account/socket/ACL/journal provisioning and independent checkpoint
admission remain external. Source packaging is uninstalled, and the public
preparation handlers are not connected to this reserver by this slice.
Protected SQL issuance/execution, completion and credential finalization still
require their separate authorities and actual owners.

Genuine prepare-and-retain now preserves signer request8/response2 and commits
their [local association with the grant](control-plane-custody-journal.md#associated-registration-preparation)
only after both original records are durable. The reserver still receives the
existing grant raw10, not signer originals or an association-based permission.
Later credential finalization must genuinely authenticate the exact associated
signer originals and committed evidence under its separate gates; that path is
not activated here. See the [reservation guide](registration-execution-reservation.md#remaining-integration).
No production acceptance gate is closed by this source implementation.
