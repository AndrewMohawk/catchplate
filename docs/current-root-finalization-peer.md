# Explicit finalization reserve admission at the state service

The dedicated [finalization reserver](registration-finalization-reserver.md)
needs actual state-service admission, not just permission to connect to a socket.
An explicit root-signed v2 startup profile adds that admission in source. It is
unbuilt, unexecuted and unprovisioned; no socket ACL or running service changed.

## Closed root-signed opt-in

The bootstrap envelope, payload and launch must use their matching v2 schemas:
`serverware.signedCurrentRootStateBootstrap/v2`,
`serverware.currentRootStateBootstrap/v2` and
`serverware.currentRootStateLaunch/v2`. The envelope signature uses the v2
domain. Mixing versions, adding fields to v1 or changing peer numbers fails.

The v2 launch has exactly the existing fixed fields plus
`finalizationReservePeerUid: 65510` and `finalizationReservePeerGid: 65510`.
All descriptor, listener, journal, key, enrollment, checkpoint, finite lifetime
and trusted-host-local assurance checks remain mandatory. The root delivery and
nonroot startup each genuinely admit the original bootstrap. The existing
provisioner-only producer chooses v2 only from a closed v2 launch; it cannot
derive a current checkpoint from local storage or a received acknowledgment.

V1 remains unchanged and does not admit the additional peer. There is no
environment toggle, caller-provided peer list or fallback after v2 rejection.

## Peer and signed-operation agreement

The v2 state service uses this fixed mapping:

| Kernel UID:GID | Transport purpose | Additional signed-operation restriction |
| --- | --- | --- |
| `65514:65514` | Reserve | `webauthn.registration.evidence.admit` |
| `65510:65510` | Reserve | `webauthn.registration.finalize` |
| `65515:65515` | Complete or query | Existing completion/query admission, unchanged |

Peer admission precedes the prefix; purpose admission precedes request bodies.
The service forwards only an additional operation restriction to the actual
decision owner. The owner authenticates the signed request, then enforces that
restriction **before** returning an existing historical receipt or computing
and publishing a new decision. No service-side parsed claim substitutes for
the enrolled request signature or serialized state checks. Neither reserve
peer can use completion or query transport.

The real owner still verifies the independent predecessor, fence, complete
before-vector, operation/capability uniqueness and completion capacity. Expiry
does not clear pending state. Exact historical redelivery returns the old
receipt without renewing execution permission or claiming latest currentness.

## Remaining deployment and workflow work

Independently provisioned socket ACLs must permit the fixed primary identity;
the reserver has no supplementary groups. Listener ownership/mode and signed
inode checks are unchanged. Adding this source profile installs nothing and
does not grant production state, witness or signing authority.

The public grant action still only prepares and retains a grant. Its separate
control-plane reservation scope, present permission, dispatch and durable
returned-original association remain to be integrated. Protected finalization
SQL and authenticated outcomes, including a separately admitted completion
path, and independent OIDC session activation also remain open.

Frozen verification must cover unchanged v1, exact v2 version/domain joins,
cross-peer and cross-operation denial before both historical and new decisions,
complete/query denial for reserve peers, uncertainty and actual state durability.
Source review is not that evidence.
