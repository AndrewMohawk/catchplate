# Explicit finalization reserve and completion admission at the state service

The dedicated [finalization reserver](registration-finalization-reserver.md) and
[completion worker](registration-finalization-completion-service.md) need actual
state-service admission, not just permission to connect to a socket. Root-signed
v2 adds the reserve peer; explicit v3 adds the completion peer in source. This is
unbuilt, unexecuted and unprovisioned; no socket ACL or running service changed.

## Closed root-signed opt-in

The v2 bootstrap envelope, payload and launch use matching schemas:
`serverware.signedCurrentRootStateBootstrap/v2`,
`serverware.currentRootStateBootstrap/v2` and
`serverware.currentRootStateLaunch/v2`. The envelope signature uses the v2
domain. V3 uses the corresponding `serverware.signedCurrentRootStateBootstrap/v3`,
`serverware.currentRootStateBootstrap/v3` and `serverware.currentRootStateLaunch/v3`
schemas and its own signature domain. Mixing versions, adding fields to an
older profile or changing fixed peer numbers fails.

The v2 launch has exactly the existing fixed fields plus
`finalizationReservePeerUid: 65510` and `finalizationReservePeerGid: 65510`.
V3 retains those fields and adds exactly
`finalizationCompletePeerUid: 65508` and `finalizationCompletePeerGid: 65508`.
All descriptor, listener, journal, key, enrollment, checkpoint, finite lifetime
and trusted-host-local assurance checks remain mandatory. The root delivery and
nonroot startup each genuinely admit the original bootstrap. The existing
provisioner-only producer selects only a matching closed launch profile; it cannot
derive a current checkpoint from local storage or a received acknowledgment.

V1 and v2 retain their prior behavior; neither admits the v3 completion peer.
V1 still has no finalization reserve peer. There is no environment toggle,
caller-provided peer list or fallback after a rejected profile.

## Peer and signed-operation agreement

The v3 state service uses this fixed mapping; its reserve map is unchanged from v2:

| Kernel UID:GID | Transport purpose | Additional signed-operation restriction |
| --- | --- | --- |
| `65514:65514` | Reserve | `webauthn.registration.evidence.admit` |
| `65510:65510` | Reserve | `webauthn.registration.finalize` |
| `65515:65515` | Complete | `webauthn.registration.evidence.admit` |
| `65508:65508` | Complete | `webauthn.registration.finalize` |
| `65515:65515` or `65508:65508` | Query | Existing full shared nonce-bound observation; no operation filter |

The completion-operation restriction for `65515` is new **only in v3**. Its
older completion/query admission remains unchanged under v1/v2.

Peer admission precedes the prefix; purpose admission precedes request bodies.
The service forwards only an additional operation restriction to the actual
decision owner. The owner authenticates the signed request, then enforces that
restriction **before** returning an existing historical receipt or computing
and publishing a new decision. No service-side parsed claim substitutes for
the enrolled request signature or serialized state checks. Neither reserve
peer (`65514` or `65510`) can use completion or query transport.

Query still calls the actual owner's existing lookup/signing path and returns
the full shared observation bound to the caller's nonce. Admitting a completion
peer does not create operation-filtered views, atomic currentness, one-use
action authorization or an independently witnessed latest head.

The real owner still verifies the independent predecessor, fence, complete
before-vector, operation/capability uniqueness and completion capacity. Expiry
does not clear pending state. Exact historical redelivery returns the old
receipt without renewing execution permission or claiming latest currentness.

## Remaining deployment and workflow work

Independently provisioned socket ACLs must permit the fixed primary identity;
the reserver and completion worker have no supplementary groups. Listener ownership/mode and signed
inode checks are unchanged. Adding this source profile installs nothing and
does not grant production state, witness or signing authority.

The separate public finalization [reservation](public-registration-finalization-reservation.md)
and [SQL](public-registration-finalization-sql.md) actions, retained associations
and corresponding portal controls are implemented in source. The dedicated
completion worker is also present. Caller-side cold completion pins, returned
completion retention, separate public completion/recovery permission and the
corresponding portal workflow remain missing. OIDC session activation remains
a separate authenticated transition; neither SQL observations nor state
acknowledgments activate it.

Expected frozen verification, **not run**, covers:

- Unchanged v1/v2 behavior, exact v3 version/domain/field joins and rejection of
  mixed profiles, arbitrary peers and environment-based opt-ins.
- V3 cross-peer and cross-operation denial before both historical receipt
  return and new decisions, including the narrower `65515` completion scope.
- Completion/query denial for both reserve peers; genuine nonce-bound shared
  lookup for both completion peers without an operation-filter/currentness claim.
- Uncertain delivery, exact historical redelivery and actual durable state
  continuity without permission renewal or automatic retry.

Source review is not this evidence or production admission.
