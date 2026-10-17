# Explicit finalization and activation-planner peers at the state service

The dedicated [finalization reserver](registration-finalization-reserver.md) and
[completion worker](registration-finalization-completion-service.md) need actual
state-service admission, not just permission to connect to a socket. Root-signed
v2 adds the reserve peer; explicit v3 adds the completion peer in source. V4
separately admits the activation planner for head observations only. This is
unbuilt, unexecuted and unprovisioned; no socket ACL or running service changed.

## Closed root-signed opt-in

The v2 bootstrap envelope, payload and launch use matching schemas:
`catchplate.signedCurrentRootStateBootstrap/v2`,
`catchplate.currentRootStateBootstrap/v2` and
`catchplate.currentRootStateLaunch/v2`. The envelope signature uses the v2
domain. V3 uses the corresponding `catchplate.signedCurrentRootStateBootstrap/v3`,
`catchplate.currentRootStateBootstrap/v3` and `catchplate.currentRootStateLaunch/v3`
schemas and its own signature domain. V4 uses the corresponding
`catchplate.signedCurrentRootStateBootstrap/v4`,
`catchplate.currentRootStateBootstrap/v4` and `catchplate.currentRootStateLaunch/v4`
schemas and its own signature domain. Mixing versions, adding fields to an
older profile or changing fixed peer numbers fails.

The v2 launch has exactly the existing fixed fields plus
`finalizationReservePeerUid: 65510` and `finalizationReservePeerGid: 65510`.
V3 retains those fields and adds exactly
`finalizationCompletePeerUid: 65508` and `finalizationCompletePeerGid: 65508`.
V4 retains v3 and adds exactly `activationPlannerPeerUid: 65507` and
`activationPlannerPeerGid: 65507`; no descriptor, key or journal is added.
All descriptor, listener, journal, key, enrollment, checkpoint, finite lifetime
and trusted-host-local assurance checks remain mandatory. The root delivery and
nonroot startup each genuinely admit the original bootstrap. The existing
provisioner-only producer selects only a matching closed launch profile; it cannot
derive a current checkpoint from local storage or a received acknowledgment.

V1, v2 and v3 retain their prior behavior; none admits the v4 planner peer.
V1/v2 still do not admit the v3 completion peer, and v1 has no finalization
reserve peer. There is no environment toggle,
caller-provided peer list or fallback after a rejected profile.

## Peer and signed-operation agreement

The v3 state service uses this fixed mapping; v4 preserves it exactly, and the
reserve map is unchanged from v2:

| Kernel UID:GID | Transport purpose | Additional signed-operation restriction |
| --- | --- | --- |
| `65514:65514` | Reserve | `webauthn.registration.evidence.admit` |
| `65510:65510` | Reserve | `webauthn.registration.finalize` |
| `65515:65515` | Complete | `webauthn.registration.evidence.admit` |
| `65508:65508` | Complete | `webauthn.registration.finalize` |
| `65515:65515` or `65508:65508` | Query | Existing full shared nonce-bound observation; no operation filter |

The completion-operation restriction for `65515` starts **only with v3**. Its
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

## Separate v4 head-only observation

Only `65507:65507` can use `SWCHQR01` head queries under v4. It cannot reserve,
complete or use `SWCDQR01` legacy lookup. Conversely, no reserve or completion
peer can use the head-query purpose. The v4 service holds an exact nine-element
configuration selected by `_with_activation_planner`; its last element is the
fixed pair `(65507, 65507)`, not an arbitrary peer list.

`_head_on_configuration(config, *, query_bytes, deadline_ns)` uses the existing
admitted endpoint four-tuple and required absolute caller deadline. The source
root-created state listener has expected peer `0:0`, distinct from the state
service UID `65516`. The client admits that configured peer before sending;
the server admits the planner and the head purpose before reading the body.
Opaque query bytes are bounded to 4 KiB and `SWCHST01` observation bytes to 8 KiB
before allocation. Exact EOF, client half-close, bounded I/O, connection cleanup
and unchanged inherited deadlines apply. Neither framing nor socket access
authenticates the returned signature.

The service calls the actual [head owner](authority-current-root-head.md),
`CurrentRootDecisionOwner.observe_head`, with the
original query and deadline. That path signs its actual serialized current head,
joins the expected vector and nonce-bound activation context, and never falls
back to a retained receipt or legacy lookup. The caller must authenticate the
original observation and reject pending state for planning. This fresh
observation is not a lease: it does not make later planning/execution atomic,
consume a one-use decision or establish an off-host rollback witness.

## Remaining deployment and workflow work

Independently provisioned socket ACLs must permit each fixed primary identity,
including the planner's `65507`; these workers have no supplementary groups.
The state socket remains `65516:65516`, mode `0660`, so a bind mount or a new
root-signed peer field alone does not grant access. Listener ownership/mode and
signed inode checks are unchanged. Adding this source profile installs nothing and
does not grant production state, witness or signing authority.

The separate public finalization [reservation](public-registration-finalization-reservation.md),
[SQL](public-registration-finalization-sql.md) and
[completion/recovery](public-registration-finalization-completion.md) actions,
retained associations and corresponding portal controls are implemented in
source. OIDC session activation remains a separate authenticated transition;
its private planning/head admission does not complete protected execution,
token delivery or public activation. Neither SQL observations nor state
acknowledgments activate the session.

Expected frozen verification, **not run**, covers:

- Unchanged v1/v2/v3 behavior, exact v4 version/domain/field joins and rejection of
  mixed profiles, arbitrary peers and environment-based opt-ins.
- V3 cross-peer and cross-operation denial before both historical receipt
  return and new decisions, including the narrower `65515` completion scope.
- Completion/query denial for both reserve peers; genuine nonce-bound shared
  lookup for both completion peers without an operation-filter/currentness claim.
- V4-only planner/head admission; denial of every cross-purpose peer before
  bodies; exact head framing caps/EOF and genuine nonce/context/vector joins,
  without receipt fallback or a renewed deadline.
- Uncertain delivery, exact historical redelivery and actual durable state
  continuity without permission renewal or automatic retry.

Source review is not this evidence or production admission.
