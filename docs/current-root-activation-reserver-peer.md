# Explicit activation reserver at the current-root state service

The source-only v5 profile admits the dedicated activation reserver
`65505:65505` for **reserve** requests whose authenticated operation is
`oidc.session.activate`. This is a separate root-signed opt-in, not an extension
of a registration peer or of the planner's head-observation permission.
No service, socket ACL or key has been provisioned; this source is unbuilt and
unexecuted.

## Closed original profile

The original envelope, payload and launch must use the matching schemas
`serverware.signedCurrentRootStateBootstrap/v5`,
`serverware.currentRootStateBootstrap/v5` and
`serverware.currentRootStateLaunch/v5`. The root signature uses the distinct
v5 envelope domain. V5 retains the exact v4 launch fields and adds only
`activationReservePeerUid: 65505` and `activationReservePeerGid: 65505`.
Mixed versions, extra fields and caller-selected peer identities fail closed.

The existing `_produce_on_work` signs this profile only from its closed launch;
`_admit_on_work` verifies the canonical original, root signature, enrollment,
independently supplied checkpoint, finite original lifetime and all five false
hardware/TEE/witness assurance flags. State remains trusted-host-local. There
is no new descriptor, key, journal, listener or environment opt-in: state runs
as `65516:65516` with the same five FDs `198..202` and fixed
`/run/serverware/current-root/state.sock`.

Root delivery and nonroot startup each admit the actual original. Only the
admitted v5 launch selects
`CurrentRootDecisionService._with_activation_reserver(*, owner, timeout_seconds)`.
Its exact ten-element configuration retains the v4 nine-element prefix and
appends `(65505, 65505)`; it is not an arbitrary peer-list API. V1–v4 keep their
prior profiles and do not admit the activation reserver.

## Purpose and operation checks

| V5 peer UID:GID | Permitted transport purpose | Signed operation restriction |
| --- | --- | --- |
| `65505:65505` | Reserve | `oidc.session.activate` |
| `65507:65507` | Separate head query only | Existing nonce/context/vector-bound activation head protocol |
| `65514:65514` | Reserve | `webauthn.registration.evidence.admit` |
| `65510:65510` | Reserve | `webauthn.registration.finalize` |
| `65515:65515` | Complete; existing lookup | Complete remains evidence-only; lookup is the existing shared observation |
| `65508:65508` | Complete; existing lookup | Complete remains finalization-only; lookup is the existing shared observation |

Kernel peer admission precedes the prefix; purpose admission precedes the
request body. The activation reserver cannot complete, use legacy lookup or
query the head. The planner cannot reserve, complete or use legacy lookup.
Other reserve peers cannot submit activation operations under v5. The earlier
[v1–v4 restrictions](current-root-finalization-peer.md) remain unchanged.

For the new peer the service passes the bounded original request and inherited
absolute deadline directly to the genuine owner's `apply`, with
`expected_action="reserve"` and `expected_operation="oidc.session.activate"`.
The owner authenticates the original request and compares both restrictions
**before** any historical receipt return or new durable decision. The service
does not parse a successful claim, choose a substitute verifier or open another
work allowance. Actual predecessor/fence, complete-vector, operation/capability
uniqueness, enrolled computation signature and pending-capacity checks still
belong to the real decision owner.

## Boundaries and remaining acceptance

Expiry or an uncertain response never clears pending state. An explicit exact
historical request may obtain its existing receipt, but cannot renew execution
authority or establish currentness. The separate
[head observation](authority-current-root-head.md) is neither reserve authority
nor an off-host rollback witness. This state profile does not perform SQL,
release a token or activate a browser session.

An independent provisioner must supply the matching v5 original and state
checkpoint, and grant this fixed primary UID/GID socket access. The socket
remains `65516:65516`, mode `0660`; these workers have no supplementary groups.
Adding a field, bind mount or source file grants no filesystem access and does
not widen an installed ACL. Dedicated reserver delivery/computation, protected
SQL, completion and the separate public activation workflow require their own
authority and integration.

Deferred frozen verification must cover v1–v4 equivalence, exact v5
schema/domain/field matching, rejection of every cross-purpose peer before the
body, and signed action/operation denial before both historical return and
publication. It must also exercise original deadline retention and uncertain
delivery without rollback, permission renewal or automatic resend. No such
runtime evidence is claimed here.
