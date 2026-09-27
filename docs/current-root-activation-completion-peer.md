# Current-root activation completion peer

The `.156` state profile adds a dedicated activation completion/lookup peer to
the actual current-root service. This is **source-only, unbuilt, unexecuted and
uninstalled**. Neither the signed profile nor the templates provision socket
access or demonstrate a running state owner.

## Explicit v6 opt-in

[`current_root_state_bootstrap.py`](../serverware/current_root_state_bootstrap.py)
defines the closed schemas `serverware.signedCurrentRootStateBootstrap/v6`,
`serverware.currentRootStateBootstrap/v6` and
`serverware.currentRootStateLaunch/v6`. The v6 launch adds exactly
`activationCompletePeerUid` and `activationCompletePeerGid`, both fixed to
**65503**, to the v5 launch shape. Root signature, enrollment, checkpoint,
resource identity, lifetime and existing purpose pins remain required.

[`current_root_state_startup.py`](../serverware/current_root_state_startup.py)
selects `CurrentRootDecisionService._with_activation_completion` only for the
genuinely admitted v6 launch. The v1–v5 schemas, dispatch branches and admitted
peer inventories are unchanged; none silently acquires UID 65503. V6 preserves
the existing peers while adding only this fixed purpose.

## Peer and signed-purpose restrictions

[`authority_current_root_service.py`](../serverware/authority_current_root_service.py)
checks kernel peer credentials before reading the request prefix. For peer
65503:65503, only these branches are admitted:

| Request | Actual owner call and restriction |
| --- | --- |
| Complete | `apply(..., expected_action="complete", expected_operation="oidc.session.activate")` |
| Lookup | `lookup(..., expected_operation="oidc.session.activate", expected_request_action="complete")` |

The peer cannot reserve or obtain planner head observations. UID 65505 retains
its separate activation-reserve purpose and UID 65507 its head-only purpose.
The exact owner class performs original verification; the service does not
substitute a transport verdict, caller callback or returned data object for it.
Framing and all owner work receive the existing bounded transport deadline.

The actual state process remains UID/GID **65516**, at
`/run/serverware/current-root/state.sock`; the inherited root-created listener
has kernel peer **0:0** for the client. Filesystem access and signed peer admission
are different requirements. The state socket's provisioned permissions/ACL must
separately admit the completion worker without broadening unrelated access.
The source templates do not install that ACL or the v6 bootstrap.

## Known receipt filtering and uncertainty

[`CurrentRootDecisionOwner`](../serverware/authority_current_root_decisions.py)
authenticates the signed control and checks its requested action/operation before
either returning a historical receipt or publishing a new completion decision.
Ordinary state transition, pending, fence, capacity and durable journal checks
remain in the actual owner; v6 does not add an execution bypass.

For a known lookup digest, the owner genuinely re-verifies the retained original
signed request, joins its digest to the query, then requires operation
`oidc.session.activate` and action `complete`. A receipt belonging to another
operation or a reservation is rejected, not returned merely because its digest
is known. Successful lookup returns the exact historical receipt inside a fresh
signed state observation; it does not renew the receipt's execution lifetime.

For an unknown digest, `notRecorded` describes only the admitted owner's locked
retained history at observation time. It is **not proof that SQL did not commit**,
that completion was never published elsewhere, or that retry/reset is safe.
It grants no permission to clear pending state, choose an older checkpoint,
regenerate a control, reserve again or repeat SQL. Failures can occur after
durable publication, and no service error frame masquerades as a receipt.

The [cold completion service](oidc-session-activation-completion-service.md)
uses this peer for first-exact completion delivery and explicit historical
reconciliation. The consumer must retain its own independent packet, pending,
configuration and enrollment expectations and genuinely verify returned originals.
The state observation establishes neither current browser authentication nor
token-release/public-action permission. No off-host currentness, rollback
resistance, hostile-root protection or production acceptance is claimed.
