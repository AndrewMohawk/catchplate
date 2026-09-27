# Current-root consume completion peer

The explicit state v9 profile adds only consume completion and purpose-filtered
lookup for UID/GID **65497**. This is source-only, unbuilt, unexecuted and
uninstalled; neither signed configuration nor templates provision socket access
or demonstrate a running state owner.

[`current_root_state_bootstrap.py`](../serverware/current_root_state_bootstrap.py)
defines `serverware.signedCurrentRootStateBootstrap/v9`,
`serverware.currentRootStateBootstrap/v9` and `serverware.currentRootStateLaunch/v9`.
V9 extends the exact v8 launch with `deliveryCompletePeerUid` and
`deliveryCompletePeerGid`, both fixed to 65497. Root signature, enrollment,
independent checkpoint, resource identity, original launch lifetime and every
existing purpose pin remain required. V1–v8 retain their exact schemas and peers.

The actual [startup](../serverware/current_root_state_startup.py) selects
`CurrentRootDecisionService._with_delivery_completion` only after genuine v9
admission. Its exact fourteen-item internal profile extends v8; no caller
supplies an arbitrary operation profile. The [service](../serverware/authority_current_root_service.py)
checks kernel peers before the request prefix and the peer's fixed purpose before
the body. Peer 65497:65497 may reach only these actual owner calls:

| Request | Original-purpose restriction |
| --- | --- |
| Complete | `apply(..., expected_action="complete", expected_operation="oidc.session.activation-delivery.consume")` |
| Lookup | `lookup(..., expected_operation="oidc.session.activation-delivery.consume", expected_request_action="complete")` |

The literal operation is the genuine consume computation/completion operation,
not activation or a token-release operation. This peer cannot reserve, request
either planner head protocol or retrieve known controls for another operation.
Consume reserver 65499, consume planner 65501 and every older peer remain separate.

The unchanged [durable decision owner](../serverware/authority_current_root_decisions.py)
authenticates action and operation before historical receipt return or new
publication. Its existing pending, vector, fence, capacity, signature and durable
journal checks still apply. A known lookup digest causes genuine verification of
the retained signed original, including its exact identity, `complete` action and
consume operation. A reserve or other operation is rejected, not returned simply
because its digest is known. Exact historical receipts inside a fresh observation
do not renew their original authority.

Unknown `notRecorded` means only that the locked retained history did not contain
that digest. It is not proof of SQL noncommit or absence of publication elsewhere,
and permits no reset, replacement, resigning, older checkpoint, new reservation
or SQL retry. Publication or transport failure may follow a durable write; no
error frame substitutes for an acknowledgment.

State remains UID/GID 65516 at `/run/serverware/current-root/state.sock`, with an
inherited root-created listener whose client-visible kernel peer is 0:0. The
provisioner must independently install v9 and narrowly grant filesystem socket
access to 65497. This source does not install an ACL or grant a public application
completion keys. The [private completion transport](oidc-session-activation-delivery-completion-transport.md)
is a different socket and requires genuine receiving-side original verification.
No current session, plaintext release, public handoff or production acceptance is
established by this peer profile.
