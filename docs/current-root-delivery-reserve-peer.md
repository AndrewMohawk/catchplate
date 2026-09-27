# Current-root consume reservation peer

The explicit signed state-bootstrap v8 profile adds one purpose-specific
consume reserver. It does not widen generic grant or original-plan replay,
convert a sampled head into action authority, or provision a process, key,
listener, socket ACL or journal. This is source-only, unbuilt and unexecuted.

## Independently signed profile

[`current_root_state_bootstrap.py`](../serverware/current_root_state_bootstrap.py)
adds these closed schemas:

- `serverware.signedCurrentRootStateBootstrap/v8`;
- `serverware.currentRootStateBootstrap/v8`;
- `serverware.currentRootStateLaunch/v8`.

The v8 launch is exactly v7 plus `deliveryReservePeerUid` and
`deliveryReservePeerGid`, both fixed to **65499**. The actual state service
remains UID/GID 65516 with its existing five descriptors 198–202 and
`/run/serverware/current-root/state.sock`. The root-signed original enrollment,
independently supplied journal checkpoint, runtime closure, listener/path and
journal identity pins, original launch interval and false hardware/witness
flags retain their existing genuine admission. No descriptor or byte/work cap
is increased. The producer and verifier derive the exact v8 envelope/payload
domain from the v8 launch; adding these fields to v1–v7 is rejected.

[`current_root_state_startup.py`](../serverware/current_root_state_startup.py)
selects `CurrentRootDecisionService._with_delivery_reserver(owner=...,
timeout_seconds=...)` only after genuine v8 original admission. That factory
holds the actual durable decision owner and an exact source-fixed 13-element
configuration. It is not an arbitrary UID or operation allowlist. Existing
v1–v7 schemas, launch fields, peer purposes and constructor behavior remain
unchanged; v7 alone does not authorize the new reserver.

## Signed action before history or publication

[`authority_current_root_service.py`](../serverware/authority_current_root_service.py)
checks actual Unix peer credentials before reading the request prefix and
checks the fixed purpose before reading the body. Peer 65499 can use only the
existing reserve framing. It reaches the exact class method:

```text
CurrentRootDecisionOwner.apply(owner, original_request_bytes,
    expected_action="reserve",
    expected_operation="oidc.session.activation-delivery.consume",
    transport_deadline_ns=original_deadline)
```

The service passes original signed bytes, not parsed claims or a successful
computation result. The existing owner genuinely authenticates the enrolled
computation signature, then compares both signed action and operation **before**
historical receipt lookup or new publication. A valid signature for another
operation, completion control or purpose cannot obtain a receipt through this
peer. Unknown framing and wrong peer/purpose combinations fail before body
admission. Peer 65499 has no lookup, complete, activation-head or consume-head
access. The consume planner at 65501 remains consume-head-only, and the
activation planner at 65507 remains activation-head-only.

## Actual state transition and first-exact ACK

The unchanged
[`CurrentRootDecisionOwner`](../serverware/authority_current_root_decisions.py)
is the only state transition and receipt signer on this path. For a new
reservation, under its real lock and process/readiness guards it requires:

- no existing pending decision and space for the later completion record;
- an unused operation identity and grant/capability commitment;
- the exact independent predecessor sequence/head and next fence;
- the complete before-vector equal to its current owned vector, with the
  authenticated after-vector satisfying the existing source delta contract.

The existing current-root authorization already has the consume operation in
its source-derived vector/control grammar. This batch does not change that
grammar or supply a bypass around genuine consume computation. The dedicated
consume producer must admit caller/grant originals and independently replay
the original consume plan/effects before using the enrolled computation key.
A state signature authenticates that enrolled producer's assertion; it is not
independent proof that state replayed the encrypted plan or that SQL executed.
The generic seven-family replay and grant inventory remain closed.

The owner derives and signs the actual receipt, appends its exact signed
request/receipt record through the existing durable journal, and accepts the
new pending state before returning the ACK. Failure during publication poisons
the owner/journal rather than asserting rollback. A repeated exact authenticated
request can return only its retained exact receipt; a conflicting original
cannot reuse the identity. Such explicit receipt recovery does not renew the
old control's interval or prove that a pending head is current now.

Transport keeps the original inherited deadline. The state owner uses its
existing single request work/window, clips it to that deadline, and checks
liveness around admission, signing, publication and return. No new service
parser, work allowance, retry loop or history bypass is introduced. Failure
after a durable write or send is still an uncertain delivery outcome.

Independently current pending admission, protected one-use consume SQL,
completion/reconciliation and exact committed-original plaintext release
remain separate requirements. A reserve ACK or fresh head observation alone
does not authorize any of them. Host-local root assertions and fsync do not
establish off-host rollback resistance or production acceptance.
