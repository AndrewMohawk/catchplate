# Consume reservation retention and explicit delivery

This is source-only implementation. No journal, state endpoint, key, account or
service has been provisioned, and no runtime reservation is demonstrated.

`OidcSessionActivationDeliveryReservationDelivery` is the fourth exact
source-owned reservation delivery class. It selects only the consume record
profile; callers cannot inject a codec, operation or owner subclass. The three
older profiles keep their existing schemas, operations and behavior.

Construction takes the actual separate `CurrentRootJournal`, original root
enrollment and independently held local sequence/head checkpoint. The caller's
existing work, processing window and absolute deadline are mandatory throughout
enrollment, local recovery and explicit delivery. A recovered prefix proves its
local signed history, not that it is the independently current prefix.

The owner retains exact signed reserve and canonical snapshot originals before
one explicit state exchange. It authenticates the original state acknowledgment
and durably retains it before returning. It does not decrypt the consume bundle
or replace genuine caller/grant/plan replay. The execution-record digest is a
local association only, never execution permission.

An unresolved request blocks a new request. Network or response-verification
uncertainty preserves pending state; uncertain local publication poisons and
closes the owner. There is no automatic resend, replacement request, re-signing,
pending clear, refreshed authority or SQL retry. A separately admitted explicit
same-original recovery can retrieve an already accepted receipt; it cannot
make an expired, previously unaccepted request valid or revive execution.

The state peer requires the explicit
[v8 consume-reserve profile](current-root-delivery-reserve-peer.md). Its real
decision owner authenticates the signed computation and atomically compares
predecessor, fence and complete root vector before durable acceptance. A prior
consume-head observation is not reservation authority.

The returned ACK proves a signed reservation event, not an independently current
pending head. The separate consume pending receiver must reauthenticate actual
originals and compare independently held database/generation, predecessor,
pending sequence/head and fence. The [cold reserver service](oidc-session-activation-delivery-execution-reserver-service.md)
now composes this delivery owner with actual receiving custody and fixed OS
resources. The actual cold SQL pending consumer still requires integration;
its [root bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md)
is only a prerequisite. Token-release row 12 remains in progress. One-use SQL,
completion/recovery and plaintext release remain separate unfinished work.
