# Dedicated activation reserver service

`oidc_session_activation_execution_reserver_startup` implements the fixed cold
`initialize_from_environment`, `require_started().serve_once()` and `close`
lifecycle. This is source-only: no build, execution, deployment, external ACL,
key provisioning or production acceptance has been performed.

The actual [delivery profile](oidc-session-activation-execution-reserver-delivery.md)
fixes UID/GID 65505, request peer 65532, the literal eight-variable environment,
and descriptors 198–205: root, bootstrap, listener, receiving-custody original,
bundle key, delivery key, computation key and private reservation journal.
The root-signed [bootstrap](oidc-session-activation-execution-reserver-bootstrap.md)
is genuinely admitted before key loading or protected owner construction.
The actual receiving owner has only the `reserve` consumer purpose; a grant
owner or caller-constructed material cannot substitute.

The service constructs the real independently locked `CurrentRootJournal` and
`OidcSessionActivationReservationDelivery`. Original enrollment and bounded
record recovery consume the supplied construction work/window, and recovery
must match the separately admitted local journal checkpoint. A root-created
state listener has kernel peer 0:0; state service UID/GID 65516 is a distinct
admitted deployment identity, not the client peer value.

## One explicit exchange

1. Open one request work/window before peer or body intake; retain the original
   launch bound and immutable descriptor/process/owner configuration.
2. Admit the fixed peer, receive bounded raw5, and decode its canonical closed
   expectations. Incoming policy can only narrow the existing clock bracket.
   Reverify the original root bootstrap/custody with that same work/window.
3. Genuinely authenticate original post-plan caller and grant authority, retain
   their live checker and derive a bounded local framed identity from exact
   raw5. This identity is an association, not execution permission.
4. Look up that exact local identity before signing. New input uses the actual
   [reserve producer](oidc-session-activation-reservation.md); a retained input
   undergoes full genuine original replay without generating a new request.
5. Clip the unchanged opening bracket and inherited deadline to the actual
   signed reserve expiry. Durably retain exact request/snapshot before one
   explicit state exchange; verify and durably retain its exact ACK before
   returning unchanged raw3. Compare response bytes with the first durable
   originals and recheck original time/scope through response transmission.

The [wire protocol](oidc-session-activation-reservation-transport.md) has no
plaintext token/key output and no error frame that claims nonpublication.
An accepted connection spends this launch even on rejection, timeout or
uncertain response delivery. There is no automatic retry or re-signing. A
separately admitted later launch may explicitly recover the unchanged retained
request while all required original live authority remains valid; it cannot
renew an expired plan, caller authorization, grant or reserve.

The singleton continually checks PID, UID/GID, empty supplementary groups,
literal environment, sealed originals, listener/journal identities, actual
custody/configuration, journal continuity, exact descriptor inventory and
nonregressing epoch/monotonic samples. Cleanup closes the accepted connection,
duplicate listener, journal-owned independent descriptor, actual receiving
owner and all eight adopted inherited descriptors. Failed construction also
closes resources already acquired; it cannot restart admission in the PID.

## Deliberately separate

The signed ACK is not independently current pending authority. The source
pending-admission API exists, but no cold SQL-issuer consumer calls it here.
Actual independent pending scope, SQL one-use orchestration, completion and
reconciliation, protected token release, public permission and portal actions
remain separate. No successful DTO, historical expiry bypass, implicit state
advance, session activation claim or broader state-peer permission is added.

This service still requires independently provisioned keys/directories, state
v5 and its narrow socket ACL, trusted runtime delivery and external syscall
timeout containment. Source admission does not establish those facts.
