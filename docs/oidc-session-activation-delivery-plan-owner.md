# Stateless delivery-consumption plan owner

This `.158` source connects the actual
[read-acquisition owner](oidc-session-activation-delivery-planning.md), original
write-proof codec and [consume-plan producer](oidc-session-activation-delivery-plan.md).
It is unbuilt and unexecuted. It neither writes a journal nor grants execution,
consumes a delivery, releases a token or returns a purported retained locator.

`OidcSessionActivationDeliveryPlanOwner` holds the exact real reader/configuration,
configured Ed25519 signer and independent identity/SPKI/configuration/policy pins,
original state enrollment/root/vector, actual historical custody owner, activation
planner/operation keys and canonical independently supplied activation expectations
and pending/authorization scope. It verifies the original enrollment, root/key
joins and current historical-custody bounds; it does not invent cold admission for
the supplied current policy or consume signing key.

`prepare` accepts the typed consume request, original old token, six independent
delivery/subject IDs, primary roots/seven heads, original head query/observation
and the exact thirteen activation-completion originals. Inputs are captured before
callbacks. Actual state signature/pending/vector projection precedes read-only
acquisition. The real transition derives three effects and actual acquisition
returns five write frontiers. The signed-plan producer then independently replays
the original state, completed-activation provenance and indexed effects; neither
an acquisition result nor a claimed completion is accepted instead.

The same supplied work, original clock samples and inherited deadline cover the
whole composition. Historical custody can only narrow current processing bounds;
an old plan's expiry never becomes the processing clock. Exact class/PID/configuration
and nonblocking locks remain checked, and final serialization/plan-digest creation
must finish within the actual signed plan and head-observation expiry.

`PreparedDeliveryPlan` contains only immutable `request_bytes`, `scope_bytes`,
`envelope_bytes` and `plan_digest`. No token, AES key, proof-success capability,
new token, encrypted journal record or durable locator is returned. `close()`
drops same-process configuration references; it does not claim memory erasure.

The registry's `plan_factory` now constructs this real owner rather than a stub;
its legacy `kernel_factory` remains absent. This is reusable private composition,
not an installed consume service. In particular, the existing historical custody
owner remains tied to its real completion process at UID 65503. The distinct
head requester at UID 65501 is not relabeled or given cross-process custody by
this factory. A new independently root-admitted consume-planner historical-custody
purpose/connection is still needed before cold UID 65501 service composition.
Durable original retention, purpose authorization/reservation, protected SQL,
original commit admission, one-use release, recovery and public/portal handoff
remain open. No tests, runtime, provisioning or deployment were performed.
