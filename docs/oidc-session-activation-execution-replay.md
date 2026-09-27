# Private activation execution-original replay

`authority_oidc_session_activation_execution_replay._replay_on_work` remains the
source-only original-replay adapter. Its earlier adapter-only checkpoint is now
connected to generic activation dispatch through the actual
[receiving custody owner](oidc-session-activation-execution-custody.md). The
generic branch requires that exact process-bound owner, the caller's original
live window and inherited deadline; a supplied successful result cannot replace
them. The adapter itself does not issue a grant, reserve state, invoke SQL or
release a token. This connection is not deployed or end-to-end verified service
composition.

The keyword-only inputs are the original signed `envelope_bytes` and
`encrypted_originals_bytes`; independently expected request, fifteen-field
scope and journal digest; actual planner and state-root public keys; original
state enrollment and complete before-vector; distinct private bundle and
delivery keys; and the existing live window, absolute deadline and shared work.
Nothing accepts a successful verification object or learns independent scope
from decrypted storage. The outer original inventory, including enrollment and
vector, must fit the existing 64 MiB aggregate. No allowance or clock window is
created or renewed. A stricter processing age/skew is permitted without changing
the independently admitted original policy or signed scope; the owner's window
helper only narrows the unchanged opening and deadline.

The adapter first owns all external graphs, keys and original bytes. It checks
the genuine typed request commitment, original policy/deadline and known plan
signature/key/request/configuration bindings **before decryption**. It derives
the exact seven-field bundle context from those independent inputs and the
authenticated original plan identity. The actual
[bundle codec](oidc-session-activation-execution-bundle.md) opens only that
scope, after which the journal-v2 decoder and exact byte comparisons join the
stored request, scope, plan, enrollment and vector to the held originals.

Raw read records are restored through the existing bounded helper. The actual
plan `_verify_full_on_work` then runs full signature, assertion, complete-read,
business-transition, audit-capacity, indexed-write and state-observation replay
once. Stored primary roots and thirteen heads are not adopted as authority:
passing them as replay expectations does not establish their provenance. They
gain independent binding only when the real verifier projects the independently
supplied complete vector, compares those roots and heads, and authenticates the
original matching state observation.

The adapter merges only that same-call replay's actual after-roots and thirteen
after-heads into the independently held complete vector. It uses the existing
generic merge, canonical vector encoding and delta validation. The original
window, inherited bound, assertion/session/delivery lifetimes, state observation
expiry and signed-plan expiry remain checked through final output creation.

The return is the existing ordinary `_ReplayedPlan`: bounded copied request,
result, selected rows, mutations and work total; complete before/after vector
bytes and identities; original signed-plan interval and identity; and a distinct
`serverware.oidcSessionActivationExecutionOriginalsIdentity/v1` framed record ID.
Its original inventory is **raw2: signed plan plus bundle ciphertext only**.
Neither decrypted journal bytes, raw tokens nor either private key is included.
The revocation-only signed snapshot/capability fields remain `None`.

This API is live-only. It cannot recover expired activation plans by changing
the clock, refreshing an observation or bypassing original freshness. A matching
journal digest/bundle proves neither durable export nor independent custody.
The [durable first-exact sender exporter](oidc-session-activation-execution-export.md)
and [root-authenticated receiving owner](oidc-session-activation-execution-custody.md)
are now separate implemented source paths. The **grant** receiver now connects
its [root-admitted bootstrap](oidc-session-activation-execution-authorizer-bootstrap.md),
[private key/FD delivery](oidc-session-activation-execution-authorizer-delivery.md)
and actual service to [genuine caller authorization and grant production](oidc-session-activation-execution-authorization.md).
This is unbuilt/unexecuted source, not a production grant-delivery result.
Dedicated **reserve/SQL** receiving delivery and service composition, the public
caller's purpose/key lifecycle and present permission, and end-to-end one-use
protected execution remain open. A connected grant role does not close the
full grant/reserve/pending/packet/SQL workflow or its production acceptance.
Completion entrypoints explicitly reject activation: recovery needs genuine
historical admission, not this API relabelled as recovery. Completion/history,
public recovery and protected token release remain separate work.

Planned frozen verification, **not run**: reject wrong keys/context/original
inventory; authenticate the known signature before bundle opening; reject any
stored-original substitution; reconstruct exact full vectors/effects; retain
all original bounds through late failure; and confirm only encrypted raw2
originals enter generic packet framing. No tests, imports or runtime
verification were performed for this source slice.
