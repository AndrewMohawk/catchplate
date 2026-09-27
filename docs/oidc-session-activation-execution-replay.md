# Private activation execution-original replay

`authority_oidc_session_activation_execution_replay._replay_on_work` is a
source-only receiving adapter. It does not register a generic replay family,
issue a grant, reserve state, invoke SQL, admit a custody owner or release a
token. Existing generic execution paths remain fail-closed until their complete
family/packet/custody integration is implemented.

The keyword-only inputs are the original signed `envelope_bytes` and
`encrypted_originals_bytes`; independently expected request, fifteen-field
scope and journal digest; actual planner and state-root public keys; original
state enrollment and complete before-vector; distinct private bundle and
delivery keys; and the existing live window, absolute deadline and shared work.
Nothing accepts a successful verification object or learns independent scope
from decrypted storage. The outer original inventory, including enrollment and
vector, must fit the existing 64 MiB aggregate. No allowance or clock window is
created or renewed.

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
Cold private-key provenance, exact durable export, public permission, generic
grant/reserve/packet integration, action-time currentness and one-use protected
execution remain separate. Completion/recovery needs genuine historical
admission, not this API relabelled as recovery.

Planned frozen verification, **not run**: reject wrong keys/context/original
inventory; authenticate the known signature before bundle opening; reject any
stored-original substitution; reconstruct exact full vectors/effects; retain
all original bounds through late failure; and confirm only encrypted raw2
originals can reach future SQL packet framing. No tests, imports or runtime
verification were performed for this source slice.
