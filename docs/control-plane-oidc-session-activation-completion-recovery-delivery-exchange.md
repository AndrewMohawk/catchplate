# Fresh completion-recovery LIVE exchange

`serverware/control_plane_oidc_session_activation_completion_recovery_delivery_exchange.py`
connects the actual fresh release-purpose owner to one protected LIVE exchange.
It accepts no posted target, successful material, raw request or permission DTO.
It does not revive `_ActivationPermission`, sign an intent, contact proof setup,
retry SQL, probe private storage or fall back to RECOVERY.

## Original source association

`_exchange_on_active(active, *, _delivery=None)` requires the exact active
`_DeliveryAttempt`, with its exchange latch already spent and in progress.
The original actor has purpose `release`, separate from the closed
`release-intent-proof` preparation actor. Its controls, genuinely verified raw6
completion response, sealed input/intent/proof continuations, retained raw2
grants, old-token possession, cold configuration, work and lifetime must agree.
The same fixed parent handoff client ID, identity and LIVE endpoint are used;
the older static `release_client` carrier is not substituted.

The `.228` caller retains two independently selected evidence authorities: R0
for the original activation and R1 for consume completion. The actor's exact
pre-permission consume selection must match the controls, and its selected
pending/packet/authorization pins enter the unchanged reconciliation identity.
Current parent enablement and transport endpoints remain separate. Intent,
proof, client and server signatures still use current R2; an old evidence root
is never substituted for the current grant root or policy.

The optional public terminal is exactly `_StagedRecoveryResponse` from
`control_plane_oidc_session_activation_completion_recovery_delivery_response`.
Its actual owner association selects the terminal ancestor **before** any new
LIVE admission. New intent, proof, client/server and receiving guards use this
original ancestor. No ordinary closed actor, input or preparation guard is
revived. Without that terminal, the continuation remains live-context-only.

## Independent current admission

The existing intent and proof are genuinely re-admitted as current, with the
independent root, enrollments, key-separation rules, scope, expected release,
old-token possession and completion receipt. Expired originals refuse; their
intervals and original delivery expiry are never renewed. Hints are compared to
the genuine signed release expectations, not accepted as execution authority.

Those authenticated fields reconstruct the canonical outcome digest and raw7
`(LIVE purpose, proof, proof enrollment, intent, intent enrollment, old64,
encrypted envelope)`. The expected client scope is independently derived from
these originals and the parent's static client/endpoint pins. It is not copied
from the candidate client or server payload.

Actual root-signed client/server admission must select **LIVE/checkpoint zero**.
Recovery scope must be absent. The server custody original must byte-match the
retained proof's custody, and its genuine planner, target, intent, configuration,
delivery and storage bindings must match the independently derived expectations.
The same current admission supplies that custody material; no successful DTO is
accepted in its place. Its launch restriction is retained and only narrows the
original processing window.

The caller also genuinely re-admits the selected R1 consume state enrollment
and the server planner's R2 enrollment, requiring equality of their complete
payloads and the independently expected database/generation. The exact current
planner and custody original, including their delivery-key joins, are preserved.
The genuine proof-v2/grant path supplies the original R0/R1-to-current-R2 bridge;
this is not a state or delivery-key migration. Retired-RI intent/proof originals
remain refused. This LIVE action neither chooses nor enables historical
`retained-release`/RECOVERY authority.

Canonical outcome reconstruction is a request binding, **not proof that private
storage is empty or absent**. Missing local records cannot authorize LIVE,
select a checkpoint, or trigger a RECOVERY fallback. Actual worker-side store
checks remain separate and can refuse the independently authorized request.

## Irreversible claim, transport and receiving

Before the only protected socket, the directly metered custody method claims
the existing global client-authorization-digest slot. It persists only five
scalar bindings: client authorization, request identity, LIVE profile, server
bootstrap and expected outcome digests. Old or recovered duplicate claims are
terminal. Neither raw7, old/new token nor response is journaled here.

The fixed transport returns only after normal close. The actual response
verifier then re-admits the original client/server/intent/proof, checks the
request identity and exact token commitment, and retains its full genuine guard.
That child is kept separately by the active owner and, when selected, the public
terminal; it is never attached back into its own ancestor. Only the actual owner
receives token64. Public current-auth, normal cleanup and the final signed
cookie-send boundary belong to the separate terminal, not to this return value.

## Original capacity

The owner reserves `EXCHANGE_RESERVATION_BYTES` (8 MiB) exactly once before its
first historical target body. Grant acquisition has a temporary 2 MiB I/O slice
inside it and a 128 KiB total raw2 response ceiling. The helper rejects larger
retained grants before fresh admission. Its hint captures, raw8 request, raw2
response copies, framing and temporary journal I/O are preflighted before hint
decode, journal body reads or issuer contact. Actual request lengths must match
that fixed preallocation.

Before decoding LIVE authority or contacting the protected worker, actual
request/client/server lengths feed two genuine receiving reservation formulas.
They cover the retained pre-contact admission plus the final response admission;
fixed hint/cold-identity, raw2-copy, claim, framing and 256 KiB public-terminal
headroom and both state-enrollment captures are also included. Their sum must
fit that same 8 MiB lane, and the
already-held whole-call reservation plus this actual usage must fit 64 MiB.
The claim receives only its separately reserved I/O capacity and charges the
same work directly. No new ledger or transport allowance is opened.

Larger otherwise valid originals may fail closed. These are conservative byte
representation bounds, not Python heap/RSS guarantees. This is source-only,
unbuilt, unexecuted and unprovisioned; no runtime token delivery is claimed.
