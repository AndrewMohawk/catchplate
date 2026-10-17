# Fresh first release after completion recovery

The .213 source connects a distinct fresh RELEASE-purpose actor to first LIVE
token delivery after acknowledged consume completion. It does not reuse the
closed intent/proof-preparation actor, repeat completion or SQL, sign another
intent, contact proof setup, or recover an unknown previous release. This is
source-only integration, unbuilt, unexecuted and unprovisioned.

## Public boundary and actual owner

The fixed POST action is
`/api/auth/session/activation/consume/completion/recovery/release`; its separate
options endpoint appends `/options`. Both use the closed 64 KiB recovery carrier,
with no posted target, grant, root policy or token. The actual fresh actor checks
old-token possession, original-bound target, current roles/trust, Origin/CSRF,
WebAuthn and configured approval. Its signed request binding uses
`catchplate.oidcSessionActivationCompletionRecoveryDeliveryIntent/v1` and
`recoveryPurpose=release`, distinct from completion and intent/proof preparation.

The async route invokes the bounded synchronous core on the same ASGI thread.
This preserves original thread/work ownership; it is not a nonblocking-I/O or
throughput claim. One work object and clock window are opened before parsing
and owner I/O. The actual `_EnrollmentOwner` facade enters
`control_plane_oidc_session_activation_completion_recovery_delivery._acquire_on_owner`;
no successful permission DTO or copied token crosses the HTTP orchestrator.

## First-to-last source connection

1. The fresh `release` actor admits genuine historical controls. The owner reads
   either exact original completion raw4 plus hints raw2 or the separate retained
   consume reconciliation raw6, with exact authorization/packet/configuration
   association. A spent reconciliation without a usable response is terminal;
   this action never contacts the completion service again.
2. Genuine completion/ACK verification feeds the [signed input derivation](control-plane-oidc-session-activation-completion-recovery-intent-inputs.md).
   Existing [intent](control-plane-oidc-session-activation-completion-recovery-intent.md)
   and [proof](control-plane-oidc-session-activation-completion-recovery-proof.md)
   originals are re-admitted read-only. Missing originals cannot cause signing,
   setup or proof contact. The protected exchange requires them still current;
   original signed intervals and delivery expiry never renew.
3. Independent parent/root configuration selects the fixed LIVE issuer/client
   scope and endpoint. The [same consume-family acquisition slot](control-plane-oidc-session-activation-completion-recovery-release-records.md)
   is durably claimed **before issuer contact**. Any existing claim or grants
   refuses this delivery attempt. The first returned client/server raw2 is
   durably retained before semantic admission; lost replies cannot authorize
   another acquisition or grant reuse.
4. The [actual LIVE exchange](control-plane-oidc-session-activation-completion-recovery-delivery-exchange.md)
   independently re-derives request scope and admits root-signed client/server
   originals, exact custody and **LIVE/checkpoint zero**, with no recovery scope.
   Missing local records or canonical outcome reconstruction do not prove that
   private storage is empty. Actual worker checks can still refuse. The unchanged
   global client-authorization-digest claim precedes the sole protected socket;
   no release request/response, token or private outcome enters this journal.
5. The [public terminal response owner](control-plane-oidc-session-activation-completion-recovery-delivery-response.md)
   is selected before genuine receiving. `_response_on_active` owns exchange and
   fresh token-based current-auth matching the exact target. The actual narrowed
   receiver guard stays separate from its ancestors, avoiding a child guard
   cycle. The HTTP core calls the staged response's `finish()` only after both
   actor and delivery-owner normal cleanup; the terminal checks the exact body
   and cookie again at the final signed ASGI send boundary.

Successful public DATA uses
`catchplate.oidcSessionActivationCompletionRecoveryDeliveryResponse/v1`, purpose
`release`, status `released`, session state `active` and
`automaticRetryAllowed=false`, with no token or authority field in JSON. Only
genuine receiving and fresh current-auth can stage the cookie. Pre-send failures
preserve the existing cookie. After headers start, output may be externally
uncertain: no undo, delivery guarantee, second response or automatic retry is
promised. Staging or local persistence is not recipient acknowledgment.

## Same allowance and remaining boundary

An additional fixed 8 MiB exchange reservation is included before the first
historical target body, within the original combined 64 MiB allowance. Its 2 MiB
grant I/O slice and total raw2 ceiling of 128 KiB do not add a new budget; the
transport checks that response cap before allocating its bodies. Actual retained
representations, two genuine admission reservations, framing, claims and terminal
headroom must fit the same lane. The directly metered journal preserves the full
original current guard through native publication and normal-close readback.
These source bounds can refuse large valid inputs; they are not heap/RSS proof.

COMPLETE and step 23 remain partial. The existing post-intent RECOVERY path is
unchanged. The separate [.214 retained-release action](control-plane-oidc-session-activation-completion-recovery-retained-delivery.md)
connects independently authorized RECOVERY/checkpoint-one delivery for separately
reconciled completion; it is not fallback permission for this first-LIVE action.
This LIVE action cannot retry or switch profiles after an unknown result.
**Unattempted-consume recovery remains open.** Fresh intent changes evidence identity, and
absence or reconstruction establishes neither private-store existence nor
non-execution. Portal/resources and all production gates remain required.
Project **34/46**, activation **22/26** and production **0/6 verified** are
unchanged. No AWS execution, runtime token delivery or production acceptance is
claimed by this guide.
