# Same-permission protected release handoff

`control_plane_oidc_session_activation_release_handoff.py` composes the existing
live release worker and genuine response verifier on the actual active
activation permission. It does not acquire root grants, renew an allowance,
accept a successful admission object, select recovery, or set an HTTP cookie.

Its source-private API is:

```text
_release_on_permission(permission, *,
    client_authorization_bytes, server_bootstrap_bytes) -> token64
```

The only supplied inputs besides the actual permission are two original public
root-control byte strings. The permission must already have its exact retained
intent, acknowledged consume completion, proof originals/context and original
old-token possession, and must be in the source-selected
`release-handoff-requesting` phase with its one-use latch spent. No caller can
provide a target, expected outcome, signing key, old-token substitute, work
ledger, clock window, or deadline to this continuation.

## Static pins and incoming originals

The separately admitted [v11 static handoff configuration](control-plane-oidc-session-activation-release-handoff-bootstrap.md)
provides immutable `_ReleaseHandoffMaterial(client_id, client_identity_bytes,
endpoint_bytes)`. Its canonical decoding helpers return the root-held identity3
and endpoint4. Existing genuine intent and proof configurations remain required;
the older `release_client` configuration is not reused or widened.

Before fresh grant admission or any socket, the exact incoming raw2 tuple
`(client_authorization_bytes, server_bootstrap_bytes)` is durably appended as
`release-grants`, bound to the same finalization and activation authorization
identities. This is original retention, not proof that either grant is valid.
It contains no old token, returned token, request frames or response frames.
The bounded original inventory also reserves the derived request, response,
scope and outcome work before their allocations.

Every stage retains the actual parent/configuration/root binding, purpose
configurations, original target, possession and prior proof context. Current
checks use that context's actual original work and processing bounds. Each
additional genuine admission may only narrow those bounds; there is no new
construction window, independent allowance, backdated clock or retry authority.
The inner intent/proof/receiver continuity hooks remain connected to the same
permission's observed clock floors.

## Derive expectations before admitting fresh grants

The continuation reauthenticates actual originals, rather than trusting cached
successful results or unsigned SQL observations:

1. It admits the retained proof enrollment against the independently configured
   scope/key and purpose exclusions, joining the actual parent configuration.
2. It verifies the original consume reservation/ACK using the independently
   root-pinned predecessor, then the signed COMPLETE and state ACK. Pending,
   fence, request, complete identity and after-vector commitments must agree.
3. It admits the signed intent and original enrollment with the same old-token
   possession, expected target and current allowance.
4. It admits the original release custody returned alongside the proof, joining
   the exact original activation planner, intent digest, target, receiver and
   configuration/generation/runtime cohort.
5. It verifies the proof signature, enrollment, expected release and independently
   derived custody/intent/state-receipt evidence. Retained completion hints then
   supply ciphertext only after their packet/effects/time/envelope commitments
   match those authenticated originals.

This public-key-only receiving composition does not take historical AES custody
or repeat the private worker's committed-original replay. That worker's genuine
proof is admitted through its separate enrolled signature and exact independent
expectations; a proof-shaped DTO is not accepted as authority.

The exact outcome record is deterministically encoded from the admitted proof,
release target, custody/intent/state evidence, original enrollment identities
and caller. Its domain-framed identity becomes the independently expected
outcome, not a returned token or server-supplied success claim.

The live raw7 request is exactly:

```text
(LIVE_PURPOSE, proof, proof_enrollment, intent, intent_enrollment,
 old_token64, encrypted_delivery_envelope)
```

Its request identity is computed over those exact originals. The complete
expected client scope17 is derived before admission of the fresh client/server
originals: `serverBootstrapDigest`, `profile`, `requestIdentity`,
`configurationDigest`, `databaseId`, `generationDigest`, `runtimeClosureDigest`,
`clientId`, `clientIdentity`, `callerId`, `receiverIdentity`, `producerId`,
`producerIdentity`, `stateReceiptDigest`, `expectedRelease`,
`expectedOutcomeDigest`, and `endpoint`. Static identity/endpoint pins come
from v11; cohort/producer/receiver pins and target/evidence come from the actual
independently admitted context, not from the incoming client authorization.

The fresh client verifier genuinely authenticates both root originals against
this scope. It must select the fixed LIVE profile, never recovery. Its server
custody bytes must exactly equal the original retained with the proof, and the
actual storage authorization must bind that same custody identity. Returned
processing bounds must preserve the original first three clock samples and
only tighten every ceiling.

## Irreversible claim, one socket, genuine receiver

Only after those checks does the existing token-free
`claim_oidc_session_activation_release` irreversibly claim the exact client
authorization digest, request identity, LIVE profile, server-bootstrap digest
and expected outcome. Failure or uncertainty does not authorize redispatch,
replacement of that claim, automatic recovery, or an unconditional retry.

The existing guarded socket helper is then called exactly once with raw7 and
the same current guard, work and deadline. Its raw2 response is unverified
`(request_identity, token64)` data. Neither raw7 nor raw2 nor either token is
appended to a journal, status object or retained success carrier.

The final operation is a tail return from the actual original-only response
verifier. It receives the exact request/response originals, original fresh
client/server controls, independently derived scope17, original processing
bounds and same-permission continuity hook. Only that genuine receiver may
return the private 64-byte token. No weaker post-verification owner callback,
token-bearing DTO or application cookie issuance follows in this helper.

## Remaining integration boundary

This composition requires real independently authorized, request-scoped
acquisition of the fresh client authorization and exact server bootstrap.
It does not implement that acquisition, mint a root authorization from proof
output, provision a live worker, or treat root-signed identity pins as a
durability witness. That acquisition and the public HTTP/cookie connection
remain separate open integration work. Source landing is not execution,
deployment, current-session proof, or production acceptance.
