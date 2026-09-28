# Same-context committed-release proof

The `.190` source connection remains unbuilt, unexecuted and unprovisioned.
Source `.198` adds optional [per-request proof setup acquisition](control-plane-oidc-session-activation-release-proof-acquisition.md)
under explicit parent `/v14`, preserving the direct-worker path below. The
issuer-side packet read, finite signer and staging channel remain unimplemented;
configuration does not make that endpoint available. Neither path opens the new
token, issues a cookie or establishes current session state.

## Cold public configuration

Explicit parent enrollment `/v10` adds nullable
`oidcSessionActivationReleaseProof`. Its closed `/v1` value contains `schema`,
`proofEnrollment` (`base64Url`, `byteCount`), `expectedScope` and `endpoint`.
It requires genuinely admitted release-intent configuration; older parent
shapes remain strict and unchanged. No new public private-key FD is delivered.

The seven-field proof scope contains configuration, database, generation and
runtime-closure identities, `producerId`, `producerIdentity` and
`receiverIdentity`. The five common fields must match the actual intent scope;
the independently root-enrolled proof producer is not the intent caller.
The proof key must differ from the actual intent key, other held purpose keys,
configured purpose pins and the running HTTP response key.

The endpoint's exact fields are `socketPath`, `requestTimeoutSeconds`,
`listenerUid`, `listenerGid`. Its path is fixed to
`/run/serverware/oidc-session-activation-token-release/proof.sock`, timeout is
an integer 1–30 seconds and the root-created listener peer is `0:0`.
`release_proof_enabled` reports configuration only.

The optional `docker-compose.oidc-session-activation-release-proof.yml` overlay
mounts the existing socket selected by
`SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_PROOF_SOCKET` at that exact path,
read-only with `create_host_path: false`. The environment value selects only a
host mount, never transport authority. It creates no key, service or socket.

## One actual continuation

The no-argument `_prove_oidc_session_activation_release()` owner facade selects
only its actual active permission. `prove_release()` requires the retained
signed-intent phase, spends its in-memory latch before callbacks and revokes the
permission on any uncertainty. No recovered record or posted result can resume it.

1. Hold the exact prior intent, delivery expectations, completion/state originals,
   old-token possession, cold verifier enrollment and original work/window.
2. Reauthenticate the original intent and possession. Durably burn
   `release-proof-claimed` before contacting the fixed socket.
3. Send raw3: fixed purpose, exact intent identity and ephemeral old token.
4. Retain the bounded opaque raw4 response as `release-proof` before inspecting
   status or authenticating any returned original.
5. Verify the root-signed custody record against the exact actual intent,
   activation planner original, delivery, receiver and configured cohort.
6. Verify the separately enrolled proof against that custody identity, the
   retained state-receipt identity and all actual intent/release bindings.

The response is `(proved, releaseCustody, proof, proofEnrollment)`. The final
return remains original bytes, not a plaintext token or transferable permission.
All predecessor guards remain active. Restrictive continuity joins clock floors
and permits only narrowing the original allowance, including after transport.

## Private boundary and remaining work

The [cold worker](oidc-session-activation-release-proof-service-bootstrap.md)
uses actual historical custody and normal-closed commit readers, a distinct
proof signer, and one original-bound private replay. It has no completion signer,
completion journal, state writer or token-opening API. It necessarily uses the
existing completion-purpose UID/GID `65497:65497`; a separate process/socket is
not a new OS isolation boundary from that same-UID purpose.

The root custody names the actual signed intent. Independent post-intent
authorization is therefore required; the new [setup policy and producer](oidc-session-activation-release-proof-input-policy.md)
derive this from authentic originals and a separately acquired private packet.
Cold public configuration does not guess a future intent or manufacture root
authority. Source templates are not installed, and the setup issuer is still open.
Live provisioning of post-intent release server/client grants and protected token
handoff, plus the public route/cookie connection, remains open. Production
evidence is unchanged.
