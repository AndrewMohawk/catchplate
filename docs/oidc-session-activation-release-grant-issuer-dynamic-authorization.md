# Independent dynamic grant-issuer authorization

[The original-only module](../serverware/oidc_session_activation_release_grant_issuer_dynamic_authorization.py)
admits a freshly issued proof bootstrap against independently provisioned cold
authority, then derives the existing exact grant-issuer policy and launch
originals. It does not widen either existing schema, read private key bytes,
observe resources, create files or provision a service. This is source-only;
staging and signed configuration do not prove readiness, replay or delivery.

## Independent signed input

The closed signed schema is
`serverware.signedOidcSessionActivationReleaseGrantIssuerDynamicAuthorization/v1`,
with payload schema
`serverware.oidcSessionActivationReleaseGrantIssuerDynamicAuthorization/v1`.
Purpose is `stage-oidc-session-activation-release-grant-issuer`; source revision
and `trusted-host-local` trust mode are fixed. The payload has exactly:

- `schema`, `sourceRevision`, `purpose`, `trustMode`;
- `proofInputIssuerPolicyDigest`;
- `clientId`, `clientIdentity`, `endpoint`, `releaseLaunch`;
- `issuerLaunch`, `rootSigningKey`, `intake`;
- `issuedAtEpochNs`, `expiresAtEpochNs`.

The digest independently pins the exact
[proof-input issuer policy](oidc-session-activation-release-proof-input-policy.md)
original, whose genuine admission pins completion, proof/intent enrollments,
scope and proof-worker launch. That policy, completion bootstrap and both
enrollment originals are separate inputs, not a caller-provided successful
object or an embedded future proof bootstrap. Client identity and release
resource pins come solely from this signed cold authorization.

`rootSigningKey` is the existing exact `{byteCount, bytesDigest}` shape.
`issuerLaunch` must be the existing closed grant-issuer launch **v2**, including
its fixed output-staging endpoint. The existing policy/bootstrap envelope
schemas and six inherited descriptors remain unchanged.

`intake` is exactly `{path, peerUid, peerGid, requestTimeoutSeconds,
listenerSocketDevice, listenerSocketInode, listenerPathDevice,
listenerPathInode}`. Its fixed path is
`/run/serverware/oidc-session-activation-token-release/grant-issuer-bootstrap.sock`,
with peer 65494:65494. Timeout is an exact integer from 1 to 30 seconds and
cannot exceed the signed issuer request timeout. These are independent pins;
the receiving root owner must observe matching resources before use.

## Three original-only operations

All three operations require `authorization_bytes`,
`proof_input_issuer_policy_bytes`, `completion_bootstrap_bytes`,
`proof_enrollment_bytes`, `intent_enrollment_bytes`, `root_public_key`,
`live_window`, `transport_deadline_ns` and `work`. Optional `_continuity` is
floor-only; optional `maximum_original_bytes` only tightens the source capacity.

1. `_verify_on_work` authenticates the cold authorization and genuinely admits
   the independent proof-input policy and its originals before the receiver
   waits or reads a private signer. Its signed interval must fit the independent
   policy; request, client and staging timeouts only narrow the original window.
2. `_admit_on_work` additionally takes exact `proof_bootstrap_bytes`. The actual
   [proof-input receiving admission](oidc-session-activation-release-proof-dynamic-delivery.md)
   rejoins those bytes to the independent completion/enrollment originals,
   scope, caller, proof signer and worker resource pins. This is public-original
   admission, not packet replay, old-token possession or proof completion.
3. `_produce_on_work` additionally takes the exact proof bootstrap and actual
   `root_private_key`. It re-admits all originals under the same allowance,
   pairs the real runtime-root key, and invokes the existing genuine policy and
   bootstrap producers. It returns **`(issuer_policy_bytes,
   issuer_bootstrap_bytes)`**, in that order. No successful material is accepted
   as an input to replace original admission.

Derived issue time is the maximum of the cold authorization and proof launch
issue times; expiry is their minimum. Empty intersections fail. There is no new
wall-clock issue time or allowance. Both existing signed outputs pin the exact
fresh proof-bootstrap identity; the issuer bootstrap additionally pins the
exact newly produced policy. Existing output producers retain actual signature
verification and original readback.

The static immutable `_AuthorizationMaterial` has 13 fields: five exact input
originals, `input_policy_material`, owned `payload`, `issuer_launch`,
`root_signing_key_byte_count`, `root_signing_key_digest`, `live_window`,
`deadline_ns` and `live`. `_AdmittedMaterial` has seven fields:
`authorization_material`, `proof_bootstrap_bytes`, `proof_material`,
`bootstrap_identity`, `live_window`, `deadline_ns`, `live`.
The identity is ASCII71 from the **grant-input delivery** domain, not the
proof-worker staging domain.

## Resource and capacity boundary

The root receiver must genuinely admit the fresh proof before opening the
private signer. Its initial signer check uses the independently admitted
dynamic byte-count/digest pins and actual root pairing. It must not weaken the
old key helper's exact static-material check to break the ordering dependency.
After deriving and re-admitting the existing signed outputs, it can seal the
old six-FD inventory and invoke the existing worker under the same PID,
work/window and permanent drop. The staging ACK acknowledges exact-original
staging only; no directory-empty, worker-ready or token-delivery claim follows.

The dynamic authorization is limited to 64 KiB, 512 nodes and depth 8. Existing
original codecs remain bounded. The 64 MiB aggregate includes conservative
decoded-original and complete output/readback reservations before admission or
signing allocations. `maximum_original_bytes` is either `None` (the original
64 MiB ceiling) or an exact integer from 2 bytes to 64 MiB. The actual owner
subtracts its measured retained resources and wire inventory before passing a
smaller capacity. A returned-size check is not the allocation guard.

The existing grant policy and bootstrap verify/produce APIs now accept optional
`_continuity=None`. The default preserves their old processing path. The
selected dynamic path retains genuine clock/work checks and exchanges only
nondecreasing epoch/monotonic floors through nested proof admission, signature
work and readback. Child calls receive the original upstream continuation, not
an aggregate guard that would recurse through their returned liveness.

Independent resource provisioning, deployment, runtime verification and the
remaining public HTTP/current-auth/cookie/recovery/portal work are separate.
