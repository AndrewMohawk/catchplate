# Same-permission proof setup acquisition

Source integrated, unbuilt and unexecuted. This public-only continuation adds
no packet reader, root signing key, provisioning claim or public HTTP route.
Source `.199` connects the separately isolated [issuer service](oidc-session-activation-release-proof-input-issuer-service.md)
to its authorized packet reader and one-shot signing/staging owner. Its resources
remain unprovisioned; configuring an endpoint does not make it available.

## Cold configuration

Signed parent enrollment v14 adds nullable
`oidcSessionActivationReleaseProofAcquisition`. Older v2–v13 envelopes retain
their exact closed shapes. The new value has exactly:

- `schema`: `serverware.controlPlaneOidcSessionActivationReleaseProofAcquisition/v1`.
- `endpoint`: `{path, timeoutSeconds, peerUid, peerGid}`. The source-fixed path
  is `/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock`,
  timeout is an integer from 1 through 30 seconds, and the server peer is 0:0.
- `issuerPolicy`: `{base64Url, byteCount}`, the exact independent root-signed
  policy original, bounded to 64 KiB.

The immutable `_ReleaseProofAcquisitionMaterial` retains only `endpoint` and
`issuer_policy_bytes`. Genuine cold admission requires the actual existing
intent and proof configurations, verifies the policy signature, and joins its
proof scope, caller and original enrollment identities. It creates no clock
window and makes no claim of full live policy admission. The actual FD
projection keeps the same ten purpose slots; no additional private key and no
root-signing or proof-signing key is delivered to the public process.

## Actual continuation and original authority

Existing no-argument `permission.prove_release()` retains its actual active
permission, signed intent, acknowledged consume completion, independent cold
enrollments, old-token possession and original work/window. When v14 acquisition
is configured, the caller rechecks the static signed policy and its current
interval, then sends only raw4:

`(purpose, signed_completion_request, state_receipt, signed_release_intent)`.

There is no public consume packet, old token, caller-selected target, proof
bootstrap or success DTO in this request. The private issuer must independently
acquire its exact policy-pinned packet. The old token remains ephemeral only in
the later existing proof request, where the worker checks possession.

The existing irreversible `release-proof-claimed` marker is durable before
setup contact and covers the subsequent proof request too. The opaque raw1
bootstrap response is bounded and durably retained as `release-proof-setup`
before semantic admission. The receiver then genuinely verifies that root
bootstrap against exact retained intent, completion request/receipt, enrollment
originals, expected release and independent proof scope. The inner completion
original is admitted against the independent root policy's identity; it is not
trusted merely because it arrived in a response. Full policy admission uses
the actual original window and independent cold enrollments, and the worker's
launch must equal the policy launch.

Both genuine liveness guards remain in the original proof continuation;
allowances may only narrow. The later proof response must contain byte-identical
acquired release custody before the ordinary proof admission proceeds. A
bootstrap reply is not staging acknowledgment, worker readiness, proof, current
session state or token release.

## Bounds and failure

The public framing ceiling is 48 MiB for the opaque bootstrap. Before receiving
it, the caller tightens that limit to one eighth of its remaining 64 MiB
whole-call inventory after prior held originals, measured policy captures,
request/framing and subsequent proof-response reservation. The eightfold
reservation covers nested original/graph and canonical readback copies; it
does not enlarge transport or processing ceilings.

All network and custody operations retain the same actual guard/work/deadline.
Missing responses, signature failures, failed retention or cleanup uncertainty
are terminal. No new ledger/window, second claim, reconnect, automatic retry or
recovered continuation is created. The optional codec index is appended without
changing earlier bytes; [durable consume records](control-plane-oidc-session-activation-consume-records.md)
remain ordinary read-only history after restart.
