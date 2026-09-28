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

The immutable `_ReleaseProofAcquisitionMaterial` retains `endpoint`,
`issuer_policy_bytes` and `current_activation_planner_bytes` (None for v1).
Genuine cold admission requires the actual existing
intent and proof configurations, verifies the policy signature, and joins its
proof scope, caller and original enrollment identities. It creates no clock
window and makes no claim of full live policy admission. The actual FD
projection keeps the same ten purpose slots; no additional private key and no
root-signing or proof-signing key is delivered to the public process.

The distinct acquisition `/v2` keeps those same three JSON fields, but requires
the signed issuer-policy `/v2`. Its wrapped `currentActivationPlanner` original
must exactly equal the genuinely admitted current parent activation-planning
original. Parent `_v14_material` supplies that independent source object; the
request repeats the signature and exact-original check. The embedded planner
is a configuration template, not renewed activation permission. The signed
proof bootstrap `/v2` and genuine issuer material must contain that same current
R2 original, while completion custody `/v2` plus history `/v11` independently
authenticate R1 consume and R0 activation provenance.
Both fresh completion-recovery preparation and the ordinary
`permission.prove_release()` caller repeat these exact v1/v2 joins. The ordinary
caller still requires its actual current consume root and original target;
accepting the configured v2 setup does not add a historical fallback. Its v1
behavior is unchanged.

V1 retains its 64 KiB policy and 128 KiB acquisition limits. V2 permits a
6 MiB policy inside an 8 MiB-plus-4 KiB wrapper ceiling, but the enclosing
signed parent remains capped at 4 MiB and the whole call at 64 MiB. Thus these
per-file maxima do not promise that every maximum-sized policy is admissible.
The future lane reserves actual policy/template representations before the
first history body, and the setup response is tightened again before contact.
The ordinary permission caller also reserves eight actual policy/template
footprints before decoding v2, checks the measured capture against that
reservation, and subtracts it before accepting a setup response.

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

The fresh completion-recovery caller additionally joins the setup's consume
authorization, state enrollment and independently selected R1 root to its
actual retained controls. Current R2 proof/intent keys remain distinct. Raw
setup/proof originals are durably retained before semantic interpretation;
neither version introduces a second claim or a retry after uncertainty. Final
release custody still uses its existing v1 grammar with the exact current R2
planner; its delivery key must match the genuinely admitted historical R0
delivery key. This preparation does not enable historical token delivery or
migrate a retained intent signed under a retired authority.

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

The completion-recovery caller instead carries its already reserved 8 MiB
intent/proof lane. Before its setup socket, it subtracts fixed framing, request,
proof and journal work, then divides the remaining setup/proof representation
space by 32. It reserves 16 setup footprints plus 16 subsequent proof-response
footprints and tightens each custody publication to what remains. The added
R0/R1/R2 state checks fit inside the separate pre-reserved 4 MiB input lane;
no new allowance is opened by selecting v2.

All network and custody operations retain the same actual guard/work/deadline.
Missing responses, signature failures, failed retention or cleanup uncertainty
are terminal. No new ledger/window, second claim, reconnect, automatic retry or
recovered continuation is created. The optional codec index is appended without
changing earlier bytes; [durable consume records](control-plane-oidc-session-activation-consume-records.md)
remain ordinary read-only history after restart.
