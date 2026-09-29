# Current-authority LIVE delivery over retained RI originals

Status: source implementation only, unbuilt and unexecuted. This extends
[read-only retained intent/proof admission](control-plane-retained-intent-history.md)
with an explicit current-authority grant/custody path. It does not reactivate a
retired key, execute COMPLETE again, extend original delivery expiry or authorize
retained-outcome recovery under a retired root. The separate
[current-authority retained-outcome recovery profile](control-plane-retained-outcome-root-history.md)
uses fresh current permission plus exact protected checkpoint-one readback.

## Two custody identities, not a relabeled original

RI is the independently archived authority that signed the retained intent and
proof. The current root signs fresh delivery custody and fresh grants; original
activation and consume authorities retain their existing separate purposes.

| Original or field | Meaning |
| --- | --- |
| `historicalReleaseCustody` in custody v2 | Exact original RI custody v1, independently authenticated as historical evidence. |
| Current custody v2 | Fresh current-root authorization containing the independently pinned RI root, archive interval, exact intent/proof enrollments, proof scope and current planner original. |
| LIVE v2 `releaseCustodyDigest` | Framed identity of the fresh current delivery custody. |
| LIVE v2 `evidenceCustodyDigest` | Framed identity of the original RI evidence custody. |
| `storageScope.releaseCustodyDigest` | The same historical evidence-custody identity used by the retained proof and outcome association, not the fresh custody identity. |

Every base custody field except schema and the fresh outer issue/expiry times
must equal the historical original. Both planners and the complete old/current
state enrollment payloads are genuinely admitted and compared. Database,
generation and delivery-key continuity remain required; root rotation grants
neither state migration nor new credential possession. Archive intervals contain
the original custody, intent and proof intervals; they are not live allowances.

## Explicit grant-only bridge and fixed issuer

`serverware.oidcSessionActivationRetainedReleaseGrantBridge/v1` has the existing
retained proof-bootstrap original inventory plus `currentActivationPlanner`, but
replaces `launch` with bounded `requestTimeoutSeconds`. Its purpose is exactly
`authorize-current-release-grants-over-retained-intent`. It supplies no listener,
signing descriptor or proof-worker launch permission.

The fixed release-grant issuer uses independently configured, root-signed
`ReleaseGrantIssuerPolicy/v2` and the exact bridge original selected by its
`proofBootstrapDigest`. V2 explicitly chooses `_verify_grant_on_work`; old policy
v1 keeps its original verifier. Ordinary proof workers reject the grant-only
envelope. Dynamic proof-launch is unchanged and does not support this bridge.

The actual fixed cold issuer still uses
`signedOidcSessionActivationReleaseGrantIssuerBootstrap/v1`, independently
pinning `issuerPolicyDigest`, `proofBootstrapDigest` and `rootSigningKey`.
Its unchanged descriptors are root public key 198, bootstrap 199, listener 200,
issuer policy 201, proof bootstrap 202 and root signing key 203; the listener is
the fixed `grants.sock`. For policy v2, the legacy-named proof-bootstrap slot
contains the exact grant-only bridge original. Startup protects and admits
those originals; `_IssuerOwner._produce` passes the held policy/bridge bytes
under the same window. Existing launch-v2 `deliveryEndpoint` may send the
produced server bootstrap to fixed `bootstrap.sock`; it does not launch a
dynamic proof producer.

Genuine original verification includes the retained intent/proof enrollments,
their independent scope and signatures, exact release target, historical
COMPLETE state evidence and its ACK. Historical COMPLETE verification is not
COMPLETE execution. No replacement intent, replacement proof or retired private
key is created or loaded when retained originals are missing or invalid.

## Fresh permission through actual delivery

The explicit public release actor v2 binds `retainedIntentOnly: true` and the
exact `retainedIntentRecordDigest` before fresh approval. Changing the retained
selection changes the approved binding; a previous readmission result is not
release permission. Current authentication/approval, original old-token
possession and current processing guards remain mandatory.

The issuer consumes separately provisioned fresh current custody and produces
LIVE server/client/storage grants. Server bootstrap v2 is `live-release` only: `recoveryScope` and
`recoveryAuthorization` are required and null, and the independently authorized
storage checkpoint is exactly zero records with null outcome digest. The actual
delivery owner checks the two custody identities separately and preserves the
historical outcome association. Existing protected storage and guarded delivery
semantics remain; uncertain delivery is not permission to retry or regenerate.

One inherited work/window/deadline bounds original admission, grant production,
cold delivery and response handling. `requestTimeoutSeconds` is 1–30 and clips
that original allowance, never starts another one. Fresh outer issue time cannot
renew the original delivery expiry or convert an expired delivery into LIVE.

## Closed data contracts and remaining scope

The [bundled schema](../schemas/oidc-session-activation-retained-ri-delivery.v1.schema.json)
defines exactly four new envelopes: custody v2, grant-only bridge v1, issuer
policy v2 and LIVE server bootstrap v2. All retain the existing closed
`schema`/`payload`/`signatureBase64Url` envelope and Ed25519 verification of the
existing `plan._frame(schema, (canonical_payload,), work)` representation. No new
raw signing recipe or implicit old-profile upgrade is introduced.

Schema checks are data-shape checks only. Paired code still enforces canonical
original bytes without LF, exact source revision, decoded lengths/raw digests,
independent signatures and scopes, currentness, byte/node/depth reservations and
the unchanged aggregate original/work ceiling. Individually valid large
wrappers can exceed that aggregate and must be refused. Serialized identities,
operator metadata and verifier results do not substitute for actual custody.

Older-source adapters and state/configuration migration remain unsupported.
Retained-outcome recovery requires its separate explicit current-authority
profile; this LIVE grant-only bridge is not dynamic proof
launch or general historical release authority. Independent provisioning,
runtime delivery/cookie evidence, interruption acceptance and production gates
remain open. No build, test, runtime, pilot, cloud deployment or parent-completion
credit follows from these source contracts.
