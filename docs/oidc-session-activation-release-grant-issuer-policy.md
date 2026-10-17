# Root-original release grant issuer policy

This source-only policy authorizes one exact live-release grant derivation. It is
not a cold issuer service, descriptor loader or provisioner, and does not close
request-scoped original acquisition. It creates no root, key, directory, listener
or processing allowance. No runtime, deployment or production assurance is claimed.

Source `.200` adds a separate [dynamic input receiver](oidc-session-activation-release-grant-input-delivery.md)
that derives this exact policy only after independently authorized fresh-proof
admission. It does not weaken this policy's exact `proofBootstrapDigest` pin or
accept a successful-material substitute.

The fixed purpose is `issue-oidc-session-activation-release-grants`. The signed and
payload schemas are
`catchplate.signedOidcSessionActivationReleaseGrantIssuerPolicy/v1` and
`catchplate.oidcSessionActivationReleaseGrantIssuerPolicy/v1`. The policy identity
domain is `catchplate.oidcSessionActivationReleaseGrantIssuerPolicyIdentity/v1`.

## Independently authorized scope

The payload has exactly eleven fields:

- `schema`, `sourceRevision`, `purpose`, `trustMode`;
- `proofBootstrapDigest`, `clientId`, `clientIdentity`, `endpoint`, `releaseLaunch`;
- `issuedAtEpochNs`, `expiresAtEpochNs`.

`proofBootstrapDigest` frames the full independently provisioned proof-bootstrap
original with the distinct domain
`catchplate.oidcSessionActivationReleaseGrantIssuerProofBootstrapIdentity/v1`.
It is not a payload hash, a returned proof digest or an accepted admission result.
The potentially large proof bootstrap remains a separate original, not an embedded
policy field. Genuine proof-bootstrap admission supplies the exact intent,
release custody, completed consume originals, target, caller and producer pins.

`clientIdentity` retains the existing exact three-digest grammar. The independently
root-selected client ID and identity are trusted-host-local metadata, not proof
of measured process identity or hardware isolation. The existing client endpoint
grammar fixes `/run/catchplate/oidc-session-activation-token-release/release.sock`,
connect-side peer 0:0 and an integer timeout of 1–30 seconds. That timeout cannot
exceed the signed release launch timeout.

`releaseLaunch` uses the actual server-bootstrap launch grammar unchanged: fixed
release process UID/GID 65502, client peer 65532, descriptors 198–202, private
outcome-directory ownership/mode and exact directory/listener device/inode pins.
These are independently authorized root expectations, never observations obtained
from the caller or this module. This policy selects only the existing live-release
profile and its independently authorized `{recordCount: 0, outcomeDigest: null}`
checkpoint. It does not establish that a directory is empty, retained storage is
durable, or an outcome does not already exist. Recovery is a separate authority.

## Original-only interfaces

`_verify_on_work` requires `policy_bytes`, `proof_bootstrap_bytes`,
`root_public_key`, and the mandatory existing `live_window`,
`transport_deadline_ns`, `work`. It holds and bounds the original inventory,
admits the exact root signature/source/purpose, joins the full proof-bootstrap
identity, and invokes the genuine proof-bootstrap verifier on that original.
No parsed payload or successful material can be supplied instead of originals.

The frozen private `_IssuerPolicyMaterial` contains `policy_bytes`,
`proof_bootstrap_bytes`, `policy_digest`, `payload`, actual same-call
`proof_material`, `client_id`, owned `client_identity`, the fixed endpoint tuple,
owned `release_launch`, `live_window`, `deadline_ns` and `live`. These are ordinary
outputs, not authority-bearing inputs. The live closure retains actual policy and
proof guards with cross-guard epoch checks and their original monotonic bounds.

`_produce_on_work` takes the payload, independently supplied proof-bootstrap
original, actual root private/public pair and the same mandatory allowance. It
genuinely admits the proof original before signing, precharges native signature
and serialization work, and reads back the canonical output and real signature
under those retained guards. It is a fixed-purpose root producer primitive, not
an endpoint that signs arbitrary caller-selected resources.

`_read`, `_digest_on_work` and `_proof_bootstrap_digest_on_work` provide bounded
shape and exact-original identity operations only; none independently establishes
authority.

## Bounds and remaining acquisition boundary

The policy is capped at 16 KiB, 256 nodes and depth 6; the detached proof bootstrap
retains its actual 48 MiB cap. The original inventory has the existing 64 MiB
aggregate ceiling, and genuine proof admission applies its bounded nested-original
inventory under the same cumulative work. Producers reserve the bounded policy
output before nested admission or signing.

The policy interval must fit within the genuinely admitted proof interval, which
already contains the original intent, release custody and completion authority.
It cannot extend the actual delivery expiry. The effective window retains its
original first three clock samples and only tightens lifetime, skew, epoch and
monotonic deadlines, including the selected endpoint timeout. No historical
original becomes renewed live authority.

The grant producer must still authenticate the request-scoped proof/intent and
completed originals, derive exact storage/server/client grants, and join all
outputs. Independently authorized resource provisioning and a real request-scoped
acquisition service/client remain separate work. This policy observes no files,
loads no private key, delivers no descriptor, connects no socket and releases no
token or public cookie.
