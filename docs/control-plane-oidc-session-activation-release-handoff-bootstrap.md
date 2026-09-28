# Static public release-handoff configuration

Explicit `serverware.signedControlPlaneEnrollmentBootstrap/v11` and payload
`serverware.controlPlaneEnrollmentBootstrap/v11` add one nullable field,
`oidcSessionActivationReleaseHandoff`. All v2–v10 shapes remain closed and
unchanged. The parent original cap remains 4 MiB. The older
`oidcSessionActivationRelease` / `release_client` lane remains separate, with
its original fixed-public-input contract and behavior.

This lane supplies independently root-pinned static client and endpoint data
for a later same-permission live release handoff. It is not a fresh client
authorization, server launch, token request, successful proof object, measured
control-plane identity, or authority to create post-intent root grants.

## Closed configuration

The nested `serverware.controlPlaneOidcSessionActivationReleaseHandoff/v1`
object has exactly four fields:

| Field | Meaning |
| --- | --- |
| `schema` | The literal nested v1 schema above |
| `clientId` | Independently root-selected canonical client token |
| `clientIdentity` | Exact existing identity3: `sessionIdentityDigest`, `measurementDigest`, `attestationReceiptDigest` |
| `endpoint` | Exact `{path, timeoutSeconds, peerUid, peerGid}` |

The endpoint path is
`/run/serverware/oidc-session-activation-token-release/release.sock`, timeout is
an integer from 1 through 30 seconds, and both peer IDs are exactly zero for
the existing root-created listener. The grammar reuses the actual release
client authorization endpoint checks. This configuration selects the live
handoff integration; it exposes no recovery selector or arbitrary socket path.

Non-null handoff configuration requires both genuinely admitted parent
`release_intent` and `release_proof` configurations. A null handoff is disabled;
older parent versions return `release_handoff=None`. Client ID and identity are
explicit root pins, not aliases for an issuer, caller, proof producer, planner,
or generic runtime role. Existing original-root/configuration/generation/runtime
admission remains in the actual parent; no absent control-plane measurement
role is invented.

## Immutable data and original allowance

`control_plane_oidc_session_activation_release_handoff_bootstrap.py` exposes:

- `_admit_on_work(*, release_handoff, release_intent, release_proof, work)`.
- Frozen `_ReleaseHandoffMaterial(client_id, client_identity_bytes, endpoint_bytes)`.
- `_identity_on_work(identity_bytes, work)`, returning the owned identity3 dictionary.
- `_endpoint_on_work(endpoint_bytes, work)`, returning the owned endpoint4 dictionary.

The decoders enforce the existing canonical JSON/identity/endpoint grammars on
the supplied work. Their fixed limits are 16 KiB, 64 nodes, and depth 4. They
decode ordinary immutable retained data; they do not authenticate a fresh grant
or open a new processing allowance. The parent `_EnrollmentMaterial` appends
`release_handoff=None`, preserving all existing material fields and purposes.
The independent root producer `_produce_v11_on_work` adds the explicit
`oidc_session_activation_release_handoff` keyword to the v10 producer inputs.
It genuinely admits the parent originals/configurations before signing in the
new v11 domain; an old-version signature does not authorize the new field.

No server bootstrap, client authorization, request identity, release outcome,
delivery token, or future release-target graph is accepted in this static
configuration. Actual handoff must independently derive its exact expected
scope from the same active permission and authenticated retained intent/proof
originals, then admit separately supplied fresh root originals under the same
current work/window/deadline. A static timeout may tighten transport but never
renews that allowance or substitutes for current permission.

## Cold delivery boundary

`authority_fd_entrypoint.py` recognizes the new field only under the explicit
parent v11 shape and applies a stdlib-only closed data gate before delivering existing optional
purpose keys. It imports no repository cryptography for that gate. Genuine
root signature admission remains in the actual child startup.

There is no new secret, key, descriptor, environment path, or key-slot
reservation. Existing FD204–207 reservations, disabled-key rejection and actual
non-overwriting key delivery remain inherited from the earlier exact profiles.
The internal ten-field slot projection and public four-field/two-field APIs
are unchanged. Handoff configuration cannot borrow an issuer, activation,
consume, intent, proof, delivery-AES, or historical private key.

These files neither provision root grants nor contact the release socket.
Source landing alone is not token delivery, an HTTP cookie, execution,
deployment, or production acceptance.
