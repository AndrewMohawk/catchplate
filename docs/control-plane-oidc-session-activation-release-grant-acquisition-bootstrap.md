# Public release-grant acquisition configuration

Explicit `serverware.signedControlPlaneEnrollmentBootstrap/v12` and payload
`serverware.controlPlaneEnrollmentBootstrap/v12` add one nullable field,
`oidcSessionActivationReleaseGrantAcquisition`. All v2–v11 shapes stay closed
and unchanged. The parent cap remains 4 MiB and the older fixed-original
`release_client` and direct-input `release_handoff` behaviors are unchanged.

This public-only configuration selects a fixed endpoint for acquisition on an
actual still-active permission. It is not an issuer policy, fresh grant, service
launch, successful response, new work/window or authority to create resources.
No issuer/root private key is delivered to the application.

## Closed endpoint

The nested schema is
`serverware.controlPlaneOidcSessionActivationReleaseGrantAcquisition/v1`.
Its object has exactly `schema` and `endpoint`. The latter has exactly:

| Field | Required value |
| --- | --- |
| `path` | `/run/serverware/oidc-session-activation-token-release/grants.sock` |
| `timeoutSeconds` | Exact integer from 1 through 30 |
| `peerUid` | Exact integer `0` |
| `peerGid` | Exact integer `0` |

Endpoint admission delegates to the actual fixed grant transport tuple grammar.
The peer pins identify the root-created listener, not proof of issuer authority,
policy, service deployment or resource delivery. Unknown fields, alternate paths,
booleans/fractional timeouts and nonzero peer IDs are rejected.

Non-null acquisition requires actual admitted parent `release_handoff`, which
already requires genuine intent and proof configuration. Null disables the lane;
all older parents return `release_grant_acquisition=None`. There is no browser-
selected endpoint, requested issuer policy, grant original or token in this
configuration.

## Actual interfaces and original allowance

`control_plane_oidc_session_activation_release_grant_acquisition_bootstrap.py`
exposes:

```text
_admit_on_work(*, release_grant_acquisition, release_handoff, work)
_ReleaseGrantAcquisitionMaterial(endpoint)
```

The sole material field is an immutable exact tuple `(path, timeout, uid, gid)`.
The bounded input graph is owned under the supplied work, with fixed limits of
4 KiB, 32 nodes and depth 3. Its parent verifies the actual canonical original
and root signature before nested admission; this material is ordinary same-call
configuration data, never accepted as a substitute for original authority.

The parent `_EnrollmentMaterial` appends `release_grant_acquisition=None`.
The distinct `_produce_v12_on_work` keeps all v11 producer inputs and adds
`oidc_session_activation_release_grant_acquisition`. It genuinely admits the
parent configurations and root key pair before signing in the v12 domain, with
the same bounded work and stable original/readback checks. An older signature
cannot authorize the new field.

The actual caller must retain this parent configuration and the same active
permission, target and original work/window/deadline through acquisition,
retention, original grant admission and protected release. The configured
timeout may only tighten the inherited deadline. Static configuration creates
no fresh permission and authorizes no automatic retry after uncertainty.

## Cold delivery boundary

`authority_fd_entrypoint.py` adds a stdlib-only closed v12 data gate. Its internal
ten-field slot projection and older four-field/two-field APIs are unchanged.
Every inherited purpose reservation and disabled-key rejection remains in force,
including the existing FD204–207 reservations. There is no new key, FD slot or
environment path and no issuer/proof/history/delivery custody in this public lane.
Actual root signature admission still belongs to the child startup.

This configuration does not provision issuer policy, signing keys, sockets or
release resources. The independently authorized acquisition/provisioning and
public HTTP/cookie/recovery/portal boundaries remain distinct. Source is unbuilt
and unexecuted; no runtime or production acceptance follows from the schema.
