# Dedicated finalization caller custody

The control plane has a source-only, explicitly opted-in cold profile for the
`webauthn.registration.finalize` caller. It does not reuse evidence-admission
permission or its caller key. The [private authorization-before-planning
continuation](control-plane-finalization-execution.md) requires genuine
present-caller permission; provisioned keys and retained originals do not supply
it. The separate [public grant-preparation routes](public-registration-finalization-grant.md)
now enforce that purpose in source. This profile neither deploys those routes
nor turns its key custody into present-caller permission.

## Explicit parent v4

The original root-signed envelope uses
`serverware.signedControlPlaneEnrollmentBootstrap/v4`; its payload uses
`serverware.controlPlaneEnrollmentBootstrap/v4`. It retains every parent v3
field and adds required `registrationFinalization`, either null or the exact
six-field object below. The complete canonical original remains bounded to
4 MiB and authenticated by the already admitted runtime root.

| Nested field | Fixed contract |
| --- | --- |
| `schema` | `serverware.controlPlaneRegistrationFinalization/v1` |
| `finalizationCallerPrivateKeyFd` | Integer `204` |
| `currentRootEnrollment` | Original `{base64Url, byteCount}`, at most 128 KiB |
| `grantEnrollment` | Original `{base64Url, byteCount}`, at most 16 KiB |
| `authorizationEnrollment` | Original finalization-purpose `{base64Url, byteCount}`, at most 16 KiB |
| `authorizerEndpoint` | Exact `socketPath`, `requestTimeoutSeconds`, `listenerUid`, `listenerGid` |

The endpoint is `/run/serverware/registration-finalization-authorizer.sock`,
timeout integer 1–30 seconds, and listener peer `0:0`. This pins a root-activated
listener, not a signing process identity or an installed/running service. There
is no hostname, environment override, alternate endpoint or evidence-authorizer
fallback.

The [parent bootstrap](../serverware/control_plane_enrollment_bootstrap.py)
provides `_produce_v4_on_work` for an independently authorized provisioner and
admits v4 through its existing `_admit_on_work`. The producer receives the actual
root key pair, complete configuration/generation/runtime identities and explicit
nested originals; it does not generate keys, open descriptors or provision files.
The [nested admission](../serverware/control_plane_registration_finalization_bootstrap.py)
genuinely checks the finalization-specific root delegation and original
current-root/grant enrollment, configuration, generation and audience bindings.
Its planner and operation keys come from the actual finalization transition
configuration, never the registration evidence-admission policy.

Parent v2/v3 and their producers retain their prior behavior, including their
previously allowed generic issuer descriptor range. Only v4 reserves FD204:
an enabled profile must use its distinct dedicated slot; a null profile rejects
that slot in the admitted inventory or already open at cold admission. Neither
an absent v4 field nor an older profile implicitly enables finalization.

## Actual key delivery and lifetime

The root [descriptor entrypoint](../serverware/authority_fd_entrypoint.py) reads
only `/run/secrets/serverware-registration-finalization-caller-key` for this
purpose: root-owned mode `0400`, bounded to 4096 bytes, through its existing
no-symlink source/sealed-descriptor path. It delivers the original at FD204 only
for an active v4 profile. The independently signed runtime descriptor inventory
must already include that slot; delivery does not invent an inventory entry.
There is no new environment variable or generic-launcher fallback.

The actual [cold owner](../serverware/control_plane_enrollment_startup.py)
requires control-plane UID/GID `65532:65532`, the original admitted bootstrap,
and the same custody owner. It loads the sealed unencrypted PKCS8 Ed25519 key
and verifies its real public-key pair against the admitted finalization caller.
FD204 must differ from the bootstrap, enrollment issuer and evidence-execution
caller slots. Key separation covers the genuine enrolled root/current-root
roles, grant authorizer, planner/finalization transition key, configured runtime
and other enabled purpose keys, any retained evidence-execution caller, and the
actual provisioned HTTP response key.

`finalization_enabled`, `_authorize_registration_finalization` and the private
`_request_registration_finalization_grant` use the same PID-bound owner and
retained original FD identities. Startup invokes none of these operations.
Existing continuity checks also cover the finalization key; shutdown drops its key/material references and
prevents reinitialization. The inherited descriptors remain owned by their
existing outer lifecycle: this owner does not close borrowed FDs or promise
Python key-memory zeroization. Fresh root provisioning and cold admission are
required to change the profile or key.

## Remaining authority and verification

Independent caller/key enrollment, root provenance, descriptor inventory,
protected files and socket access still require real provisioning. This cold
profile alone performs no network request, grant signing, reserve, SQL, one-use
consumption, completion, credential registration or session activation.
The private request method is now connected in source to the
[dedicated finalization authorizer](registration-finalization-authorizer.md)
and public grant-preparation facade, including same-read full-vector acquisition
and durable original association. The service source and packaging remain
unbuilt, unexecuted and unprovisioned; the fixed path is not evidence of socket
availability or deployment. Independent reserve, protected SQL and completion
orchestration, plus separate OIDC session activation, remain outstanding.
Trusted-host-local descriptor continuity is not independent enclave evidence.

This implementation has not been built or executed. Deferred frozen validation
includes old-profile compatibility; closed v4/null-slot rejection; tampered or
cross-purpose enrollment rejection; actual separate key/FD pair admission;
missing, reused or changed key rejection; PID/custody/descriptor drift; and
shutdown/failure preventing reuse. These are planned checks, not passing results.
