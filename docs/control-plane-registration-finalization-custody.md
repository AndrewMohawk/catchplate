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
field and adds required `registrationFinalization`, either null, the exact
six-field v1 object below, or the explicit nested v2/v3 extensions described next.
The complete canonical original remains bounded to
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

The stdlib-only [early descriptor projection](../serverware/authority_fd_entrypoint.py)
now accepts each closed nested v1/v2/v3 shape and its source-fixed endpoints;
the older v1-only projection would have rejected v2 before child startup. All
three profiles still select the same FD204. This delivery check authenticates
no root, signature, generation or currentness: full child admission remains
mandatory before the key or configuration is used.

Parent v2/v3 and their producers retain their prior behavior, including their
previously allowed generic issuer descriptor range. Only v4 reserves FD204:
an enabled profile must use its distinct dedicated slot; a null profile rejects
that slot in the admitted inventory or already open at cold admission. Neither
an absent v4 field nor an older profile implicitly enables finalization.

## Opt-in reservation scope

Nested `serverware.controlPlaneRegistrationFinalization/v2` retains the six
fields above and requires exactly `reserverEndpoint` and `statePredecessor`.
The complete parent v4 root signature authenticates these fields; no newer
parent schema, new key, descriptor or environment variable is needed. Nested
v1 remains grant-only and cannot silently acquire reservation authority.

`reserverEndpoint` uses the same closed endpoint shape with fixed path
`/run/serverware/registration-finalization/reserver.sock`, integer timeout
1–30 seconds and listener peer `0:0`. `statePredecessor` is exactly
`{sequence, headDigest, nextFence}`. Genuine current-root enrollment admission
binds its capacity and generation. A genesis sequence requires the original
enrollment digest and fence one; every predecessor must leave room for both
reserve and completion. A signed old head is not automatically a current head:
the provisioner must independently establish these pins before cold admission.

The owner exposes `finalization_reservation_enabled` and the separate private
`_request_registration_finalization_reservation`. It authenticates the complete
original grant before one exchange and verifies returned reserve/snapshot/state
acknowledgment against those independently held pins. No response updates the
expected predecessor, changes the original lifetime or authorizes SQL.
See the [caller reservation contract](control-plane-finalization-reservation.md)
and [public permission flow](public-registration-finalization-reservation.md).

## Opt-in SQL/current-pending configuration

Nested `serverware.controlPlaneRegistrationFinalization/v3` retains the exact
eight v2 fields and adds only `sqlEndpoint` and `currentPending`. Its SQL
endpoint is `/run/serverware/registration-finalization/sql.sock`, with the same
closed endpoint fields, integer timeout 1–30 seconds and root listener `0:0`.
`currentPending` is the exact independently root-signed
`{sequence, headDigest, fence}`. The sequence and fence are positive; the head
is canonical SHA-256. The sequence must equal the signed predecessor sequence
plus one, and the fence must equal its `nextFence`. The genuine current-root
enrollment's capacity must leave a completion slot after that pending sequence.

Private material adds `sql_endpoint` and `current_pending`, both `None` for
v1/v2. `finalization_sql_enabled` reports this configured pair under existing
owner/lifetime checks; it does not send SQL or grant present execution consent.
The unchanged signed parent v4 and FD204 carry this opt-in profile without a
new key, descriptor, environment variable or fallback.

No returned reserve receipt, retained record or observed database value supplies
the independent pending head. A root-signed cold pin remains a provenance-bound
assertion, not proof that an off-host head is still current at action time.
Actual original admission and protected one-use database effects remain separate
checks in the [private SQL caller/worker path](control-plane-finalization-sql.md).
Neither that source integration nor the cold pin establishes independent currentness.
See the [pending-scope boundary](control-plane-finalization-reservation.md#opt-in-current-pending-pins-not-a-witness).

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
availability or deployment. The explicit nested v2 reservation flow still
requires the independently provisioned reserver and state v2 peer admission.
Nested v3 now supplies explicit SQL/current-pending configuration to the private
SQL request method and dedicated cold worker. They authenticate original pending
scope before actual protected issuance/execution; the caller joins every returned
marker field to the verified original plan. A separate [public finalization
execution action](public-registration-finalization-sql.md) now repeats retained
ownership and joins durable local dispatch/outcome handling. Signed
completion/recovery and separate OIDC session activation remain outstanding.
A configured property alone is not a completed workflow.
Trusted-host-local descriptor continuity is not independent enclave evidence.

This implementation has not been built or executed. Deferred frozen validation
includes old-profile compatibility; closed v4/null-slot and nested-version
rejection; independently pinned predecessor/capacity checks; inconsistent v3
pending successor/fence/capacity and endpoint rejection; tampered or
cross-purpose enrollment rejection; actual separate key/FD pair admission;
missing, reused or changed key rejection; PID/custody/descriptor drift; and
shutdown/failure preventing reuse. These are planned checks, not passing results.
