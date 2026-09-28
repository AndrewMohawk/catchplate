# Public recovery grant acquisition configuration

Explicit signed/payload control-plane parent v15 adds the nullable field
`oidcSessionActivationReleaseRecoveryGrantAcquisition`. Earlier v2–v14 parents
retain their closed shapes and disabled recovery-acquisition lane; null v15
also disables it. No key, descriptor or secret delivery is added. The parent
wire/capture limit stays **4 MiB**, including every encoded original and all
existing configuration. Oversized configurations are refused, not externalized
to a caller-selected path or admitted under a larger limit.

The nested schema is
`serverware.controlPlaneOidcSessionActivationReleaseRecoveryGrantAcquisition/v1`,
with exactly these six fields:

| Field | Exact input |
| --- | --- |
| `schema` | The nested v1 literal |
| `endpoint` | Fixed path, integer timeout 1–30, peer UID/GID 0 |
| `issuerPolicy` | Independent recovery policy original, at most 64 KiB |
| `releaseCustody` | Historical custody original, at most 8 MiB before the tighter parent cap |
| `proofEnrollment` | Independently provisioned proof enrollment, at most 16 KiB |
| `intentEnrollment` | Independently provisioned intent enrollment, at most 16 KiB |

Each original uses only `{base64Url, byteCount}` with canonical unpadded
base64url and an exact 2-byte minimum. The endpoint path is
`/run/serverware/oidc-session-activation-token-release/recovery-grants.sock`;
its closed fields are `path`, `timeoutSeconds`, `peerUid`, and `peerGid`.
This is the recovery issuer, not a LIVE issuer or staging socket.

A non-null lane requires genuine configured parent `release_intent` and
`release_proof`. Cold admission authenticates the recovery policy root
signature and exact framed custody/enrollment identity pins, compares the
supplied enrollment bytes to those actual parent originals, and joins the
independently configured proof scope and intent caller. It preserves the four
exact originals. The stdlib FD projection checks the same closed public shape,
canonical wrapper grammar and endpoint without importing child authority or
changing its existing ten-value slot projection.

`_admit_on_work(*, recovery_grant_acquisition, release_intent, release_proof,
runtime_root_public_key, work)` returns null or immutable
`_RecoveryGrantAcquisitionMaterial(endpoint, issuer_policy_bytes,
release_custody_bytes, proof_enrollment_bytes, intent_enrollment_bytes)`.
The genuine parent retains it as `release_recovery_grant_acquisition`;
`_produce_v15_on_work` signs that explicit parent shape with the actual runtime
root pair. There is no live guard, fresh processing window, token or admitted
success DTO in this cold material.

Static signature/identity joins are not full historical custody/proof admission
or a present recovery permission. The finite recovery client must genuinely
re-admit all independent originals for each call under the fresh actor's
original work/window, immutable target and restrictive continuity. This
configuration does not renew old execution authority or make a signed
checkpoint-one expectation proof that the retained outcome exists. Durable
request retention, genuine recovery-worker staging, private exchange and
current-auth/cookie completion are separate source connections; no provisioning,
runtime or production acceptance is established here.
