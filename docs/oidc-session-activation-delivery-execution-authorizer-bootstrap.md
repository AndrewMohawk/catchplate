# Consume execution authorizer bootstrap

This dedicated root-original profile admits the cold scope for the consume-only
grant authorizer. It provisions no keys or process, grants no present caller
permission, and performs no reservation, SQL mutation or plaintext release.
The implementation is source-only, unbuilt, unexecuted and unprovisioned.

[`oidc_session_activation_delivery_execution_authorizer_bootstrap.py`](../serverware/oidc_session_activation_delivery_execution_authorizer_bootstrap.py)
authenticates its own original launch and all four detached originals through
the actual [consume receiving bootstrap](oidc-session-activation-delivery-execution-custody-bootstrap.md).
It then admits the original current-root enrollment, dedicated consume-grant
enrollment and consume caller enrollment. An incoming material object or a
successful replay result never replaces these originals. The existing
activation authorizer and generic seven-operation grant profiles are unchanged.

## Closed launch and originals

The distinct signed-envelope, payload and launch schemas are respectively:

- `serverware.signedOidcSessionActivationDeliveryExecutionAuthorizerBootstrap/v1`;
- `serverware.oidcSessionActivationDeliveryExecutionAuthorizerBootstrap/v1`;
- `serverware.oidcSessionActivationDeliveryExecutionAuthorizerLaunch/v1`.

The envelope is exactly `{schema, payload, signatureBase64Url}`. Its schema is
also the root-signature domain. The role original is capped at 4 MiB. Its exact
payload contains `schema`, `sourceRevision`, `role`, `operation`,
`receivingCustody`, `plannerBootstrap`, `plannerHistoryCustody`,
`receivingHistoryCustody`, `receiverIdentity`, `configurationDigest`,
`generationDigest`, `runtimeClosureDigest`, `databaseId`,
`currentRootEnrollment`, `grantEnrollment`, `authorizationEnrollment`,
`authorizerSpkiDigest`, `authorizerMeasurementDigest`, `issuedAtEpochNs`,
`expiresAtEpochNs`, `trustMode`, `launch` and the five assurance flags below.

Each detached-original descriptor is exactly `{byteCount, bytesDigest}` and
binds actual immutable bytes by plain SHA-256. The originals are not embedded
again in the role envelope:

| Detached original | Source cap | Actual admission |
| --- | --- | --- |
| `receivingCustody` | 16 KiB | Consume-grant receiver purpose |
| `plannerBootstrap` | 4 MiB | Consume-planner v2 |
| `plannerHistoryCustody` | 8 MiB | Consume-planning history v2 |
| `receivingHistoryCustody` | 8 MiB | Consume-grant history v3 |

The three embedded enrollment descriptors are each exactly
`{base64Url, byteCount, bytesDigest, identityDigest}` and use their actual source
module's byte limit. Raw digests and authenticated framed identities are both
joined. Role, detached and enrollment originals have a cumulative 64 MiB
ceiling on the same supplied work ledger.

Role and process mode are
`oidc-session-activation-delivery-execution-authorizer`; operation is fixed to
`oidc.session.activation-delivery.consume`. UID/GID are 65500:65500 and the
control-plane peer is 65532:65532. The fixed listener is
`/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock`,
named `serverware-oidc-session-activation-delivery-execution-authorizer`.

| Launch field | Fixed FD | Original/resource |
| --- | --- | --- |
| `rootPublicKeyFd` | 198 | Independent root public key |
| `bootstrapFd` | 199 | This role original |
| `listenerFd` | 200 | Activated listener |
| `custodyFd` | 201 | Consume receiving original |
| `plannerBootstrapFd` | 202 | Consume-planner original |
| `plannerHistoryCustodyFd` | 203 | Planning-history original |
| `receivingHistoryCustodyFd` | 204 | Receiving-history original |
| `executionBundleKeyFd` | 205 | Consume execution-bundle AES key |
| `historicalBundleKeyFd` | 206 | Historical activation-bundle AES key |
| `deliveryKeyFd` | 207 | Activation delivery AES key |
| `signingKeyFd` | 208 | Dedicated consume-grant signer |

The closed launch additionally contains only `schema`, `processMode`,
`serviceUid`, `serviceGid`, `peerUid`, `peerGid`, `inheritedFileDescriptors`,
`listenerPath`, `requestTimeoutSeconds`, `listenerSocketDevice`,
`listenerSocketInode`, `listenerPathDevice` and `listenerPathInode`. The FD array
must be exactly 198 through 208 in order; timeout is 1–30 integer seconds.
Devices are UInt64 including zero and inodes are positive UInt64. The bootstrap
authenticates these pins; actual delivery must independently check the live
descriptors, files and process. There is no DB, journal, planner private key,
state signer or completion signer in this role's descriptor inventory.

## Genuine purpose, key and cohort joins

The independent role `receiverIdentity` must match the authenticated receiving
identity. Its measurement digest must equal the role's authorizer measurement
pin and the actual consume-grant enrollment's measurement pin. This supplies a
separate launch-owned expected identity to the receiving owner; a value copied
from a successful receiving material is not independent admission. These are
root assertions about a trusted host, not measured-runtime or hardware proof.

The genuine consume-planner original supplies configuration, generation,
runtime-role identities, runtime closure, planner key, policy, state enrollment
and complete before-vector. Material exposes that vector through
`custody_material.planner.complete_root_vector_bytes`: it is not substituted
with the old activation planner's historical vector. Receiving admission joins
the two historical originals to the same original activation cohort and the
same independently bound consume request. The role's configuration, generation,
runtime closure and database pins must match these genuine admissions.

The current-root enrollment must byte-match the consume planner's retained
state enrollment. Actual consume caller admission binds configuration,
database, generation, current-root/grant identities, consume planner SPKI,
root operation SPKI and dedicated authorizer audience. Generic grant or
activation caller enrollment is not an alternate purpose.

The authorizer public key comes from the actual root-signed consume-grant
enrollment. Enrollment excludes root and current-root producer keys; this role
additionally separates the signer from the caller, both dedicated planners,
and all admitted generic-role, enrollment, evidence and transition signing
keys. UID/GID collision with configured generic roles is rejected. Distinct
purposes may share measured artifact bytes; signing keys and independently
admitted role identities must still have their exact purpose bindings.

Actual receiving admission verifies distinct consume execution, historical
bundle and delivery key pins, also separating them from the admitted journal
key purposes. The role bootstrap holds digests only. Private-key pair matching
and raw AES-key hash checks belong to actual fixed delivery and private owners;
no secret value enters this JSON profile.

## APIs and unchanged current allowance

```text
_verify_on_work(*, bootstrap_bytes, custody_bytes, planner_bootstrap_bytes,
    planner_history_custody_bytes, receiving_history_custody_bytes,
    root_public_key, work, live_window=None, transport_deadline_ns=None)
    -> _AuthorizerMaterial

_produce_on_work(*, payload, custody_bytes, planner_bootstrap_bytes,
    planner_history_custody_bytes, receiving_history_custody_bytes,
    root_private_key, root_public_key, work,
    live_window=None, transport_deadline_ns=None) -> bytes

_construction_on_work(work) -> (window, deadline)
_fresh(interval, work, opening=None)
```

All input originals and producer graphs are captured before cryptographic
callbacks. The producer genuinely repeats receiving and enrollment admission,
then signs with the actual independent root key, verifies the signature via the
real signing primitive and reads back the exact canonical output payload.
It is not a payload-signing endpoint or a role-provisioning mechanism.

A supplied processing window is never replaced or renewed; its deadline is
clipped only by an inherited earlier deadline. The optional cold form opens
one actual source-max clock bracket before signature work. Cold delivery can
instead call `_construction_on_work` before reading inputs and pass that same
window/deadline throughout. Neither form allocates a new work ledger.

The positive role interval is at most 300 seconds and lies inside all four
fresh nested launch intervals: receiver, consume planner, planning history and
receiving history. Their original brackets and the processing allowance remain
live through the final return. The old activation planner is admitted as a
historical original; its expired interval is never treated as a current clock
allowance. A grant producer separately retains the original signed consume
plan's issue/expiry bounds; this launch does not renew them.

The frozen private material preserves the older role's common original,
configuration/runtime, enrollment, public-key, authorizer, policy-limit,
launch and clock fields, and appends `planner_bootstrap_bytes`,
`planner_history_custody_bytes` and `receiving_history_custody_bytes`. It is
ordinary same-call data, not a proof token accepted by another API.

`trustMode` is exactly `trusted-host-local`. `hardwareBacked`, `nativeStageZero`,
`hsmBackedKeys`, `teeVerified` and `externalWitnessVerified` must all be false.
This profile alone closes no cold-service, deployment, reservation, execution,
release, browser permission or current-session acceptance gate.
