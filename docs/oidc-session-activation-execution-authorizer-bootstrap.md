# Activation execution authorizer bootstrap

This dedicated source profile admits the cold scope for an actual activation
execution grant authorizer. It does not provision keys, install a service,
authorize a present caller, produce a grant, reserve current-root state, invoke
SQL or release a token. No build, test or runtime verification is claimed.

[`oidc_session_activation_execution_authorizer_bootstrap.py`](../serverware/oidc_session_activation_execution_authorizer_bootstrap.py)
genuinely verifies the new role launch, the separate
[receiving-custody original](oidc-session-activation-execution-custody-bootstrap.md)
and its embedded [planner-bootstrap v3](oidc-session-activation-planner-bootstrap.md).
No previously returned material object is accepted as authority.

## Closed originals and fixed delivery

The three new schemas are:

- `serverware.signedOidcSessionActivationExecutionAuthorizerBootstrap/v1`;
- `serverware.oidcSessionActivationExecutionAuthorizerBootstrap/v1`;
- `serverware.oidcSessionActivationExecutionAuthorizerLaunch/v1`.

The signed envelope is exactly `{schema, payload, signatureBase64Url}`, with the
signed-envelope schema also serving as its distinct root-signature domain.
The role original is at most 4 MiB. Its exact payload fields are:

- `schema`, `sourceRevision`, `role`, `operation`;
- `receivingCustody`, `receiverIdentity`, `configurationDigest`,
  `generationDigest`, `runtimeClosureDigest`, `databaseId`;
- `currentRootEnrollment`, `grantEnrollment`, `authorizationEnrollment`;
- `authorizerSpkiDigest`, `authorizerMeasurementDigest`;
- `issuedAtEpochNs`, `expiresAtEpochNs`, `trustMode`, `launch`;
- `hardwareBacked`, `nativeStageZero`, `hsmBackedKeys`, `teeVerified`,
  `externalWitnessVerified`.

`receivingCustody` is exactly `{byteCount, bytesDigest}`. It binds the external,
immutable receiving original, at most 8 MiB, by actual raw SHA-256. Those bytes
are not base64-nested into the role launch. Each of the three enrollment records
is exactly `{base64Url, byteCount, bytesDigest, identityDigest}` and retains its
own actual authority module's original-byte limit.

Role and process mode are `oidc-session-activation-execution-authorizer`, the
operation is `oidc.session.activate`, and the receiver consumer role is fixed
to `grant`. Service UID/GID are 65506:65506; the request peer is 65532:65532.
The source-fixed listener is
`/run/serverware/oidc-session-activation-execution/authorizer.sock`, named
`serverware-oidc-session-activation-execution-authorizer` for socket activation.

| Launch field | Fixed FD | Original/resource |
| --- | --- | --- |
| `rootPublicKeyFd` | 198 | Root public key |
| `bootstrapFd` | 199 | Role bootstrap |
| `listenerFd` | 200 | Activated listener |
| `custodyFd` | 201 | Separate receiving-custody original |
| `bundleKeyFd` | 202 | Private bundle AES key |
| `deliveryKeyFd` | 203 | Private delivery AES key |
| `signingKeyFd` | 204 | Successor-grant authorizer private key |

The launch has only `schema`, `processMode`, `serviceUid`, `serviceGid`, `peerUid`,
`peerGid`, those seven FD fields, `inheritedFileDescriptors`, `listenerPath`,
`requestTimeoutSeconds`, `listenerSocketDevice`, `listenerSocketInode`,
`listenerPathDevice` and `listenerPathInode`. The descriptor array must be exactly
198 through 204 in order; timeout is an integer 1–30 seconds. Devices are UInt64
including zero, and inodes are positive UInt64. The verifier authenticates these
pins; actual delivery must check the live descriptors and paths. No planner key,
planner journal key, reserve journal or SQL credential belongs in this profile.

## Independent purpose and key joins

The role's independently supplied `receiverIdentity` must match the genuine
receiving statement. It remains the distinct launch-sourced pin passed to the
[private receiving owner](oidc-session-activation-execution-custody.md), not a
value copied from its returned material. Its measurement digest must equal both
the role's authorizer measurement pin and the genuine grant enrollment's pin.
These are host-local root assertions, not hardware measurement evidence.

Actual embedded planner admission supplies configuration, generation, runtime,
planner key/policy and state/vector scope; the role does not duplicate those
configuration graphs. Its configuration, generation and runtime-closure digests
must match that admission. The current-root enrollment must byte-match the
planner's original state enrollment. Every enrollment's raw and framed identity,
database and generation joins are checked against genuine original admissions.

The new activation caller enrollment is admitted through
`authority_oidc_session_activation_execution_authorization._admit_enrollment_on_work`:
purpose `authorize-oidc-session-activation-execution`, fixed activation operation,
actual dedicated planner key and actual state-root operation key. It binds the
caller to the genuine successor-grant authorizer audience. Registration
evidence/finalization purpose enrollment is not a fallback.

The authorizer public key comes from genuine grant enrollment. Existing grant
admission excludes current-root authority keys; this profile also separates the
signer from the caller, dedicated planner and all admitted generic-role,
enrollment, evidence and transition signing purposes. No arbitrary key is
accepted because a digest happens to appear in the launch. Actual private-key
pair and raw AES-key pin checks remain the delivery/owner's responsibility.

## APIs and original lifetime

```text
_verify_on_work(*, bootstrap_bytes, custody_bytes, root_public_key, work,
    live_window=None, transport_deadline_ns=None) -> _AuthorizerMaterial

_produce_on_work(*, payload, custody_bytes, root_private_key, root_public_key,
    work, live_window=None, transport_deadline_ns=None) -> bytes

_fresh(interval, work, opening=None)
```

The producer repeats genuine receiving/planner and enrollment admission before
signing the independent role statement. It does not synthesize caller permission
or turn a matching identity into provenance. Both APIs retain the same supplied
work and any inherited processing window/deadline. The positive role interval
is at most 300 seconds and fits inside the original receiving interval, which
already fits inside the planner launch. All three original brackets remain
checked through return; no replacement allowance or renewed launch is created.

The private frozen material exposes original `bootstrap_bytes`/`custody_bytes`,
same-call `custody_material`, independently launch-owned `receiver_identity`,
the admitted configuration/generation/runtime graphs and digest pins, all three
enrollment originals, planner/operation/authorizer public keys and authorizer
pins, database/generation identity, `maximum_authorization_age_ns`,
`maximum_authorization_clock_skew_ns`, `attestation_interval`, `opening_sample`
and `launch`. The authorization limits come from the genuine caller enrollment;
they are limits, not a fresh processing window. No public API accepts this
material as a substitute for the originals.

`trustMode` must be `trusted-host-local` and all five assurance flags must be
false. This profile adds no receiving reserve/SQL role service, historical
completion fallback, public activation permission or session-currentness claim.
