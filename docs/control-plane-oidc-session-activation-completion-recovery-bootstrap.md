# Explicit public completion-recovery configuration

`control_plane_oidc_session_activation_completion_recovery_bootstrap.py` supplies
small, independently root-signed expectations for a later completion-only
recovery caller. It is part of actual signed parent admission and production,
not a standalone successful-result carrier. This slice supplies prerequisites
for COMPLETE; it does not close that facet, contact a service, observe a commit,
repeat SQL or deliver a token.

## Explicit parent and closed roles

The signed and payload parent schemas explicitly advance to
`serverware.signedControlPlaneEnrollmentBootstrap/v16` and
`serverware.controlPlaneEnrollmentBootstrap/v16`. The new required parent field
`oidcSessionActivationCompletionRecovery` is nullable. Versions v2–v15 retain
their exact old shapes and produce `completion_recovery=None`; a current source
revision does not silently enable a new recovery path.

The non-null nested object has exactly `schema`, `activation` and `consume`.
Its schema is `serverware.controlPlaneOidcSessionActivationCompletionRecovery/v1`.
Each role is null or has exactly:

```text
schema, endpoint, packetDigest, authorizationDigest, currentPending
```

At least one role must be non-null. The activation role schema is
`serverware.controlPlaneOidcSessionActivationCompletionRecoveryScope/v1`; the
consume role is
`serverware.controlPlaneOidcSessionActivationConsumeCompletionRecoveryScope/v1`.
Any non-null recovery configuration requires the actual parent
`oidcSessionActivationPlanning` configuration and its independently admitted
historical planner original, including when only consume recovery is enabled.
No posted profile, alternate protocol or fallback is accepted.

| Root-selected role | Fixed existing public protocol | Endpoint path |
| --- | --- | --- |
| activation | authorization dispatch / launch v2 | `/run/serverware/oidc-session-activation/completion.sock` |
| consume | release-hints dispatch / launch v3 | `/run/serverware/oidc-session-activation-delivery-execution/completion.sock` |

Each endpoint uses the genuine existing closed fields `socketPath`,
`requestTimeoutSeconds`, `listenerUid`, `listenerGid`. Timeout is an exact integer
1–30; listener UID/GID are exactly 0. The entire tuple must equal the actual
parent execution configuration's completion endpoint. Activation needs an
enabled execution v3/v4. Consume needs actual execution v4 with
`release_hints is True`; the private UID65497 packet-selector protocol is not
made available to the public app.

`packetDigest` and `authorizationDigest` are canonical SHA-256 identities
supplied independently by the root provisioner. `currentPending` is exactly
`{sequence, headDigest, fence}`: sequence 1–1024, positive bounded fence and a
canonical SHA-256 head. Its sequence must equal the actual configured reservation
predecessor sequence plus one, and its fence must equal that predecessor's
next fence. The pending head and packet pin cannot be learned from an unsigned
SQL response, candidate ACK or recovery result.

## Genuine parent joins and immutable API

Actual parent v16 admission invokes:

```text
_admit_on_work(
    *, completion_recovery, activation_execution, consume_execution,
    runtime_root_public_key, configuration_digest, generation_digest, work
) -> None | _CompletionRecoveryMaterial
```

This private nested join is called only after genuine signed-parent admission
has admitted the existing execution configuration. Each enabled role also
genuinely re-admits its original caller, grant and current-root enrollments
against the actual root, configuration digest, planner and operation keys. It
joins parent generation, caller enrollment identity, caller ID/measurement and
public key. Consume must retain the exact activation parent's current-root
enrollment original. No previously successful object replaces those signature
and purpose checks; configured execution material is only the source-selected
same-call input to them.

The parent appends immutable `.completion_recovery`. Its exact
`_CompletionRecoveryMaterial` has two nullable fields, `.activation` and
`.consume`. Each enabled field is exact `_CompletionRecoveryScope` with:

```text
endpoint: tuple
packet_digest: str
authorization_digest: str
current_pending: tuple(sequence, headDigest, fence)
```

There is no key, descriptor, mutable nested graph or live guard in this material.
The explicit `_produce_v16_on_work` parent producer takes all v15 arguments plus
`oidc_session_activation_completion_recovery`, captures the complete payload,
performs these genuine original joins and checks the root pair before signing
the distinct v16 domain. Existing producers and admissions remain unchanged.

The root FD entrypoint recognizes only the new exact v16 envelope/payload and
closed role shapes. It checks the same paths, profile prerequisites and pending
relations while preserving the existing ten-value purpose-slot projection.
That data gate performs no signature admission and opens no new descriptor.

## Bounds and remaining authority

The nested object is capped at 16 KiB, 128 nodes and depth 4. All existing parent
originals plus this field remain within the unchanged 4 MiB parent cap, with
the existing cumulative parsing, capture, hashing and signing allowance.
Oversize combinations refuse; no embedded 16/32 MiB worker bootstrap, private
AES key, reader or new allowance enters the public parent.

The selected protocols send only the fixed purpose and exact historical caller
authorization. The real worker must compare that original to its independently
root-admitted original, then use its own packet/pending/resource pins. A raw4
reply does not attest packet identity; raw6 hint framing is not authority or
private replay proof. These cold expectations do not assert that matching
resources were provisioned or that a worker is ready.

A future effect still requires fresh actor authorization bound to this exact
scope, genuine historical original/control admission, one durable token-free
attempt, completion-only exchange and separately retained reconciliation.
Existing live `_ActivationPermission` continuation seals are not bypassed.
Expired execution grants remain historical evidence, never renewed SQL or
activation permission. Source only: no build, test, execution, provisioning or
production verification is claimed.
