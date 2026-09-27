# Root-authenticated activation receiving custody

This source-only profile independently authorizes a fixed **receiving** purpose.
It is not the planner's sender authorization, a registered execution service,
permission to activate a session or a successful-verification token. No build,
test, runtime, key delivery, filesystem provisioning or production verification
is claimed.

[`oidc_session_activation_execution_custody_bootstrap.py`](../serverware/oidc_session_activation_execution_custody_bootstrap.py)
admits two genuine signed originals: the new outer receiving statement and its
exact embedded [planner-bootstrap v3](oidc-session-activation-planner-bootstrap.md).
Neither API accepts a previously returned planner material as authority.

## Fixed receiving purposes

| Consumer role | Process mode | UID/GID |
| --- | --- | --- |
| `grant` | `oidc-session-activation-execution-authorizer` | 65506:65506 |
| `reserve` | `oidc-session-activation-execution-reserver` | 65505:65505 |
| `sql-issuer` | `oidc-session-activation-execution-sql` | 65504:65504 |

The caller independently selects `expected_consumer_role`; an authenticated
statement for another role still fails. Registration, control-plane, planner
sender, executor-only and historical/completion roles are not in this profile.
These constants reserve source identities; they do not create accounts,
processes, descriptors, environment selectors or state-service permissions.

## Original wire and scope

The exact envelope fields are `schema`, `payload`, `signatureBase64Url`.
`serverware.signedOidcSessionActivationExecutionCustody/v1` is both its schema
and the distinct root-signature domain. The payload schema is
`serverware.oidcSessionActivationExecutionCustody/v1`.

The payload is closed over:

- `schema`, current `sourceRevision`, fixed `operation` = `oidc.session.activate`;
- `consumerRole`, `processMode`, `serviceUid`, `serviceGid`, `receiverIdentity`;
- `configurationDigest`, `generationDigest`, `runtimeClosureDigest`,
  `bundleKeyDigest`, `deliveryKeyDigest`;
- `plannerBootstrap`, `issuedAtEpochNs`, `expiresAtEpochNs`, `trustMode`;
- `hardwareBacked`, `nativeStageZero`, `hsmBackedKeys`, `teeVerified`,
  `externalWitnessVerified`.

`receiverIdentity` is the exact three-digest identity:
`sessionIdentityDigest`, `measurementDigest`, `attestationReceiptDigest`.
It is an independent root assertion, not proof of a currently measured process
or permission inferred from the planner identity. Actual receiver process,
runtime identity and private-key continuity must be joined by the cold owner.
That owner requires a distinct caller-supplied `expected_receiver_identity` pin,
captured as immutable canonical bytes and compared at construction and every
original reauthentication; it must not be copied from this receiving statement.
Cold delivery must independently join that pin to its admitted runtime. This
comparison adds no measured-runtime or hardware assurance claim.

`plannerBootstrap` is exactly `{base64Url, byteCount, bytesDigest}`. It contains
the complete canonical signed planner-v3 original, at most 4 MiB; the digest
is SHA-256 of those exact bytes. The outer original is at most **8 MiB**, with
256 JSON nodes and depth four. The actual bounded integer-JSON decoder and
canonical encoder receive that outer limit; the 4 MiB configuration-bootstrap
decoder/signing wrapper is not reused for the larger envelope. Embedded
configuration remains opaque base64 until the actual inner verifier admits it.
All parsing, encoding, hashing and signature work spends the same supplied
cumulative work; a wire ceiling is not a new work allowance.

The outer root signature and canonical original are verified before embedded
planner admission. The actual planner verifier then repeats its signature,
configuration/generation/runtime, dedicated planner-key, policy, state-enrollment
and complete-vector checks. Outer configuration, generation and runtime-closure
digests must equal that genuine material, as must bundle/delivery key pins.
Planner v3 also requires both keys to differ from its journal key. No key value
is embedded, generated or inferred; actual independently supplied private keys
remain a receiver-owner obligation.

## APIs and unchanged original bounds

```text
_verify_on_work(*, custody_bytes, root_public_key,
    expected_consumer_role, work, live_window=None,
    transport_deadline_ns=None) -> _CustodyMaterial

_produce_on_work(*, payload, root_private_key, root_public_key, work,
    live_window=None, transport_deadline_ns=None) -> bytes
```

The provisioner's producer validates the same scope and genuinely verifies the
embedded signed original before signing the independent receiver statement.
It signs and verifies the actual output using the admitted root pair. It does
not manufacture an inner bootstrap, receiver identity or private key.

The frozen, private material contains `custody_bytes`, the genuinely admitted
same-call `planner`, `consumer_role`, `process_mode`, `service_uid`, `service_gid`,
owned `receiver_identity`, `attestation_interval` and `opening_sample`.
Construction is not proof; no public receiver accepts this material as an
alternative to both original signatures.

The outer positive lifetime is at most 300 seconds and must fit completely
inside the original inner launch interval. Both original clock brackets remain
checked through return, together with the caller's optional live window and
earlier absolute transport deadline. No work owner, replacement allowance,
backdated clock or renewed launch is created. Both signatures use the same
independently admitted root key supplied to this API.

`trustMode` is `trusted-host-local`; all five hardware/native/HSM/TEE/witness
flags must be false. Neither the root-asserted vector nor this receiving-purpose
signature grants action-time currentness, permission, one-use consumption or
SQL authority. This profile provides no historical fallback for expired plans.
Generic frame/replay integration is source-connected, as are the dedicated
[grant](oidc-session-activation-execution-authorizer-delivery.md),
[reserve](oidc-session-activation-execution-reserver-delivery.md) and
[SQL](oidc-session-activation-execution-sql-delivery.md) cold receiving roles.
The actual SQL service joins independent pending pins to genuine admission and
one-use issuer/executor owners. Historical completion, public permission and
protected token delivery remain separate implementation and acceptance work.
No service, key or runtime was provisioned or verified by these source changes.
