# Native response-observation v2 configuration

Status: source-only, unbuilt and unexecuted. This defines the
`responseObservationV2` member of
[native startup configuration](native-startup-config.md), not an attestation or
a ready custody service. The closed
[NativeResponseObservationV2ConfigV1](../data-plane/decision-gate-rs/src/response_v2/native_config.rs)
converts into the existing client configuration through `into_config()`.
Conversion reads no environment or files and contacts no service; it checks
the current UID and the transparency pin's validity against the local clock.

## Member fields

All names are case-sensitive. Unknown fields are rejected. All fields below
are required except the three explicitly optional expected pins. Those three
may be omitted or `null`; neither form supplies an expectation. Other fields
cannot be `null`. SHA-256 strings use `sha256:` followed by 64 lowercase hex
digits. Numeric fields are integers, not floats or numeric strings.

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `catchplate.nativeResponseObservationV2Config/v1`. |
| `socketPath` | Absolute, non-NUL Unix-domain socket path fitting the platform's `sockaddr_un.sun_path`. |
| `expectedUid` | Unsigned 32-bit custody UID, different from the caller's actual effective UID. The later connection must authenticate this UID. |
| `startupTimeoutMs` | Integer 1–30,000. Actual startup uses the shorter of entry time plus this interval and the original caller's absolute `CLOCK_BOOTTIME` deadline. |
| `signerKeySha256` | Independently pinned runtime-attestation role key digest. Must match that role's actual configured raw-key digest. |
| `roleIdentityRootSha256` | Exact existing domain-separated identity-root digest reconstructed from the complete configured role map. |
| `proofPinsRootSha256` | Independent proof-pin root; must match the transparency trust pin. |
| `teeVerifier` | Required closed pinned-verifier object described below. |
| `transparencyTrustPin` | Existing closed `ReleaseTransparencyTrustPinV2` object, active at validation time. |
| `roleKeys` | Array of existing closed `V2PinnedRoleKeyV1` objects; duplicate role names are rejected. |
| `generationId` | Nonempty identifier, at most 256 bytes, without ASCII control or whitespace characters. Must match every role and the transparency pin. |
| `expectedSourceCommitSha256` | Independent source-commit digest pin for the attested custody release. |
| `expectedSourceTreeSha256` | Independent source-tree digest pin for that release. |
| `expectedProviderGeneration` | Optional positive integer; if present, must equal the trust pin, every role and the actual attested generation. |
| `expectedTrustRootSha256` | Optional SHA-256 pin, checked against the actual attested trust root. |
| `expectedTrustCheckpointSha256` | Optional SHA-256 pin; if present, must equal the transparency pin and actual attested checkpoint. |
| `minimumRevocationEpoch` | Required unsigned integer; zero is permitted. Must not exceed the configured transparency pin's epoch; actual attested evidence must meet this floor. |

There are no selectable `attestationMode` or `teeTopologyProfile` fields.
Conversion always sets `TeeHardware` and `LocalSingleNodeOneOfOne`
(`local-single-node-1-of-1`). Supplying either selector is an unknown-field
error; there is no trusted-host or environment fallback.

## `teeVerifier`

This is the existing closed
[ResponseV2PinnedTeeVerifier](../data-plane/decision-gate-rs/src/response_v2/attestation.rs),
not a shell command or a claimed verification result.

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `catchplate.responseObservationV2PinnedTeeVerifier/v1`. |
| `executable` | Required absolute normalized path to the independently pinned verifier executable; at most 4,096 path bytes. |
| `executableSha256` | Required SHA-256 digest of that executable. |
| `arguments` | Optional array, default `[]`; any nonempty array is rejected. `null` is not an array. |
| `verifierModule` | Optional/nullable `ResponseV2MeasuredVerifierInput`, when that verifier profile needs a separately measured module. This does not enable interpreter arguments. |
| `expectations` | Required `ResponseV2MeasuredVerifierInput` containing independently pinned verifier expectations. |
| `trustRoots` | Required `ResponseV2MeasuredVerifierInput` containing independently pinned Nitro trust configuration. |

Each `ResponseV2MeasuredVerifierInput` is exactly
`{"path": <absolute normalized path>, "sha256": <digest>}`. Both fields are
required; unknown fields are rejected. Paths are capped at 4,096 bytes. Typed
configuration validation checks these shapes and pins; later genuine hello
verification uses the existing descriptor-pinned executable and measured-input
path. Configuration alone does not establish that those files exist, are the
admitted verifier closure or have successfully verified a quote.

## Existing role and trust schemas

`roleKeys` uses the closed
[V2PinnedRoleKeyV1 schema](../data-plane/decision-gate-rs/src/response_observation_v2_api.rs):
`role`, `generationId`, `providerId`, `providerGeneration`, `keyId`,
`keyMaterialSha256`, `keyMaterialPath`, `executableMeasurementSha256`,
`executablePath`, `providerConfigSha256`, `providerConfigPath`,
`teeMeasurementSha256`, `publicKeyBase64`, `publicKeySha256` and
`allowedOperations`. All are required. `providerGeneration` is a positive
integer; `allowedOperations` is a nonempty, sorted, unique string array.
`publicKeyBase64` uses standard Base64 for the raw 32-byte public key.
Its SHA-256 must equal `publicKeySha256`, `keyMaterialSha256` and `keyId`.
Material, executable and provider-config paths must be absolute.

The shared validator retains the complete runtime-attestation, custody and
nested-authority operation requirements and exact identity-root recipe. Every
role must name the configured generation and the transparency pin's provider
generation. Array ordering does not replace the canonical role-map hash.

`transparencyTrustPin` uses
[`ReleaseTransparencyTrustPinV2`](../data-plane/decision-gate-rs/src/response_v2/transparency_contract.rs)
and the existing
[`releaseTransparencyTrustPin` JSON definition](../schemas/response-v2-release-transparency-proof.v2.schema.json).
Its version is `catchplate.responseV2.releaseTransparencyTrustPin/v2`, kind is
`CatchplateResponseV2ReleaseTransparencyTrustPin`, and `schemaVersion` is the
string `"2"`. Include `revokedAtEpochMs: null` when not revoked, as specified by
that JSON schema; the existing Rust optional field also accepts omission as
`None`. The existing validator checks the log SPKI/digest, positive
safe-integer generations/epochs/tree sizes, active validity interval,
revocation and checkpoint-age bounds, plus generation/proof-root joins. These
ordinary supplied pins still require independent provenance and freshness.

## Bounds and actual startup boundary

The enclosing original parser caps the entire startup configuration at 16 MiB,
depth 64 and 100,000 nodes, and rejects duplicate JSON keys and floats before
typed decoding. The v2 member additionally limits roles to 1–256, operations
to at most 256 per role and aggregate role text to 1 MiB. Role, generation,
provider and operation identifiers are at most 256 bytes; other role text is
at most 4,096 bytes per field. Transparency text fields are capped at 4,096
bytes before their existing stricter semantic checks.

Successful conversion is only configuration preflight. The separate
[explicit startup constructor](../data-plane/decision-gate-rs/src/response_v2/client_transport.rs)
must connect to the actual separate custody process using the existing local
`SOCK_SEQPACKET` peer-authentication path and perform the real authenticated
hello, pinned TEE-verifier, role, release and transparency checks. The existing
sealed-descriptor/exact-object transaction gates remain unchanged.

The returned health flag is the actual `providers_ready` value and may be false.
The [owned lifecycle](native-runtime-lifecycle.md) performs fresh probes and
readiness checks before serving. Neither config conversion nor hello success
provisions the opaque custody/authority services, makes them enclave-owned,
proves readiness or provides multi-node fault tolerance. Original deadline
checks reject late completion but do not interrupt a kernel-blocked filesystem
operation or supply a hard watchdog.
