# Native startup CLI and pinned originals

Status: source-only, unbuilt and unexecuted. The decision gate now has an
explicit opt-in CLI that parses pinned originals and invokes the actual
[native startup sequence](native-startup.md). This is not signed configuration
admission, deployed service provisioning or proof of a production-ready enclave.

## Exact command selection

The [CLI parser](../data-plane/decision-gate-rs/src/native_startup_config/cli.rs)
accepts this shape; the paths/digests below are placeholders, not a ready launch:

```text
serverware-decision-gate --native-startup \
  --configuration /approved/private-native-configuration.json \
  --configuration-sha256 sha256:<exact-configuration-original-digest> \
  --launch /approved/native-launch.json \
  --launch-sha256 sha256:<exact-launch-original-digest>
```

`--native-startup` must be first; all four named options are required exactly
once. Unknown, duplicate, missing or malformed arguments fail. With no arguments,
the existing environment-driven startup remains unchanged. Native parsing or
startup failure never falls back to that legacy path. No environment default
fills missing native configuration.

Configuration contains service bearer tokens: provision it privately and never
paste it into chat, logs or public examples. Digest pins are nonsecret byte
identifiers, not the token contents or evidence of authorization. The loader
requires the configuration file to have no group/other permission bits, one
hard link, and ownership by root or the effective caller; 0400/0600 are usual
file modes. These local POSIX checks are not encryption, hostile-host isolation
or admission of ACL/mount provenance. Raw configuration bytes use a zeroizing
buffer, without claiming that every parsed copy or runtime token is wiped.

## Top-level configuration

[ConfigurationV1](../data-plane/decision-gate-rs/src/native_startup_config/mod.rs)
has exactly these required camelCase fields:

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `serverware.nativeStartupConfiguration/v1`. |
| `gate` | The [closed gate configuration](native-config-gate.md), including service tokens, policy trust and supplied checkpoint. |
| `native` | The native settings below. |
| `shadow` | The shadow settings below. |
| `responseObservationV2` | The [closed v2 configuration](native-config-v2.md) and its existing role/trust originals. |
| `policy` | Artifact reference for the original signed-policy bytes. |

An artifact reference is exactly `{ "path": ..., "sha256": ... }`: an absolute
path and canonical lowercase `sha256:` digest. A pinned verifier description is
exactly `{ "executable": ..., "arguments": [], "sha256": ... }`. `arguments`
is required and must be empty; this is not an arbitrary command-line adapter.
The existing verifier owner still performs actual executable admission/use.

The bounded strict JSON parser rejects duplicate keys, floating-point values,
trailing data, depth over 64 and more than 100,000 nodes. Typed contracts reject
unknown fields and require their non-optional fields. No canonical whitespace
or member ordering is imposed on input JSON: its **exact original bytes**, not
a reserialized object, are pinned. Formatting changes therefore change its
configuration digest.

## Native settings

[NativeSettingsV1](../data-plane/decision-gate-rs/src/native_startup_config/parameters.rs)
has exactly these required fields, with no nested `apiVersion`:

| Field | Meaning and bounds |
| --- | --- |
| `ingressHost` | Bounded DNS/IP name for the generated ingress certificate; SPIFFE identity comes from `gate.instanceId`. |
| `ingressClientRootsDerBase64url` | 1–32 original DER certificates, canonical unpadded base64url; each nonempty and at most 64 KiB, at most 1 MiB total. Actual TLS construction rejects duplicates/invalid roots. |
| `controlPlaneResponsePublicKeyPem` | Actual Ed25519 SPKI public-key PEM, nonempty and at most 4,096 bytes; no private key. |
| `controlPlaneResponseKeyId` | SHA-256 of that actual SPKI, joined again by native custody. |
| `attemptLedgerDirectory` | Bounded absolute existing ledger directory; no initialization/provisioning shortcut. |
| `relayAssignments` | 1–32 exact objects with `host`, literal `endpoint` socket address, and `parentPort`; the actual relay owner enforces its canonical table and fixed-endpoint joins. |
| `listenerPort` | Fixed vsock port, greater than 1,023 and not `u32::MAX`; expected parent CID is source-fixed to 3. |
| `expectedPolicySigningKeyId` | Explicit canonical SHA-256 signing-key pin for actual signed-policy compilation. |
| `runtime` | Exact worker settings below. |

`runtime` requires `proxyWorkers` (1–24), `proxyQueueCapacity` (1–4,096),
`policyIntervalMs` (50–60,000) and `auditIntervalMs` (10–60,000). These are local
resource bounds, not independently admitted capacity. Relay assignments and
TLS trust do not authorize application paths or prove the parent's network route.

## Shadow settings

[ShadowConfigV1](../data-plane/decision-gate-rs/src/native_startup_config/shadow.rs)
requires exactly `trustManifest`, `runtimeVerifier`, `webauthnVerifier`,
`publicationHandoff`, `custodyConfig` and `startupActiveAuthorization`.
`trustManifest`, `custodyConfig` and `startupActiveAuthorization` use the artifact
form; the other three use the no-argument pinned-verifier form.

The conversion supplies actual pins to the existing shadow owner, including
the custody-config content pin and original startup-active authorization. It
does not introduce a pending startup-generation installation field. The actual
constructor checks its original resources; later signed-policy preparation
still joins the startup authorization to the actual snapshot. These references
are not a successful-authorization DTO or authority to skip either step.

## Separately pinned launch

The launch original has exactly these required fields:

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `serverware.nativeStartupLaunch/v1`. |
| `releaseRecordSha256` | Canonical SHA-256 release-record reference; this loader does not verify or admit that record. |
| `configurationSha256` | Must equal the CLI configuration pin, already checked against the actual configuration original. |
| `deadlineBoottimeNs` | Unsigned absolute `CLOCK_BOOTTIME` deadline for this launch, not a renewable duration. |
| `caNotBeforeUnixSeconds`, `caNotAfterUnixSeconds` | Signed integer Unix-second CA times. |
| `ingressNotBeforeUnixSeconds`, `ingressNotAfterUnixSeconds` | Signed integer Unix-second ingress-certificate times. |
| `ingressNonceBase64url`, `proofNonceBase64url` | Each canonical unpadded base64url of a 32-byte value other than all-zero. |

Actual startup requires live certificate intervals, a positive CA interval of
at most 24 hours, and an ingress interval within it. Local time checks and
nonzero nonce shape do not establish trusted time, nonce freshness/reservation
or an independently current release.

The split avoids embedding a configuration's own hash inside itself. Native
scope commitments come from the separately supplied launch's release reference,
`gate.policyHighWater.policyHash`, and SHA-256 of the **actual static configuration
original**. Sequence/rollback floors come from that same supplied checkpoint.
The policy artifact pin identifies raw signed-policy file bytes, not the compiled
policy hash. Genuine preparation must still compile/admit the signed policy and
join its digest to the checkpoint and retained native identity. Neither an
ordinary checkpoint nor a matching hash proves independently latest state.

## Original custody and unchanged limits

The retained [original loader](../data-plane/decision-gate-rs/src/native_startup_config/originals.rs)
reads the configuration (16 MiB maximum), launch (16 KiB) and policy (8 MiB).
All three must be nonempty regular files at exact canonical absolute paths of
at most 4,096 bytes. Every actual path component is opened relative to a held
directory with no-follow flags; final files also use close-on-exec/nonblocking
opens. Symlink aliases, including ancestor aliases, are rejected.

Actual bytes must match the independent SHA-256 pin, with held metadata checks
before and after reading. Before handing off to startup, all three retained
files are reread/rehashed and their current names rejoined to their held
identities; the configuration-only privacy guard is repeated. Failed rechecks
poison that owner. The owners remain held through the call, but there is no
periodic config reload or claim of an atomic hostile-host filesystem snapshot.
Policy execution retains the admitted original bytes rather than reopening the
path for each refresh. Shadow/v2 referenced resources retain their own existing
admission rules; this loader's three-file claim is not a blanket guarantee for
every configured path.

The successful handoff executes real native startup and owned serving. It adds
no deployed daemon, parent relay provisioning, v2/custody service provisioning,
signed configuration/current release admission, KMS Recipient release or latest
off-host witness/rollback custody. Blocking filesystem, NSM and service work
still needs an outer watchdog. Immutable packaging, independent pin/hardware
admission and consolidated frozen build/runtime validation remain required;
none was executed for this source slice.
