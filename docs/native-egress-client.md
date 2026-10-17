# Fixed native bootstrap client: egress observation v3

`catchplate-native-bootstrap-client` has an explicit v3 profile for one local,
authorized egress observation around a never-executed child. It admits the actual
same-TLS bootstrap proof, durably claims creation before cloning the child, and
uses the separate guarded kernel transaction/readback pipeline. It is not a
workload launcher, network-attachment mechanism, persistent deployment or CA
installer. Source connectivity is not an executed or production-accepted result.

## Independent cold inputs

The pinned CLI is unchanged:

```text
catchplate-native-bootstrap-client --configuration /absolute/client.json --configuration-sha256 sha256:<independent-64-lowercase-hex-pin>
```

The [closed configuration](../schemas/native-bootstrap-client.v3.schema.json)
is `catchplate.nativeBootstrapClient/v3`, at most 16 KiB. It requires the same
18 base fields described by the [fixed bootstrap client](native-bootstrap-client.md#explicit-inputs)
and one nonnull `egress` object with exactly these four artifact pins:

| Field | Required original |
| --- | --- |
| `authority` | Independently signed egress authorization **v2**, at most 32 KiB, including the separate signed creation journal |
| `authorityRoot` | Independently pinned canonical nonweak Ed25519 SPKI PEM, at most 16 KiB; actual owner admission enforces separate key roles |
| `capabilityToken` | Protected owner-only, single-link regular file containing exact 32–256 URL-safe ASCII bytes, without LF; its actual hash must match the dedicated egress capability |
| `launchManifest` | Protected canonical `catchplate.nativeEgressLaunchManifest/v1` original, at most 4 KiB without LF, binding the selected protected executable original, at most 16 MiB |

Each artifact pin is exactly `{ "path": "/absolute/original", "sha256":
"sha256:<64-lowercase-hex>" }`. Root, scope, identity and original pins must be
independently supplied, not learned from a capture or response. The manifest's
fixed executable/argument/environment profile does not authorize executing it.

V3 forbids `installation`, including null. V1 and v2 forbid `egress`, including
null; their existing behavior is unchanged. The v2 CA-installation token, grant,
journal and result are not egress authority. Combined CA installation and egress
is unsupported rather than implicitly composing those purposes. A v1 egress
grant can still be parsed by its internal compatibility reader, but the public
v3 path requires the separately signed v2 creation authority with no fallback.

## One original operation

The original clock begins before configuration admission. Genuine startup
verification completes first; protected egress preparation then admits the
grant, host and launch originals **before client private-key access or network
contact**. It creates no child and supplies no kernel-effect authority at that
stage. Every later step narrows or checks that same clock, never opens another
allowance.

The fixed bootstrap exchange and genuine original receiver use the actual held
TLS connection, selected caller chain, challenge, endpoint and independent
roots. The source-owned precreation owner then retains that admitted proof,
packet/configuration/CA originals, host/launcher, private token and clock. A
successful Python/JSON diagnostic cannot substitute for this owner.

The [creation journal](native-egress-creation.md) is separately preprovisioned
root:root `0700`, with signed path/device/inode/namespace distinct from the kernel
journal. Its stable namespace-plus-capability slot is claimed through exclusive
publication, file and directory fsync, and exact readback before the sole child
creation attempt. An existing, incomplete or uncertain slot never permits new
creation, retry or attachment to an old child. The permit and actual owner remain
held throughout the child's lifetime.

The child is a newly created, never-executed network-namespace owner, not the
launcher's signed host namespace. The [kernel pipeline](native-egress-kernel.md)
separately reserves exact transaction originals and durably claims before its
single fixed mutation attempt. Actual ACKs, generation-bracketed full readback
and raw-original custody are required; no arbitrary nft text or shell command is
accepted. Creation success alone does not authorize that mutation. The kernel
journal and preprovisioned backend lock remain protected and held afterward.

The client retains all actual owners through bounded output and final checks,
then owner teardown terminates the task-created child. The child is never
started, connected to a host network or adopted across invocations. Historical
claims are not recovery permission; incomplete or uncertain outcomes are not
automatically retried, repaired or rolled back.

## Nonactionable output

The [capture v3 schema](../schemas/native-bootstrap-client-capture.v3.schema.json)
contains the nine base capture fields plus required `egress`. Its API is
`catchplate.nativeBootstrapClientCapture/v3`, scope
`local-fixed-endpoint-bootstrap-and-egress-observation`, with `okForAction: false`.
One complete UTF-8 JSON line, including its final LF, is at most 1.5 MiB.

The [egress child object](../schemas/native-egress-observation.v1.schema.json)
is at most 8191 compact UTF-8 bytes and has exactly ten fields: `apiVersion`,
`resultScope`, `okForAction`, `status`, `authorizationSha256`,
`creationSlotSha256`, `creationRecordSha256`, `kernelSemanticSha256`,
`kernelEvidenceSha256` and `workload`. Its API is
`catchplate.nativeEgressObservation/v1`, scope
`local-authorized-egress-observed-before-owner-teardown`, again with
`okForAction: false`. Status is selected only from the actual retained
`Installed.created` value: `observed-created` or `observed-complete`. Neither
spelling permits a new effect. The nested workload identifiers describe actual
local observations, not portable PID, namespace, socket or continuing-ownership
authority.

The exact original bootstrap evidence remains in `evidenceBase64url` for
[data-only packet extraction](native-bootstrap-capture.md) without a second
bootstrap attempt. Extraction does not query a journal or kernel, validate an
installation result, or authorize issuance, attachment or execution. Preserve
the producing process's exit status: a parseable complete line followed by a
nonzero exit is not successful acquisition, and partial stdout is not a receipt.
The invoker must protect output redirection from aliasing inputs and retain an
external watchdog for already-blocked kernel/filesystem/output operations.

No token bytes or private key are output or journaled. Local locks and fsync are
not hostile-host isolation or off-host rollback proof. Runtime deny/allow and
connectivity evidence, workload start/network attachment/lifecycle authority,
Kubernetes ownership, provider canaries and independent production gates remain
open. No build, test, execution or provisioning claim follows from this guide.
