# Native pilot authority commands

These are purpose-specific commands for an independently operated authority,
not independent approval automation or a pilot quickstart. They produce the existing
cohort precreation/release, driver admission/continuation, native and ordinary
delivery, and ordinary service grants from explicitly approved input. Restricted
installers publish literal public originals and the fixed endpoint-precreation
configuration bundle at the paths consumed by the existing pilot owners.

The commands do not generate keys, approve their own inputs, start the pilot,
provision private service credentials or replace any independent signer. A protected
input FD means stable file ownership, not independent approval. The authority
operator must approve the complete input before supplying that FD and its
matching key. Do not connect untrusted conductor JSON directly to a signing
command without that authority's own approval and observation checks.

## Authority-side execution

Use a separately admitted Linux Python runtime and protected source/dependencies.
These commands are deliberately not added to the conductor's two-script runtime
package. Run them under an external supervisor, on the admitted pilot host and
time namespace: their existing producer profiles bind the actual local boot and
BOOTTIME clock. Off-host issuance needs an independently authenticated equivalent
observation path; it cannot substitute its own boot or start a fresh window.

The examples name inherited descriptors, not files to create or keys to paste:

```text
python3 -I -B scripts/authority/sign_native_pilot_cohort.py --operation precreation --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_cohort.py --operation release --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_scope.py --input-fd 3 --authority-key-fd 4
```

FD 3 must hold the independently approved canonical ASCII JSON input, without
a terminal newline. It must be a root:root `0400` read-only, single-link regular
file, or a sealed `0400` memfd. FD 4 must be the already provisioned root:root
`0400`, 32-byte Ed25519 authority memfd with write/grow/shrink/seal seals. The two
descriptors must be distinct and at least 3; the helpers mark them non-inheritable.
The purpose-specific producer verifies the key against its approved authority.
There is no default key or key generation path.

Stdout must be a root-owned supervisor pipe. It receives only the existing signed
original, without a newline. Capture the complete output and successful exit
before treating it as available; a partial write is an unknown failed output,
not permission to sign again. Output writes are nonblocking and bounded to one
second or the original startup deadline, whichever is earlier. The external
supervisor must additionally bound filesystem/crypto stalls and retain failure
state; this is not a hard-real-time Python runtime. Input bytes are reread before
output, and failure diagnostics never include keys or original documents.

The sealed software-key interface is inherited from the existing authority
producers. It is not non-exportable KMS/HSM custody, measured execution or a
zeroization guarantee. The helper requires isolated/no-bytecode Python and
disables process dumps before reading a key. Those controls do not establish
the outstanding production custody requirements.

## Exact input contracts

The cohort command accepts `serverware.nativePilotCohortAuthorityInput/v1`,
bounded to 2 MiB, with these exact common fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | The wrapper version above. |
| `operation` | `precreation` or `release`, matching the CLI selection. |
| `configurationOriginal` | Exact cohort configuration/v7 bytes as an ASCII string. |
| `configurationSha256` | Independently approved pin of those configuration bytes. |
| `coldOriginals` | Exact fixed ten endpoint role names, each mapping to its literal cold configuration. No bridge role. |
| `payloadOriginal` | Approved existing precreation/release payload, not fields invented by the command. |

Release additionally requires `precreationOriginal` and `observationsOriginal`.
The command reuses `native_shadow_proof_cohort_assignment.sign_precreation` or
`sign_release`, including their existing cold-key, external-driver, signature,
role, descriptor and original-window bindings. It does not reconstruct a live
cohort from observations or turn a constructed notice into readiness.

The scope command accepts `serverware.nativePilotScopeSigningInput/v1`, bounded
to 4 MiB, with exactly `apiVersion` and these eight literal ASCII originals:

```text
configurationOriginal       windowOriginal
observationOriginal         operationOriginal
publicBundleOriginal        deliveryConfigurationOriginal
launchOriginal              bootstrapAdmissionOriginal
```

It produces the existing `serverware.nativeShadowDriverScope/v4` signed envelope.
The approved configuration/window, bootstrap admission, actual operation and
public bundle determine the scope. Existing signature domains and authority
bindings remain unchanged. It supplies no live `DriverBootstrap` owner and does
not claim that the referenced descriptor inventory, bridge, generation or
request has independently passed runtime acceptance.

## Protected publication

`scripts/install_native_pilot_public_original.py` accepts only source-fixed
purposes. Its public input is a protected root:root `0400` read-only single-link
file on an inherited FD. No authority private-key FD is accepted.

| Purpose | Fixed destination |
| --- | --- |
| `cohort-precreation` | `/etc/serverware/native-shadow-proof-cohort-precreation.json` |
| `cohort-release` | `/etc/serverware/native-pilot-inputs/cohort-release.json` |
| `driver-scope` | `/etc/serverware/native-pilot-inputs/driver-scope.json` |

The additional purposes below use
`/etc/serverware/native-pilot-inputs/<purpose>.json`. Role suffixes are the exact
fixed inventory, never a caller-supplied path or extensible role list.

| Purpose family | Fixed selection | Maximum bytes |
| --- | --- | --- |
| `driver-bootstrap-admission`, `driver-constructed-admission` | Two existing driver admission envelopes | 8,192 / 16,384 |
| `native-delivery-<role>` | Ten cohort endpoint roles plus `bridge` | 65,536 |
| `ordinary-delivery-<role>`, `ordinary-generation-<role>` | Five ordinary roles | 65,536 |
| `ordinary-dispatch-<role>` | DRS and CurrentSignatureAuthority only | 65,536 |
| `ordinary-head`, `ordinary-cleanup`, `ordinary-current` | DRS, Cleanup, Current respectively | 65,536 / 131,072 / 131,072 |
| `native-cold-<role>`, `ordinary-cold-<role>` | Ten endpoint and five ordinary cold configurations | 65,536 |
| `bridge-runtime` | Approved bridge runtime/v9 public original | 65,536 |
| `native-generation-install-grant` | Existing native coordinator assignment envelope | 65,536 |

The precreation installer also uses `cohort-configuration`, `ordinary-launch`
and `cohort-control` at their fixed `/etc/serverware/` loader paths. Their limits
are respectively 32,768, 65,536 and 4,096 bytes. The original three purposes keep
their 32,768-byte ceilings. `bridge-outgoing` uses the fixed
`/etc/serverware/native-shadow-driver-outgoing.json` loader path with an
8,192-byte bound. Aggregate publication stays bounded to 128 originals
and 32 MiB. Native C9 files are delivery originals, **not** endpoint/bridge launch
envelopes; independently approved launch files must still reference them.

```text
python3 -I -B scripts/install_native_pilot_public_original.py --purpose cohort-release --input-fd 3 --sha256 sha256:INDEPENDENTLY_APPROVED_ORIGINAL_DIGEST
```

The placeholder is intentionally invalid. All parent directories must already
exist under protected root ownership; this command does not create or repair
them. It validates the exact purpose envelope shape and supplied byte pin,
creates a new `0400` file exclusively, fsyncs and reads back the actual bytes,
then emits the existing `{path,sha256}` pin. Publication does not verify signing
authority: the pilot's purpose-specific consumers still authenticate the original.
There is no overwrite, leftover adoption, delete, automatic retry or deadline
renewal. A failed publication leaves its exact partial file for explicit
reconciliation, even if output delivery subsequently fails.

## Driver, delivery and ordinary service producers

These commands use the same approved-public-FD/sealed-key-FD contract and
supervisor pipe as the earlier authority commands:

```text
python3 -I -B scripts/authority/sign_native_pilot_driver.py --operation bootstrap --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_driver.py --operation constructed --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_delivery.py --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_service.py --operation generation --role durable-recovery-store --input-fd 3 --authority-key-fd 4
```

Driver input is the closed `serverware.nativePilotDriverAuthorityInput/v1`
wrapper (at most 24 MiB). Common fields are `apiVersion`, `operation`,
`controlOriginal`, `configurationOriginal`, `windowOriginal`,
`deliveryConfigurationOriginal` and `payloadOriginal`. Bootstrap adds
`observationOriginal`. Constructed adds `bootstrapAdmissionOriginal`,
`censusOriginal`, `publicAdmissionOriginal`, `verifierConfigurationOriginal`,
`verifierConfigurationSha256`, `assignmentPublicKeyOriginal`,
`assignmentPublicKeySha256` and `launchOriginal`. Trust/key configuration and
pins must be independently approved, not taken from an untrusted measurement's
own key selection. The producer checks exact prepared payload associations and
existing signature domains; it does not authenticate kernel observations or
re-run hardware attestation merely by parsing exported originals.

Delivery input is the closed `serverware.nativePilotDeliverySigningInput/v1`
wrapper (at most 1 MiB): `apiVersion`, `role`, `configurationOriginal`,
`ownerConfigurationOriginal`, `windowOriginal`, `observationOriginal`,
`runtimeOriginal`, `payloadOriginal`, `activationOriginal`. Endpoint owners use
cohort/v7 and signed precreation; bridge ownership uses driver/v4 and its signed
window. The activation original is a canonical array matching the actual
operator observation. Fixed inventories select the exact endpoint descriptors
or the runtime/v9-derived 41-descriptor bridge. No peer, socket, journal or
runtime configuration is fabricated by the signer.

Ordinary-service input is `serverware.nativePilotServiceAuthorityInput/v1`
(at most 32 MiB), with common fields `apiVersion`, `operation`, `serviceRole`,
`launchOriginal`, `payloadOriginal`. Operation and CLI role must agree:

| Operation | Roles | Additional approved input |
| --- | --- | --- |
| `delivery` | All five | `configurationOriginal`, `configurationSha256`, `runtimeOriginal`, actual `activation` array |
| `generation` | All five | `services` containing the selected role |
| `dispatch` | DRS, Current | Selected `services`, `nativeGrantOriginal`, `nativeConfigurationOriginal`, `nativeConfigurationSha256` |
| `head` | DRS | DRS and Cleanup `services`, exact seven `nativeOriginals` |
| `cleanup` | Cleanup | Same two `services` and `nativeOriginals`, plus `headGrantOriginal` |
| `current` | Current | All three `services` and `nativeOriginals`, plus `headGrantOriginal`, `cleanupGrantOriginal` |

Each service bundle contains `configurationOriginal`, `configurationSha256`,
`deliveryOriginal`, `runtimeOriginal`, `historyOriginal`; all operations except
generation also include `generationGrantOriginal`. The ordinary launch is the
approved existing FiveServiceLaunch/v6, not a fresh clock. Existing byte
producers handle delivery/generation/dispatch; the effects grants bind the
actual signed public predecessors without constructing a `GenerationInputs`
owner. Native signature/quote/currentness and retained-resource admission remain
with their purpose-specific receivers; no output is a service-ready verdict.

## Endpoint-precreation configuration installation

```text
python3 -I -B scripts/install_native_pilot_precreation.py --input-fd 3 --input-sha256 sha256:INDEPENDENTLY_APPROVED_BUNDLE_DIGEST
```

This is a real filesystem mutation when invoked, not a planning command. Its
closed `serverware.nativePilotPrecreationBundle/v1` input (at most 4 MiB) has
exactly `apiVersion`, `driverConfigurationOriginal`, `driverWindowOriginal`,
`driverObservationOriginal`, `cohortConfigurationOriginal`,
`cohortPrecreationOriginal`, `cohortControlOriginal`, `ordinaryLaunchOriginal`,
`nativeColdOriginals` and `ordinaryColdOriginals`. The last two maps contain the
fixed ten/five literal cold originals. The independently approved bundle digest
binds every byte; a digest computed locally after accepting untrusted input is
not independent approval.

Before creating anything, the installer checks the complete bundle, signed
driver/precreation windows, external-driver observation binding, all cold-file
pins and the fixed destination names. It preflights all 19 names for absence,
then publishes the 15 cold originals, cohort configuration, precreation and
ordinary launch; **cohort control is last**. Every creation remains exclusive,
with fsync and exact readback. Preflight is not a filesystem transaction: a
later race or failure can leave a partial bundle. It is never rolled back,
adopted, overwritten or automatically retried.

Cohort and driver retain their existing equal window binding. Ordinary services
keep their supplied original interval; publication and output use the earliest
startup deadline without extending either window. Successful installation only
reports file pins. It neither starts a service, acknowledges conductor progress,
nor proves a pilot request or cleanup succeeded.

## Protected bridge runtime installation

```text
python3 -I -B scripts/install_native_pilot_bridge.py --input-fd 3 --input-sha256 sha256:INDEPENDENTLY_APPROVED_BUNDLE_DIGEST
```

This command mutates only the two public files needed before actual bridge
outgoing-resource allocation. The approved canonical no-LF input is
`serverware.nativePilotBridgeRuntimeBundle/v1`, at most 512 KiB, with exactly:

```text
apiVersion                 driverControlSha256
driverObservationOriginal  runtimeOriginal
outgoingOriginal
```

The three originals are literal ASCII strings. Observation/runtime are bounded
to 65,536 bytes each; outgoing configuration to 8,192. The control pin is
independently approved, not calculated to bless an untrusted conductor request.
The installer opens and retains the existing protected fixed driver control,
configuration and signed window, plus their pinned bridge cold configuration.
It checks supplied observation associations and the unchanged original boot/time
window, then uses the existing runtime/v9, bridge-launch/v5 outgoing selector
with that actual cold UID. It does not authenticate kernel provenance from JSON.

After complete preflight, publication is exclusively:

1. `/etc/serverware/native-pilot-inputs/bridge-runtime.json`
2. `/etc/serverware/native-shadow-driver-outgoing.json`

The outgoing original must pin the exact first file and retained driver
configuration/window/observation/invocation. Existing `PublicPublisher` creates
root:root `0400` originals with fsync/readback; all held inputs are rechecked
around publication. Partial files remain on failure; no overwrite or retry is
provided. Successful output contains installed pins under
`serverware.nativePilotBridgeRuntimeInstallation/v1`, not a ready verdict or an
automatic `bridge-runtime` protocol acknowledgment. Stdout remains clipped to
the original startup deadline and the shared bounded pipe-write contract.

Only after the supervisor validates successful installation may it acknowledge
that phase and allow the conductor's real `prepare_bridge_connections()` call.
The later C9 delivery binds the actual allocated descriptors. Runtime history
and authority-key credential names are not credential contents: separate private
provisioning, later complete C9/launch originals and actual native admission are
still mandatory. This installer neither receives nor writes service secrets,
keys, invented histories, C9 deliveries or launch files.

## Initial generation-install authority

```text
python3 -I -B scripts/authority/sign_native_pilot_generation_install.py --input-fd 3 --authority-key-fd 4
```

The independently approved no-LF wrapper uses
`serverware.nativePilotGenerationInstallAuthorityInput/v1` and exactly:

```text
apiVersion                    payloadOriginal
nativeConfigurationOriginal   nativeConfigurationSha256
assignmentPayloadOriginal     cohortConfigurationOriginal
precreationOriginal           observationOriginal
coordinatorConfigurationOriginal
coordinatorDeliveryOriginal   coordinatorRuntimeOriginal
ordinaryLaunchOriginal        services
genesisOriginal               recordOriginals
```

`services` is the fixed ordinary-five map. Each member has the existing service
authority bundle fields (`configurationOriginal`, `configurationSha256`,
`deliveryOriginal`, `runtimeOriginal`, `historyOriginal`) plus
`generationGrantOriginal`. Originals are literal canonical ASCII strings.
The native configuration and all original approvals/keys must come from the
independent authority, not be selected to bless an untrusted pipe request.

This is explicitly an **initial-install-only issuer**. It requires the supplied
`keyHistory` to contain epoch one and no predecessors, all five authenticated
service scopes to have no previous configuration, an explicitly empty
`recordOriginals` array, and a supplied journal with sequence zero and head equal
to its supplied genesis hash. It creates none of those facts. Historical key
transitions and restored journal signing require their own verified producer
path and remain open; the existing Rust historical verifier is not weakened.

The output is the existing `nativeGenerationCoordinatorAssignment/v1` payload
and `signature` envelope, bounded to 65,536 bytes. It retains the existing
signature domain and original host/window/output deadline. The fixed public
publication purpose is `native-generation-install-grant`, beneath
`/etc/serverware/native-pilot-inputs/`; publication is not signature admission,
actual generation installation or pilot readiness.

## What remains

These commands close specific producer/publication gaps. The implemented
[process coordinator and eleven-phase relay](native-pilot-coordinator.md) owns
the real conductor process and transport, but does not automate independent
approval, signing or installation. Still required are that authority's actual
approval/observation and supervision, all required service-grant and launch
originals, artifact assembly and protected installation, service/private-input
and workload provisioning, then the connected ordinary application allow/deny
and cleanup run. No command in this guide was executed when authored.
