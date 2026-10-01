# Native pilot authority commands

These are purpose-specific commands for an independently operated authority,
not independent approval automation or a pilot quickstart. They produce the existing
cohort precreation/release, driver admission/continuation, native and ordinary
delivery, native endpoint key/admission authorizations, and native and ordinary
service grants from explicitly approved input.
Restricted installers publish literal public originals, configuration bundles
and fixed endpoint/bridge launches at the paths consumed by the pilot owners.

The commands do not generate keys, approve their own inputs, start the pilot,
provision private service credentials or replace any independent signer. A protected
input FD means stable file ownership, not independent approval. The authority
operator must approve the complete input before supplying that FD and its
matching key. Do not connect untrusted conductor JSON directly to a signing
command without that authority's own approval and observation checks.

## Authority-side execution

The [native key-authorization issuer](native-pilot-key-authorizations.md) now
supplies the existing role-key/v2 and admission/v1 signatures for each of ten
actual endpoint deliveries. Its two fixed operations use separate approved
inputs and the assignment-authenticated supervisor capability. The second
consumes the real first signed original. Twenty source-fixed decisions are now
in the coordinator; this is not Nitro attestation or a native admission result.

The [ordinary current-key issuer](native-pilot-ordinary-key-authorization.md)
produces an existing v3 checkpoint under an authenticated supplied fresh retained
epoch. Its `--input-fd` and `--authority-key-fd` select independently approved
originals and the distinct checkpoint key. This successor command is not a
cold-history bootstrap or a running-service proof.

The separate [ordinary initial-history ceremony](native-pilot-ordinary-initial-history.md)
uses actual parked-child/empty-resource observations and an independently
approved initial state. `sign_native_pilot_ordinary_initial.py` issues checkpoint
one, obtains three separate one-key anchor signatures, then verifies and
assembles the explicit wrapper without a private key. Typed INITIAL commitments
are not past receipts. Native opt-in admission checks the actual process and
empty directories before gates write; legacy raw history remains unchanged.
Supervisor history/runtime/delivery wiring has since landed, followed by
generation, native-delivery, key-authorization and native-service decisions. Current coverage is
80/105 fixed jobs, 25 unsupported and 0/6 production acceptance; these commands
do not bypass the startup guard. See [current supervisor scope](native-pilot-supervisor.md).

The [driver-window issuer](native-pilot-window-authority.md) handles the existing
pre-start Window/v1 under the bootstrap authority. The
[bootstrap installer](native-pilot-bootstrap-installation.md) verifies that
window and the actual fixed supervisor executable before publishing the control
file last. The separate [closure issuer](native-pilot-closure-authority.md)
authorizes the v2 late-runtime execution closure after genuine observation and
C9 delivery. None is called by the current 105-job coordinator, and none supplies
the missing independently authorized commissioning decision engine.

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

The initial-history command additionally has the fixed operations `checkpoint`,
`root-anchor`, `checkpoint-anchor`, `service-anchor` and `assemble`. Each requires
its own complete independently approved input; the latter stages consume actual
prior public outputs. For example:

```text
python3 -I -B scripts/authority/sign_native_pilot_ordinary_initial.py --operation checkpoint --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_ordinary_initial.py --operation root-anchor --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_ordinary_initial.py --operation checkpoint-anchor --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_ordinary_initial.py --operation service-anchor --input-fd 3 --authority-key-fd 4
python3 -I -B scripts/authority/sign_native_pilot_ordinary_initial.py --operation assemble --input-fd 3
```

These are separate invocations with separately supplied purpose-matching FDs,
not a script which provisions inputs or loads all three private keys. Assembly
forbids `--authority-key-fd`. The [ceremony guide](native-pilot-ordinary-initial-history.md)
specifies its exact input11/12/13 contracts and wrapper4. The current coordinator
connects that ceremony and publishes only each complete assembled wrapper.

FD 3 must hold the independently approved canonical ASCII JSON input, without
a terminal newline. It must be a root:root `0400` read-only, single-link regular
file, or a sealed `0400` memfd. FD 4 must be the already provisioned root:root
`0400`, 32-byte Ed25519 authority memfd with write/grow/shrink/seal seals. The two
descriptors must be distinct and at least 3; the helpers mark them non-inheritable.
The purpose-specific producer verifies the key against its approved authority.
There is no default key or key generation path.

Stdout must be a root-owned supervisor pipe. It receives only the purpose-specific
signed original, detached signature or verified public wrapper, without a newline.
Capture the complete output and successful exit
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

## Per-job approval installation

The separate supervisor-side `scripts/install_native_pilot_approval.py` connects
an existing independent approval to the fixed files and reply consumed by the
[authority coordinator](native-pilot-coordinator.md). It issues no approval or
signature and accepts no key, command or destination argument.

```text
python3 -I -B scripts/install_native_pilot_approval.py --request-fd 3 --approval-fd 4 --approval-sha256 sha256:INDEPENDENTLY_APPROVED_APPROVAL_DIGEST --input-fd 5 --input-sha256 sha256:INDEPENDENTLY_APPROVED_INPUT_DIGEST
```

These placeholders are deliberately invalid. The three distinct descriptors
use the protected public-FD contract above. They contain, respectively, the
actual canonical `nativePilotAuthorityJobRequest/v1`, the already approved
`nativePilotAuthorityJobApproval/v1`, and the complete purpose-specific input.
The request is observation data, never approval. The supplied hashes must come
from the independent decision; recomputing them from unapproved bytes does not
meet that prerequisite. The request ceiling is 32 MiB minus its channel LF;
approval is at most 8 KiB, and input retains its existing per-job byte ceiling.

The installer derives both destinations solely from the existing fixed job
table, under `/etc/serverware/native-pilot-authority/<phase>/`. All ancestors
must already be root-owned and non-group/other-writable. It refuses either
existing target, writes the exact `<job>.input.json` first and
`<job>.approval.json` last as exclusive root:root `0400` single-link files, then
fsyncs, reads back and retains/checks both originals before returning the existing
exact ten-field job reply. It checks the original absolute BOOTTIME deadline
and unchanged local boot/time namespace throughout; it cannot renew a window
or attest that the supplied request owns a process. Run on the admitted pilot
host/time namespace. The coordinator's retained request and purpose producer
still perform their actual admission checks.

Stdout is the root-owned supervisor pipe, with canonical reply bytes and no LF.
Only after successful exit and complete output may the supervisor forward that
reply with the channel's one LF. Output is clipped to the original deadline.
Filesystem stalls still require external supervision. Installation is not an
atomic transaction: a failed write, deadline or output leaves all partial files
for explicit reconciliation, with no rollback, adoption or automatic retry.
This CLI requires separately protected supervisor source/dependencies; it is not
added to either conductor or authority runtime entrypoint/package. No pilot or
service is started, and no execution/readiness result follows from installation.

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
| `native-generation-install-grant` | Native coordinator assignment; v1 retains its old limit | 4,194,304 for v2; 65,536 for v1 |
| `native-service-<operation>` | Ten native operations listed below, version-checked | 4,194,304 for the seven history-bearing successors; 65,536 otherwise |
| `native-launch-<role>` | Ten endpoint roles plus `bridge` | 32,768 |
| `native-runtime-<role>` | Ten endpoint roles only; bridge uses `bridge-runtime` | 65,536 |
| `native-<role>-trust`, `native-<role>-closure` | Eleven launch roles | 1 MiB each |
| `native-<role>-assignment` | Eleven launch roles | 4 MiB |
| `native-<role>-time-bootstrap`, `-keys`, `-encrypted-keys`, `-admission` | Eleven launch roles, each suffix appended to `native-<role>` | 65,536 each |
| `native-<role>-verifier` | Eleven independently pinned verifier transport originals | 32,768 |

The precreation installer also uses `cohort-configuration`, `ordinary-launch`
and `cohort-control` at their fixed `/etc/serverware/` loader paths. Their limits
are respectively 32,768, 65,536 and 4,096 bytes. The original three purposes keep
their 32,768-byte ceilings. `bridge-outgoing` uses the fixed
`/etc/serverware/native-shadow-driver-outgoing.json` loader path with an
8,192-byte bound. The 4 MiB global single-original ceiling does not enlarge any
older per-purpose limit. Aggregate publication stays bounded to 128 originals
and 32 MiB. Native C9 files are delivery originals, **not** endpoint/bridge launch
envelopes; the launch installer below references their retained exact pins.

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

## Native operational grant producers

```text
python3 -I -B scripts/authority/sign_native_pilot_native_service.py --operation retrieval --input-fd 3 --authority-key-fd 4
```

The approved `serverware.nativePilotNativeServiceAuthorityInput/v1` input is
bounded to 4 MiB and has these exact 15 common fields, plus only the selected
operation's fields below:

```text
apiVersion                    operation
configurationOriginal         configurationSha256
assignmentPayloadOriginal     cohortConfigurationOriginal
precreationOriginal           observationOriginal
coldConfigurationOriginal     deliveryOriginal
runtimeOriginal               peerOriginal
peerSha256                    issuedAtUnixNanos
expiresAtUnixNanos
```

`configurationOriginal` is the independently approved native verifier/key
admission configuration, distinct from the cold C9 configuration. All named
originals are literal canonical ASCII strings; pins and epoch bounds are
supplied, not generated. CLI and input operation must match. In this table,
**S** means the three additional fields `spoolScopeOriginal`,
`proofScopeOriginal`, `originVerifierOriginal`—not an input field named `S`.
Every signature domain is fixed by the operation:

| Operation | Additional fields | Existing signature domain |
| --- | --- | --- |
| `ingress` | S | `serverware.nativeShadowIngressServiceAssignment.signature/v1` |
| `ledger` | S, `companionPin`, `companionOriginal` | `serverware.nativeShadowLedgerSpoolServiceAssignment.signature/v2` |
| `terminal` | S | `serverware.nativeShadowTerminalSpoolServiceAssignment.signature/v1` |
| `dispatchBarrier` | S | `serverware.nativeShadowDispatchBarrierServiceAssignment.signature/v1` |
| `activeEffectBarrier` | S | `serverware.nativeShadowActiveEffectBarrierServiceAssignment.signature/v1` |
| `activeEffectCommit` | S | `serverware.nativeShadowActiveEffectCommitServiceAssignment.signature/v1` |
| `retrieval` | `spoolScopeOriginal`, `proofScopeOriginal`, `endpointDeliveryResultOriginal`, `nativeGrantOriginals` | `serverware.nativeLedgerSpoolRetrievalGrant.signature/v3` |
| `commitRequest` | `commitmentScopeOriginal` | `serverware.nativeShadowCommitRequestServiceAssignment.signature/v1` |
| `persistence` | `proofScopeOriginal`, `genesisOriginal`, `journalOriginal`, `permissions` | `serverware.nativeShadowPersistenceServiceAssignment.signature/v1` |
| `trustedTime` | `bootstrapOriginal` | `serverware.nativeShadowTrustedTimeServiceAssignment.signature/v1` |

Legacy outputs are the existing `{payload,signature}` envelopes, at most 65,536 bytes,
published under `native-service-<operation>`. `commitRequest` produces the
separate companion grant for the same actual ledger guest; `ledger` verifies
that original before binding its pin. Retrieval's `nativeGrantOriginals` has
exactly the six signer operation names (`ingress`, `ledger`, `terminal` and the
three effects), each containing its already signed original.
`endpointDeliveryResultOriginal` carries the retained three endpoint guests and
physical `spoolJournal` observation from the preceding endpoint-deliveries
phase; it is not substituted for a live resource owner or approval.

The producers preserve existing signature transcripts, original boot/time
namespace and startup deadline, and authenticate the supplied predecessor
associations. They do not synthesize peers, journal history, permissions, keys
or evidence. Native operational consumers still check their actual retained
resources, trusted time and admission before use.

Explicit input/v3 adds the actual ordinary launch and complete five-service
contexts for CommitRequest and the six spool operations; CommitRequest also
requires `runtimeEvidence` and the actual `assignmentOriginal`. Their eight
output successor versions (including GenerationInstall below) and changed
version-specific limits are documented in
[operational-history handoff](native-pilot-operational-histories.md).
Retrieval input/v4 accepts all six actual new spool grants while preserving its
existing fresh output/v4. New native inputs are bounded to 32 MiB; legacy
inputs retain 4 MiB. Explicit supervisor/v9 composes these through the shared
pure payload validators also used by the real live signing wrappers; payload
preparation is not signing or live acceptance.

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

Explicit input/v2 preserves the fifteen-field input and selects
`nativeGenerationCoordinatorAssignment/v2` with its own signature domain and
4 MiB complete-output limit. Each output service member additionally retains
its actual `runtimeOriginal` for initial-history wrapper admission. V1 remains
closed and retains its old bound. The v9 supervisor may derive unsigned fresh
genesis from the independently approved fresh policy and actual guest/services;
this does not claim historical state or replace receiving-owner emptiness checks.

## Endpoint and bridge launch installation

```text
python3 -I -B scripts/install_native_pilot_launch.py --input-fd 3 --input-sha256 sha256:INDEPENDENTLY_APPROVED_BUNDLE_DIGEST
```

This exclusive filesystem installer accepts a protected public input FD, never
a signing key or credential FD. Its canonical no-LF
`serverware.nativePilotLaunchBundle/v1` bundle is bounded to **16 MiB**, with
exactly these nine fields:

```text
apiVersion                    role
ownerConfigurationSha256       windowSha256
observationOriginal           keyAdmission
runtimeOriginal               originals
serviceGrant
```

The eleven fixed roles are `retrieval`, `persistence`, `trustedTime`,
`generationInstall`, `commitRequest`, `ingressAdmission`, `terminalAppend`,
`dispatchBarrier`, `activeEffectBarrier`, `activeEffectCommit`, and `bridge`.
`keyAdmission` is the complete supplied `nativeShadowGuestLaunch/v1` object:
`apiVersion` plus exact pins for `deliveryConfiguration`, `delivery`, `trust`,
`timeBootstrap`, `assignment`, `closure`, `keys`, `encryptedKeys`, `admission`
and `verifierTransport`. `originals` has exactly the latter eight component
names, each mapped to its literal canonical public original. `serviceGrant` is
the pin of the previously published role-specific grant, not a new signature.

Endpoint owner pins select the existing fixed cohort configuration/precreation;
bridge pins select the existing driver configuration/window. The installer
retains those files and the existing cold, C9 and service-grant originals,
checks their supplied associations and signatures, and preserves the original
boot/window/epoch limits. Observations remain independently approved inputs,
not authenticated kernel evidence merely because this command parsed them.

For each endpoint it publishes the supplied runtime at
`native-runtime-<role>.json`, then the eight nested public originals, then
**`native-launch-<role>.json` last**. These names are beneath the fixed public
input directory in the publication table. The first three endpoint C9 intake
methods check runtime pins without opening the files; this later publication
therefore precedes the actual native runtime read. The bridge instead retains
and compares the already installed `bridge-runtime.json`; it never replaces it.
Bridge launch/v5 references the actual `native-service-trustedTime` endpoint
grant, not an invented bridge-guest time grant. The `commitRequest` launch uses
`native-service-ledger` and retains its separately pinned `native-service-commitRequest`
companion. GenerationInstall uses `native-generation-install-grant`.

Every new launch requires its own fixed `native-<role>-verifier.json` pin. The
runtime successor admits that role-specific selection; this is not a shared
global verifier file rewritten for each guest. Existing legacy profiles remain
separate. Key files here contain public authorization and encrypted-delivery
metadata only. The installer neither opens nor copies the separately
provisioned ciphertext/private C9 credential files, and cannot generate keys,
renew authorization, release endpoints or start a service.

All public joins and destination preflight precede writes. Publication remains
root:root `0400`, exclusive, fsynced and read back; each role has one attempt,
with at most 128 new originals and 32 MiB across calls in the process. Existing
files are not adopted or repaired. A partial installation or output failure
retains all created paths and fences further attempts; no rollback or retry is
provided. Require complete `nativePilotLaunchInstallation/v1` output and
successful exit. Its `launch` pin and component `pins` report file publication,
not native admission, readiness or request success. Filesystem/crypto stalls
still require the independent supervisor's watchdog.

## What remains

The source-connected per-job executor now joins approved inputs to these actual
producer and installation APIs, then forms replies from their real returned
originals/pins. The existing [process coordinator and eleven-phase transparent
relay](native-pilot-coordinator.md) is unchanged; neither mode supplies
independent approval or converts conductor observations into signing authority.

The independent supervisor is a **remaining source implementation**, not just a
service to provision. The coordinator waits for 60 dependent decisions, and the
approval installer only consumes an existing decision. No current executable
composes and evaluates all complete inputs against an independently authorized
commissioning policy. Human per-job interaction cannot be assumed to fit the
original startup window. See the [supervisor gap](native-pilot-coordinator.md#remaining-supervisor-implementation).

Remaining work also includes independently approved complete public inputs,
matching authority keys and required
artifacts; build/package and protectively install the current runtimes; provision
service/private inputs, native hardware and workload identity/namespace/sidecar;
then deploy and run one connected ordinary application allow/deny and genuine
cleanup sequence. Initial generation issuance remains initial-only; historical
issuance and full production acceptance are not credited. These source changes
do not prove any command was executed, any service is admitted, or a user-testable
pilot is running.
