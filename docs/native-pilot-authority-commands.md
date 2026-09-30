# Native pilot authority commands

These are purpose-specific commands for an independently operated authority,
not a completed coordinator or a pilot quickstart. They produce the existing
cohort precreation, endpoint release and driver continuation originals from
explicitly approved input. A separate restricted installer publishes literal
public originals at the paths consumed by the existing pilot owners.

The commands do not generate keys, approve their own inputs, start the pilot,
install service configurations or replace any independent signer. A protected
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

`scripts/install_native_pilot_public_original.py` accepts only three fixed
purposes. Its public input is a protected root:root `0400` read-only single-link
file on an inherited FD. No authority private-key FD is accepted.

| Purpose | Fixed destination |
| --- | --- |
| `cohort-precreation` | `/etc/serverware/native-shadow-proof-cohort-precreation.json` |
| `cohort-release` | `/etc/serverware/native-pilot-inputs/cohort-release.json` |
| `driver-scope` | `/etc/serverware/native-pilot-inputs/driver-scope.json` |

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

## What remains

These commands close specific producer/publication gaps, not the ten-phase
coordinator. Still required: independently operated approval/observation and
supervision, remaining driver admission and ordinary/native C9/grant producers,
approved bridge runtime/configuration installation, coordinator process/pipe
ownership and ordering, artifact assembly and protected installation, services
and workload provisioning, then the connected ordinary application allow/deny
and cleanup run. No command in this guide was executed when authored.
