# Independent late-runtime closure authority

`scripts/authority/sign_native_pilot_closure.py` issues only the existing
`catchplate.nativeCustodyClosureAssignment/v2`, for
`measured-bootstrap-late-runtime-static-amd64-v1`. It returns the complete
`catchplate.nativeCustodyClosure/v2` original for the existing bridge launch
installer. Endpoint closure assignment v1 is not implemented by this command.

This issuer runs **after the retained driver observation and signed operational
C9 delivery, before bridge launch installation**. It is not a pre-build or
earliest-bootstrap input. Existing C9 signing uses cold configuration, window,
observation, runtime and activation metadata; it does not require this closure.
No job has been added to the existing fixed 60-job execution table. The
independent automated authority supervisor and its approved decision policy must
explicitly compose this step; the conductor cannot approve its own observations.

## Protected command and complete input

The independently operated authority invokes:

```sh
python3 -I -B scripts/authority/sign_native_pilot_closure.py \
  --input-fd 3 --authority-key-fd 4
```

FD 3 contains an independently approved canonical ASCII/no-LF object, at most
8 MiB, with exactly these 13 fields:

| Field | Required existing original |
| --- | --- |
| `apiVersion` | `catchplate.nativePilotClosureAuthorityInput/v1` |
| `controlOriginal` | Driver bootstrap control v1, pinning configuration/window and supervisor executable |
| `configurationOriginal` | Driver bootstrap configuration v4, including approved immutable image pins |
| `windowOriginal` | Signed bootstrap window v1, with original boot, time namespace and deadlines |
| `observationOriginal` | Actual retained driver observation v1, independently approved as such |
| `deliveryConfigurationOriginal` | The exact pinned C9 cold configuration |
| `deliveryOriginal` | Authenticated complete bridge C9 delivery v1 |
| `runtimeOriginal` | The C9-bound operational runtime v9 |
| `trustOriginal` | Independently provisioned native guest trust v1 |
| `trustSha256` | Independent pin for those exact trust bytes |
| `assignmentOriginal` | Complete existing signed policy-shadow assignment v1 |
| `manifestOriginal` | Complete execution-closure manifest v2, including original policy/provenance |
| `payloadOriginal` | Complete proposed closure-assignment v2 payload; no field is defaulted |

All `*Original` values are literal canonical ASCII/no-LF JSON strings, not paths.
The public FD is root:root0400, single-link read-only regular or a fully sealed
0400 memfd. FD 4 is a distinct, already provisioned root:root0400, fully sealed
32-byte Ed25519 seed memfd for the independently assigned
`custody-supervisor-capability` role. The existing shared authority I/O checks
these contracts. Neither the command nor possession of its FDs supplies approval.
The input must be approved in full; a caller-computed hash is not that approval.

## Existing authority and consumer bindings

The assignment signature is verified with the assignment key from the approved,
separately pinned trust original. Candidate payload fields cannot select a key.
The existing assignment independence validator authenticates all role bindings,
including key-ID/SPKI/material roots, and joins their public keys to that trust.
The supplied private key must match its exact supervisor-capability binding.
No alternate key, new checkpoint, role history or authority is constructed.

The issuer checks the signed bootstrap window, original local boot/time namespace,
observed driver identity, C9 signature/guest/41-descriptor shape and operational
runtime pin. Closure payload assignment, guest, checkpoint/revocation, signer and
manifest fields must exactly match these originals. The v2 manifest binds the
**bootstrap runtime** in the immutable image; its payload guest separately binds
the operational C9 runtime. Image/executable/policy/lock/recipe/provenance hashes
must match the original driver image; provenance and manifest framed digests are
recomputed. Recipe, transparency-log entry and reproducible-build assertions are
independently supplied evidence, not evidence generated or established here.

The existing signature transcript is
`catchplate.nativeCustodyClosureAssignment.signature/v2` within the existing
signed-envelope canonical-JSON framing. Output is at most 1 MiB, canonical
ASCII/no-LF, and can be supplied as the bridge installer's `closure` original;
that installer publishes the fixed `native-bridge-closure` slot. The Python API
is `sign(*, input_original: bytes, signing_key) -> (original_bytes, startup_deadline)`.

The unchanged native consumers are `policy_custody/native_closure.rs` and
`native_closure_late.rs`: actual trusted-time/current-checkpoint verification,
structural seccomp validation, image bytes, retained executable and guest owner
checks remain mandatory. This issuer does not recreate a process owner, execute
the BPF validator, contact hardware, prove reproducibility or claim admission.

## Time, failure and remaining prerequisites

Run on the original admitted boot/time namespace. Supplied issue/expiry values
are not replaced; signing/output must complete within the original startup
deadline. Expiry cannot outlive the approved assignment, trust, relevant key
validity or checkpoint freshness. The command rechecks retained FD identities,
public bytes and time before and after output. Stdout must be the root
supervisor's bounded pipe, never an interactive secret/original dump.

There is no install, key generation, service-credential read, network call, automatic
retry or cleanup. A failure may leave partial output, which the supervisor must
reject without treating absence as authorization to retry. An external watchdog
must bound filesystem/cryptographic stalls; software sealed-key handling does
not claim hardware custody or guaranteed erasure of Python/OpenSSL copies.

Independent image/policy/provenance approval, supplied assignment/trust and keys,
v1 endpoint closure issuance, automatic supervisor composition, publication,
deployment and connected acceptance remain separate prerequisites. Source
availability is not guest assembly, native admission or production readiness.
