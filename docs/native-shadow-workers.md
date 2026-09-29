# Native prestarted shadow commands

This additive source profile moves the three existing pinned shadow command
launches out of the serving gate. It does **not** install or attest a native
policy-shadow custody service, supply verifier signing keys, or demonstrate a
running Nitro image. No build, test, runtime or provider validation accompanied
this source change.

## Explicit selection and actual owners

`native_startup_config::shadow::ShadowConfigV2` is a closed nested alternative:
`apiVersion=serverware.nativeShadowConfiguration/v2`, the six original shadow
fields, and required `workers`. The worker configuration has only
`apiVersion=serverware.nativeShadowWorkers/v1` and the independently pinned fixed
executable `/usr/local/bin/serverware-native-shadow-worker`. Outer v1–v14 keep
their old exact shadow decoder. Outer v15 explicitly admits either the unchanged
closed v1 fields or this closed v2 alternative; unknown markers/fields cannot
fall back to v1. The paired v15 schema makes the same disjoint choice. No new
outer version or default selection is added, and configuration is not runtime
authority.

`PreparedNativeShadowControl::open` runs after genuine guest cohort startup and
before gate cgroup attachment or permanent privilege drop. It admits the existing
trust/configuration/authorization originals, preserves the actual three pinned
static executable checks, and launches the worker under the **same** root
`native_serving_privileges::Prepared`. The cohort supplies actual signed role
identities for a collision check: no UID or GID may equal fixed worker 64988.
Inspector 64990, boot role-key provisioner 64989, and gate 65534 remain separate.

After the irreversible gate drop, `bind` requires that same preparation origin
through the real serving owner. The control is not published before this bind.
`NativeRuntimeLifetimeV1` retains the exact worker alongside the cohort and
inspector and checks its originals/liveness. Every worker and command child
remains outside the fresh gate-only cgroup. A selected owner failure never falls
back to the old gate `Command::spawn` path.

## Private transport and command contract

The source-fixed worker has no argv tail or environment. Its inherited set is:

| FD | Original |
| --- | --- |
| 0–2 | Verified fixed null stdio, closed before any private request |
| 3 | Private AF_UNIX SEQPACKET parent link |
| 5 | Sealed root-owned bootstrap, mode 0600, zero links, at most 16 KiB |
| 6–8 | Sealed static runtime-verifier, WebAuthn-verifier, publication-handoff images |

The parent retains original protected executable files/ancestor descriptors and
their metadata plus immutable four-seal copies. Each executable is at most
64 MiB and passes the existing little-endian static amd64 ELF algorithm (no
PT_INTERP or DT_NEEDED). Snapshots are public executable bytes, mode 0555; they
contain no provisioned secret. The Docker source builds and installs only the
fixed worker; independently supplied verifier/handoff images and keys remain
separate release/provisioning inputs.

The worker derives its actual parent from SO_PEERPIDFD and getppid, then drops
permanently to UID/GID 64988, empty groups, zero capability sets/bounding/ambient,
NNP and nondumpable. Its initialized packet and every response carry genuine
kernel SCM_CREDENTIALS plus SCM_PIDFD matching the parent's clone3-owned child.
Every request similarly must come from the original parent now at UID/GID
65534. Socketpair creation-time root SO_PEERCRED is not final worker identity.
Neither side accepts a public socket/PID/descriptor constructor or reconnect.

Bootstrap5, request8, response3 and initialized3 are specified in
`schemas/native-shadow-workers.v1.schema.json`. Frames are compact sorted JSON
at most 4096 bytes. One monotonic channel sequence, original bootstrap hash and
nonce bind every exact request echo. Each request carries one fully sealed
gate-owned 0600 input memfd, at most 32 MiB; each response carries one fully
sealed worker-owned output memfd. Runtime and WebAuthn output is at most 64 KiB,
publication output at most 2 MiB. No descriptors are returned as executable or
key capabilities.

Only these existing purposes are executable:

- runtime: `verify-generation-runtime`;
- WebAuthn: `resolve-and-verify-assertion-by-digest`;
- publication: `prepare-or-recover` or `commit`.

The pinned original path is argv0 only; no arguments, paths, command lines or
environment are selected by a request. Stdin contains the sealed original JSON,
stdout is bounded, stderr goes to the verified fixed `/dev/null` device, and
LANG/LC_ALL/TZ remain C/C/UTC as in the old restricted invocation. Returned stdout
uses the existing strict JSON parser, not a newly imposed canonical-output
format. Existing signed-envelope, role, generation, request and publication
checks remain the authority; `process-exited-zero` is only process evidence.

## Lifetime, confinement and provisioning boundary

The parent chooses the original per-call ten-second allowance once, before
preparation/send, capped by the retained native lifetime. The worker may only
narrow it. Busy calls are refused rather than queued. IPC uncertainty poisons the
owner and stops it; there is no replay, retry or renewed allowance.

Each command is an owned real child with a PIDFD and separate process group.
PDEATHSIG, parent PIDFD/channel checks and bounded BOOTTIME polling cover parent
loss and expiry. Its filter blocks process fork, group/session escape, ptrace,
process_vm, namespace/mount changes and ordinary exec; only thread clones are
allowed. The exact initial execveat uses the retained static image. This is **not
a proof of a complete syscall sandbox or of immutable post-exec behavior**:
trusted pinned command implementations retain their existing file/network
semantics, and exec normally resets command dumpability. The dispatcher remains
nondumpable and cap-free; no serving process gains inspection/DAC capabilities.
Such command implementations and their real service access are part of the
independently admitted TCB, not replaced by this transport.

On failure/timeout the worker kills its actual job group/PIDFD and attempts a
real waitid reap within the original lifetime. Gate stop shuts down the private
channel (cross-UID signal permission is not assumed). Explicit lifetime cleanup
stops/reaps the worker before the cohort, then inspector, and reports failure
when a timely reap is not observed. Drop attempts cleanup but makes no success
claim. Already completed external publication effects are not undone.

The independently pinned commands need genuine final-UID-accessible keys and
service endpoints; this change neither chmods existing histories nor creates
credentials. Existing shadow custody still requires its own signed generation,
real endpoints, backend, driver, journal and peer measurements. In particular the
trusted-host-no-TEE shadow implementation is not relabeled native. Its genuine
guest owner/provisioner and complete runtime validation remain unfinished.
