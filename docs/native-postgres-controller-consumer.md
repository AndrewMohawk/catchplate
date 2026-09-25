# Native PostgreSQL controller consumption

Status: source-implemented, unbuilt and unexecuted. This is an optional v12 Unit
body contract, not an enabled lane or passing native result. The fifteen suites
remain excluded pending full preparation, coverage admission and verification.

## Decision and signed contract

Native PostgreSQL is supplemental Unit work. It does not introduce a sixth lane
or silently replace ordinary Unit coverage. An independently admitted command
must retain that work and invoke the fixed native entrypoint. A missing
`nativePostgres` field preserves the existing non-native body representation.
The option is permitted only for Unit and binds:

- `preparedSourcesSha256`: the nonzero digest of the exact prepared manifest.
- `sourceSha256`: fifteen nonzero digests in the source-owned suite order.
- All 33 native output paths in the body's existing `expectedOutputPaths`.

These fields are covered by the canonical body digest and existing signed plan.
They are not generated or approved from the runner's reports. The
[Rust inventory](../data-plane/decision-gate-rs/src/native_postgres_contract_v12.rs)
contains the same fifteen ordered suites and 311 explicit method identities as
the Python inventory. This includes representation/source component methods;
it is not a claim of 311 executed SQL tests.

The runner must have an artifact mount, Linux/amd64, UID/GID `10001:10001`, and
the exact source/artifact/output destinations under `/opt/serverware`. Admission
requires at least 4 GiB memory, 128 PIDs, 1024 open files, 64 MiB each shared
memory and `/run`, 256 MiB `/tmp`, 2 GiB private data, and 256 MiB/4096 inodes
for output. General no-swap, closed network/mount/inspection and checked total
memory constraints still apply. These are conservative minima, not measured
capacity or enforcement results. The larger output allocation accommodates
136 MiB of bounded logs plus reports; it does not relax individual file limits.

The signed command timeout must be at least 5700 seconds. Immediately before
start, the controller requires that much remaining time and uses the earlier
of its original operation deadline and the signed command timeout. Start, wait,
source readback and collection do not renew it. Private DinD socket connection
is nonblocking and must succeed immediately; backlog, interruption or pending
connection fails before HTTP transmission. An approved combined body needs
additional time for ordinary Unit work and collection. The default 900-second
Unit profile and 10-second Docker stop timeout are unchanged; the latter still
needs admission reconciliation with the native 60-second cooperative shutdown.

## Original-file and result joins

```text
independently signed body + prepared artifact/source mounts
  -> exact manifest bytes and fifteen measured script hashes
  -> existing inspected runner starts and controller observes its exit
  -> same source pins remeasured; original 33 output files collected
  -> closed report reconciliation and actual file-inventory digest
  -> equality with original outer nativePostgresOutputSha256
  -> unchanged courier/runtime evidence validation and terminal cleanup
```

The [FD reader](../data-plane/decision-gate-rs/src/native_postgres_output_v12.rs)
uses retained directory descriptors, fixed leaf names, no-follow/nonblocking
opens, same-device/mount checks and bounded reads. Prepared inputs must be
root-owned, not group/world-writable, and actually read-only. The manifest is
limited to 16 KiB and must equal the one canonical document reconstructed from
the signed pins and fixed inventory; each script is limited to 2 MiB and is
hashed before and after execution. The whole approved source archive still
binds transitive dependencies, not just these fifteen entrypoints.

Output must belong to the admitted nonroot owner on the retained capped tmpfs.
The `native-postgres` subtree admits only:

- `runtime-result.json`, at most 64 KiB.
- `reports/00.json` through `reports/14.json`, each at most 256 KiB.
- `logs/00.log` through `logs/14.log`, `initdb.log` and `postgres.log`, each at
  most 8 MiB; a genuinely empty log is allowed and hashed normally.

Directories are private mode 0700; leaves are regular, single-link mode 0400 or
0600 files. Unknown/missing entries, mount crossings or metadata/name/identity
drift fail admission. Logs stream through one 64 KiB buffer. The reader retains
file descriptors and rechecks their identities and the exact directory inventory
after reconciliation. Every read remains under the unchanged deadline.

The [pure reconciler](../data-plane/decision-gate-rs/src/native_postgres_reports_v12.rs)
accepts only original bounded canonical ASCII JSON. A depth/node scan precedes
parsing; exact canonical reconstruction rejects duplicate keys and alternative
encodings. Closed field sets, exact ordered test identities and recomputed
counts must show all 311 methods started, stopped and passed with no skips,
errors, expected failures or negative subtests. All fifteen fixture processes
must have exited zero. Summary, fixture and process-log records must agree with
the actual report/log bytes, hashes, sizes and signed script digests.

The runtime must be `COMPLETE`, source-unchanged and locally clean, with direct
children reaped and external destruction still required. Its original cluster
observation has only a PG16 version number and canonical nonzero system ID.
The consumer does not invent a richer independent observation of server
settings; those checks remain in the source-pinned cooperative producer/probe.

On success, the native commitment is SHA-256 of a canonical ASCII JSON array
containing the lexicographically sorted 33 records. Each record has exactly
`path`, `sha256` (a lowercase `sha256:` string) and integer `bytes`, with sorted
object keys and no whitespace or final newline. The original generic
`BodyExecutionResultV12.nativePostgresOutputSha256` must equal this digest. As
with other v12 `Digest` fields, its wire value is a 32-byte JSON array. The field
is required only for the signed native option and participates in the existing
canonical terminal digest. The controller returns the unchanged original outer
result; it does not synthesize that result from fixture JSON.
The [shared body contract](controller-body-evidence.md) additionally binds this
native digest and all ordinary result claims into the required v13 observer
signature. Its original terminal wire is bounded to the existing 4 MiB plan
frame. The independent observer acquisition/publisher is still unfinished.
The [general output collector](controller-body-output.md) now binds actual
stdout/stderr and the signed payload manifest. Its native 33-file subset must
equal the separately reconciled native digest, rejecting cross-pass drift.

## Remaining prerequisites

This consumer does not provide an admitted PG16/Python/libpq image, a signed
invocation/deadline profile, or a producer of genuine generic body/courier/runtime
evidence. The standalone native entrypoint still does not emit that outer result.
Native report consistency is not independent authorship, a runtime measurement,
durability on tmpfs, or proof that all descendants are gone. Existing static
closure, runtime observer, plan/body/command binding and authenticated `DESTROYED`
receipt requirements remain mandatory. No production or external service was
provisioned, no exclusions removed, and no source freeze or verification occurred.
