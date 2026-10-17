# Durable native terminal outcomes

The explicit cold `nativeBootstrapClient/v8` path connects actual native
execution, terminal cleanup and owned-resource retirement to a protected
write-once outcome before stdout. It extends [v7 retirement](native-execution-retirement.md),
not the diagnostic child or an older execution grant. This is source integration;
no build, runtime, interruption experiment or pilot acceptance follows from it.

## Separate authority and actual producer

V8 keeps the exact 22 configuration fields of v7. `egress`, `attachment` and
`execution` are required objects. `installation` is required and may be null
(execution-only, manifest v1) or the existing CA-install object (manifest v2 and
actual immutable in-image trust). It explicitly requires signed
`nativeWorkloadStartAuthorization/v3`, whose existing containment retirement
purpose is unchanged and whose journal has the additional exact field
`outcomeProfile: "durable-terminal-retirement-v1"`. The existing Python producer
selects this only through `requested_profile=OUTCOME_PROFILE`
(`native-workload-start-outcome-v3`); its old default remains v1. V1/v2 signing
domains and public clients are unchanged and reject the additional purpose.

The original start/creation claims still precede creation. The terminal writer
is reachable only from a private, source-created `LifecycleObservation` after
positive EXEC, the exact leader exit/reap, guardian terminal frame and reap,
leaf-empty observation, output EOF/accounting, actual host-veth absence and
owned-leaf removal. It pointer-compares the retained actual start permit with
that observation's owner. It cannot accept a deserialized result, capture,
caller assertion, hash or completion callback as permission. A nonzero ordinary
application exit can produce a terminal outcome; it is not application success.
Any missing/failed phase leaves the irreversible claim consumed and does not
manufacture a completed record.

The real start/root/token originals and both claims remain held and checked.
Terminal publication uses the separately signed **original absolute cleanup
BOOTTIME bound**, not a renewed admission/proof/CA allowance. It checks the bound
and nondecreasing BOOTTIME around each operation and after exact named readbacks.
Synchronous filesystem IO is not preemptible by these checks: a late or failed
write/fsync is reported as uncertain, never successful. Independent emergency
termination is already available on every preceding error and is not gated by
publication succeeding. CA installation and execution/outcome are separate
effects: a prior successful host CA installation is not rolled back or retried
when execution or terminal publication fails.

## Fixed protected records

The signed journal remains the retained root-owned protected ancestor chain and
root:root mode-0700 directory, with its original exclusive nonblocking flock.
The stable slot remains SHA-256 of `catchplate.nativeWorkloadStartSlot/v1`, NUL,
then big-endian-u32 length-framed signed journal namespace and capability ID.
Neither an attempt nonce, fresh proof nor a changed operation creates a new
attempt under the same slot. Exact names are `<64 lowercase hex>.claim`,
`.outcome` and `.complete`. V3 admits at most 64 slots / 192 named records; old
profiles retain their claim-only inventory. Unknown names, foreign/oversized
records and current-slot collisions fail closed. No existing slot authorizes
reuse, even after a successful terminal observation.

All files are root:root mode-0600, single-link, same-device, no-follow and
close-on-exec originals. Each new name uses one `O_EXCL` creation and one bounded
write, then file fsync, parent-directory fsync, and independently opened exact
named/held identity and byte readbacks. There is no rename-overwrite, unlink,
repair, write retry, cleanup deletion of partial records or reexecution. The
outcome is published first; only its successful durable readback permits the
separate completion-marker attempt. A later interrupted stdout cannot cause
either execution or retirement to be repeated.

The existing `SWNESTR1` claim remains exactly 73 bytes. New outcome framing is:

| Original | Fixed representation and bound |
| --- | --- |
| `.outcome` | `SWNEOUT1`; slot32, operation32, SHA-256(claim)32, cleanup deadline BE64, five BE32 section lengths; 132-byte header, total at most 1152 KiB |
| Section 1 | Exact canonical ASCII execution/retirement observation v2, at most 24 KiB |
| Section 2 | Actual `SWNATCL1` host retirement request/kernel-datagram transcript, at most 1 MiB, 16 requests and 256 datagrams |
| Section 3 | Actual retained 64-byte guardian terminal frame, not a reconstructed acknowledgement |
| Section 4 | Exact cgroup.events bytes from the successful populated-zero observation, at most 4096 bytes |
| Section 5 | Canonical selected initialized fields from the actual pidfd leader reap, at most 1024 bytes; not raw siginfo padding |
| `.complete` | Exactly 192 bytes: `SWNEOCM1`; slot32, operation32, claim hash32, outcome hash32, raw-evidence hash32, outcome length BE64, recorded BOOTTIME BE64, original cleanup deadline BE64 |

The raw-evidence hash uses `catchplate.nativeTerminalOriginals/v1`, NUL, then
BE32-length-framed sections 2–5. Section lengths are checked before allocation.
The record parser joins all operation/claim/hash associations, exact closed
observation fields, guardian flags/time, populated-zero original, actual reap
fields and retirement times. The host evidence digest is the exact retained
transcript hash. Cgroup removal remains an observed successful exact removal,
named parent-relative ENOENT and retained parent/leaf identities—not a raw
syscall buffer, a memory-reclamation assertion or generic deletion authority.

The record's operation binds the genuine admitted start grant/root, executable
parents and execution-manifest originals through the existing start-operation
domain. Lookup does not obtain or reverify new live proof from those hashes and
does not turn historical raw originals into current kernel state or permission.

## Operator lookup after lost stdout

The same binary has one separate read-only entry point:

```text
catchplate-native-bootstrap-client --inspect-native-outcome \
  --configuration /protected/native-outcome-lookup.json \
  --configuration-sha256 sha256:<independently pinned configuration hash>
```

This does not require a CA/private issuer key, expired bootstrap session or a
running workload. Its independently pinned, root-owned owner-only single-link
configuration is canonical ASCII JSON without LF, at most 8192 bytes:

```json
{"apiVersion":"catchplate.nativeExecutionOutcomeLookup/v1","capabilityId":"<signed start capability ID>","expectedOperationSha256":"sha256:<expected operation>","journal":{"device":1,"inode":1,"namespace":"<signed journal namespace>","path":"/protected/start-journal"}}
```

The identities and digest in that illustration are placeholders, not permission
or usable provisioning. Select the actual journal and public capability from
the signed original. If stdout was entirely lost, a privileged operator may
inspect **only the exact selected protected 73-byte claim**: bytes 0–7 are
`SWNESTR1`, byte 8 is 1, bytes 9–40 are its slot, and bytes 41–72 are the operation
hash to pin for this read-only association. This is not a new authority, secret
token recovery, automatic claim adoption or permission to execute. The lookup
still checks the actual descriptor chain, identities, private record metadata
and exact fixed name. It refuses an operation mismatch instead of falling back.

Lookup acquires a shared nonblocking flock, so an actual still-owned writer
causes refusal rather than waiting, guessing or stealing its lock. Its separate
at-most-five-second allowance applies only to read-only inspection and bounded
output; it cannot finish an expired writer or issue any effect.

| Status | Meaning |
| --- | --- |
| `no-claim` | All three exact names were absent under the retained journal lock. This is not start permission. |
| `consumed-outcome-unknown` | A valid matching claim exists, but a required outcome/marker is absent. Any retained partial original is bounded and protected. No retry follows. |
| `committed-outcome-observed` | A complete matching outcome and marker, including their raw-original associations, were read from exact protected names. The execution observation and outcome hash are returned as data. |

Malformed, foreign, oversized or inconsistent completed pairs are explicit
errors, never `no-claim` or fabricated completion. A pair with a partial marker
is refused; a missing counterpart remains unknown. A process may die after a marker write but before the
writer observes fsync completion: later lookup can report matching records
**observed**, not prove that a historical fsync returned. No observation authorizes
repair, archival, restart, slot reset, claim reuse or another attempt.

The lookup emits exactly ten fields in one at-most-32-KiB JSON line including LF,
always `actionAuthorization: null` and `okForAction: false`. Its originals and
shared lock remain held through output. A read-only lookup can be repeated;
execution and publication cannot be repeated by it.

## Capture and SDK boundary

The v8 capture has the v7 eleven fields plus `outcome`, with result scope
`local-fixed-endpoint-bootstrap-execution-outcome-observation`. Its nine-field
outcome receipt is at most 4096 bytes, binds slot/operation/outcome/raw-evidence
hashes and the marker's pre-publication recorded BOOTTIME, and is nonactionable.
The producer reserves 36 KiB before effects and preserves the overall 1.5-MiB
JSON-plus-LF limit. Publication precedes stdout; the actual claims, record FDs,
removed-leaf FD and host originals remain held through the attempted output.

The SDK only adds an explicit v8 closed-shape/data extraction branch. It pairs
the receipt operation with execution and requires its recorded time to be at
least both retirement observations and strictly before the original cleanup
deadline. It does not inspect the journal, authenticate the receipt, prove
fsync or issue execution/retirement/publication permission. It still extracts
only the original native packet through the existing verification boundary.

Schemas: [config](../schemas/native-bootstrap-client.v8.schema.json),
[capture](../schemas/native-bootstrap-client-capture.v8.schema.json),
[signed authority](../schemas/native-workload-start-authorization.v3.schema.json),
[receipt](../schemas/native-execution-outcome-receipt.v1.schema.json),
[lookup](../schemas/native-execution-outcome-lookup.v1.schema.json) and
[lookup result](../schemas/native-execution-outcome-lookup-result.v1.schema.json).

Host CA removal, journal archival/migration, ambiguity repair, automated restart,
continuous supervision after this single attempt, and runtime/pilot evidence
remain separate. This path does not turn provider effects or application
business outcomes into a durable transaction.
