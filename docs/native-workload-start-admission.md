# Native workload start constraints and protected preparation

Status: source implementation only, unbuilt and unexecuted. The separate
`nativeWorkloadStartAuthorization/v1` contract authenticates constraints for a
new executable-child path. It is not a start permit, a running/healthy-workload
observation or permission to convert the existing never-executed egress child
into an application. The separate [v5 lifecycle](native-execution-lifecycle.md)
retains this admission through actual child/guardian/network ownership and
consuming release. None of those source paths has been executed.

## Separate original and exact signature

The [closed schema](../schemas/native-workload-start-authorization.v1.schema.json)
pairs with
[`execution/start_authority.rs`](../data-plane/decision-gate-rs/src/native_bootstrap_client/execution/start_authority.rs).
The envelope is exactly `schema`, `payload`, `signature`, with envelope schema
`catchplate.signedNativeWorkloadStartAuthorization/v1` and payload schema
`catchplate.nativeWorkloadStartAuthorization/v1`.

The original is sorted compact canonical ASCII JSON without LF, at most 32 KiB
and nesting depth six. The signature is `ed25519:` followed by canonical unpadded
base64url for exactly 64 bytes. Ed25519 signs the payload schema's ASCII bytes,
one NUL byte, then the exact canonical ASCII payload. This is not the framed
Python historical-delivery signing recipe, nor a signature over a JSON verdict.
The whole original must also equal its canonical encoding.

The paired original-only
[`native_workload_start_authorization.py`](../catchplate/native_workload_start_authorization.py)
producer and verifier take an existing work ledger, live window and absolute
transport deadline, independently pinned public-key original, and (for signing)
an explicitly supplied canonical Ed25519 PKCS8 private-key original. They do not
read files, generate keys, provision services or authorize an effect.
The default `requested_profile=START_PROFILE` accepts only v1.
The caller must independently choose `RETIREMENT_PROFILE` for
[v2](../schemas/native-workload-start-authorization.v2.schema.json);
no incoming schema or diagnostic makes that decision.

V2 keeps the exact 22-field payload and three-field envelope, changing both
schema constants and therefore the signature domain. Its containment object
adds exactly `retirementProfile: "remove-empty-owned-leaf-v1"`.
V1 rejects that field even if null, and v2 requires its exact nonnull value.
The original-only APIs check exact fields and scalar types, nonzero digest
pins, distinct grant/manifest commitments, host and isolation constraints,
resource bounds, separate journal/parent identity, and all four signed epoch
relationships. Only the start boundary narrows their inherited work window;
they never turn the later stop/cleanup epochs into new signing time or a
Python-produced runtime clock projection.

The separate native owner must still admit these exact signed bytes and join
its actual held start/creation claims and created leaf. V2 permits one exact
empty-owned-leaf removal only within the original signed cleanup deadline,
after leader and guardian cleanup and fresh retained parent/leaf/control
checks. It does not authorize removing a parent, recursive deletion, deleting
an unrelated host link, host CA removal, retries or recovery. The corresponding
explicit v7 client selects this profile; v5/v6 start semantics remain unchanged.

`admit_constraints` takes raw authorization bytes, an independently pinned root
PEM original/digest and the existing `OriginalClock`. Root bytes are bounded to
16 KiB. It verifies the actual root and strict signature, rejects unknown fields,
requires the exact current common source revision and returns a source-private,
non-Clone `Authorization`. Retained root-key identity, original SHA-256 and
absolute deadline projections are observations from that admission, not bearer
authority. Schema matching alone establishes none of them.

## Exact signed scope

The payload binds separate egress and attachment authorization originals, the
explicit executable-profile construction manifest and the execution manifest, actual launcher
binary and machine identity. Egress/attachment digests must differ, as must the
two manifest digests. `creationMode` is exactly `new-execution-child-v1`.
The host association pins host ID, boot ID and the launcher-host network
namespace device/inode with root ownership; it is not a future child identity.

The fixed isolation profile requires nonroot UID/GID, empty supplementary groups,
no-new-privileges, empty capabilities as a profile obligation, ordered mount/IPC/UTS/
network/PID namespaces, umask `0077`, null input and bounded output. It does not
declare a user namespace or prove these controls have been installed.

Signed resource bounds are 16 MiB–1 TiB memory, zero swap, 1–4096 processes,
1000–6400000 microseconds CPU quota per fixed 100000-microsecond period, and
4 KiB–64 MiB output. The fixed containment profile requires a new cgroup-v2 leaf
under a pinned parent and an independent whole-cgroup guardian. Its parent path
and device/inode pair must differ from the separate start journal. The dedicated
capability binds an independently held token original; its digest is not token
possession. Paths and names are bounded ASCII scalars, not filesystem ownership
or existence proof.

## Three absolute deadlines

| Signed deadline | Meaning |
| --- | --- |
| `startBeforeEpochNs` | Latest preparation/start admission boundary; it tightens the existing original clock. |
| `stopAtEpochNs` | Separately signed absolute stop boundary retained by the actual guardian; not a new request lifetime. |
| `cleanupBeforeEpochNs` | Absolute deadline for the guardian's bounded cleanup after stop; not recovery or restart permission. |

At a checked admission wall/boottime sample, issue time must be no later than
wall time and wall time strictly before `startBeforeEpochNs`. The issue-to-start
interval is at most 300 seconds, and start must not exceed capability expiry.
Stop is strictly after start, by at most 86400 seconds. Cleanup is 100 milliseconds
to 30 seconds after stop. All signed epochs are positive signed-64-bit nanoseconds;
capability expiry is bounded milliseconds.

Stop and cleanup boottime values are checked projections from that one sample,
not `now + TTL` calculations on later use. Admission narrows the same original
clock to the start deadline and rechecks actual wall/boottime continuity before
returning. The continuation deadlines do not renew bootstrap, CA, egress,
attachment, approval or filesystem-proof lifetimes. The actual blocked-child
owner transfers those absolute bounds into its independently armed guardian.

## What still has to authorize execution

The source-private [`PreparedStart`](../data-plane/decision-gate-rs/src/native_bootstrap_client/execution/start.rs)
now opens exactly four artifact roles: `authority`, `authorityRoot`,
`capabilityToken` and `executionManifest`, under the same `Arc<OriginalClock>`.
It invokes signature admission, joins the signed token/manifest pins, retains
actual protected root/grant/private-token originals and host ownership, and opens
and retains the non-Clone `PreparedFilesystem` under that same clock.
`check(&self)` repeats original, host, token and filesystem checks and poisons the
owner on failure. This is protected preparation, not transferable permission.
The separate [retained start owner and claims](native-start-claim.md) now join
actual v4 executable-profile parents and protected cgroup-parent admission;
the real start/creation claims precede [new-leaf containment](native-execution-containment.md).
The [new child owner](native-executable-child.md) now consumes those actual
parents/claims and stays blocked before execution. The private
[guarded composition](native-execution-guardian.md) arms its guardian and retains
both owners through explicit cleanup. Legacy v1-v3 diagnostic grants cannot
enter this new branch.

Content closure for an ordinary dynamically linked application cannot follow from executable SHA-256
or a read-only mount alone: its interpreter, libraries and other code lookup
must remain inside the independently admitted runtime-filesystem contract.

Before any executable child can run, the retained actual owners and claims must
also join exact child cgroup membership, isolation and filesystem installation,
network effects and an independent guardian that can stop and clean up the whole
workload. Constraints or a prepared filesystem cannot substitute for those joins. No old never-exec
PID migration, callback-based success assertion, reset/retry, automatic rollback
or running/health claim is introduced here.

Explicit v5 configuration/orchestration now joins same-child networking and
consuming release. Persistent deployment and runtime acceptance remain open. This profile
does not claim a tested start/stop/cleanup cycle, persistent deployment,
cloud provisioning or production acceptance.
