# Native pilot dispatch durability

The `.393` work addresses the actual selected RPC bridge, not the unconstructed
legacy watchdog driver. It fixes v11 active-effect selection and adds durable
pre-contact request ownership. The native compile and eight reducer controls pass.
Source checkpoints remain **36/46** and independent production acceptance **0/6**.

## Selected runtime and interrupted requests

The supervisor selects RPC runtime v11. Its CommitRequest client must enforce
the same active-effect contract as the selected spool owner; v11 must not fall
back to the legacy permit shape because a second version list omits it.

Previously, the bridge wrote the request/response exchange only after remote
authority calls. Failure after a side effect but before that append could leave
no bridge-owned record of the attempt. A live error also did not consistently
retire the bridge's readiness. Per-service fences help, but do not supply that
missing outer ownership record.

The new ordering is a durable start, authority contact, fully validated result,
and durable completion. The bridge retains its failure latch throughout the
attempt. Original operation deadlines, peer authentication, service signatures
and exact request/result associations still apply. A transport, validation,
clock or journal failure cannot be turned into a successful completion marker.

Recovery must distinguish a definitely completed exchange from an unmatched
start. An unmatched or detached record refuses admission; it is not an
instruction to retry the remote effect. Historical completed records retain
their validation requirements. Exact cached mutation results remain separate
from operations whose evidence must be recertified by the live authority.

The closed start marker binds the physical journal sequence, replay identity,
request digest, literal request bytes and any previous exact response. Start
and completion use separate domain-derived keys. A recertification writes its
own pair, must retain the prior response body, and returns the original reply
bytes. New completed records cannot appear without their matching start.

An unresolved attempt returns a request-bound `RecoveryNotReady` refusal while
the caller's deadline remains live. That refusal is not a journaled completion
and does not establish that no effect occurred. Expired requests retain their
existing deadline failure; channel survival after timeout is not claimed.
Even an authority rejection conservatively retains the fence when the compound
operation cannot establish whether earlier contacts had effects. A fenced bridge
does not accept further authority operations as an improvised recovery route.

Both physical journal records and all bytes counted by journal recovery must
fit the original bounded budget before an attempt begins. Request-start data
is local recovery evidence, not a cleanup authorization, upstream success,
currentness decision or independently signed terminal settlement.

## Cleanup remains a separate implementation gap

The [operation-ownership review](native-pilot-operation-ownership.md) traces the
actual first terminal refusal and the mismatch between long-lived native
services and the older process-reaping contract. Neither this journal fence
nor the existing service-shutdown owners prove that an operation's late effects
are impossible. No worker, PIDFD parenthood, authorization consumption or
terminal receipt is fabricated here.

The next cleanup change must implement and authenticate a complete operation
lifecycle against the selected runtime. That can satisfy the existing real
process contract or explicitly introduce native per-operation settlement with
equivalent late-effect guarantees; it cannot silently relabel one as the other.

## Verification boundary

Exact source `46821ad7bf00f94207d3d6aaa71cfae2a57f4785` passed one cached,
offline/locked/frozen Rust 1.88 check of `serverware-decision-gate` (exit **0**,
compiler-reported **57.08 seconds**). The pinned container used one CPU, 8 GiB,
no additional swap, no network and read-only source/vendor mounts. Existing
warnings remain: 312 library and 2,430 binary warnings, including duplicates.

The exact std-only production reducer and its adjacent companion were compiled
separately; all **8 controls passed**. Synthetic byte inputs exercise ordering,
failure fencing, recovery pairing, legacy-prefix handling and physical capacity.
These are executable reducer controls, not real journal I/O, marker-codec,
signature, socket or native-constructor tests. The marker/bridge integration and
v11 selection were source-reviewed and typechecked, not run against real owners.
Six documentation files passed **623 distinct local file targets**; anchors and
external URLs were not checked.

The initial preflight stopped before compilation because the cached image
reference was missing. Restoring the same pinned Rust digest found both layers
already present; the successful runner also verified the unchanged image ID.
No source/dependency change or duplicate compile was needed. That restoration
used registry access; only the verification container was network-isolated.

Exact source, scripts, complete logs, the test binary, results and checksums are
retained at `codex-offload/serverware/engineering-builds/46821ad7-dispatch-fence-MjQRSL/`.
The source archive SHA-256 is
`7f4809b2df94aec010431a8baaecfe5ad7911a707e8352be7dad3e74b60896e8`.
No live authority, protected signing service, privileged worker launch, cloud
resource or paid test ran. Journal crash durability, complete native
authentication, connected application allow/deny/cleanup and the independent
production gates remain unverified.
