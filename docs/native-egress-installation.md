# Native egress authority and protected journals

The `.251` authority/workload/journal foundation now has a `.252`
[private kernel transaction and readback pipeline](native-egress-kernel.md).
This is source integration, not an executed firewall transaction, public
installer, workload launch or production gate. The original hash-only
`native_bootstrap_client/egress/reservation.rs` and the new raw-custody
`kernel_reservation.rs` have distinct formats. Neither reuses the CA installation
journal, token, slot domain, records or receipt as egress authority.

## Authority and sequencing

The new independently pinned egress grant authorizes its own public runtime scope,
setup/delegation/target-request associations, exact destinations and port, host and
controlled-workload scope, and separate capability/token/journal association.
Expected runtime scope in the grant is not an already acquired session proof.
Exact packet/evidence hashes and the actual transaction are bound into the
operation-side association when genuine originals are admitted. Neither capture
JSON, a CA installation receipt nor a supplied digest substitutes for those owners.

The grant separately permits creation of one **never-started** `NEWNET` child
before journal admission. There is no target start API in this foundation. The
actual launcher retains the child through a pidfd and holds its newly created
namespace; failure or parent death tears down only that child. This creation is
not authorized retroactively by the later journal claim. Signed setup
`networkOwner` identifies the admitted launcher-host namespace, not the child
namespace inode that does not exist when the grant is signed. Actual child
identity must be retained and bound operation-side, never invented from a label.

Creation is limited to one child per retained owner. This internal primitive does
not itself supply cross-invocation launch admission or a durable once-only child
creation record. The later firewall claim is not retroactive permission or proof
of such admission. Public orchestration must define that lifecycle explicitly;
there is currently no configuration or CLI path that invokes this foundation.

The irreversible journal claim must be durable **before firewall mutation**.
The root-owned concrete `EgressGuard::check(&self)` supplies the same original
clock, admitted authority/proof/input/token and actual host/launcher ownership
checks through every journal phase. There is no caller-provided current time,
success callback or generic effect command. A `Spec` by itself grants no authority.
Acquire the journal lock before the protected backend lock; both
must be nonblocking and remain held through effect, exact readback and completion.
The private `.252` pipeline connects those owners and retains both locks after
completion. No public configuration/CLI or installation invocation is exposed;
a parsed digest remains no substitute for the retained originals and guard.

## Historical hash-only records: SWNEGRS1

The `.251` `reserve(Spec, &EgressGuard)` returns a non-Clone, non-Debug `Reservation` holding
the original guard and directory lock. Its `Spec` contains the signed journal
path/device/inode, stable reservation ID, exact operation-association hash,
protected token hash and intended-transaction hash. The parent verifies the actual
protected token bytes and retains their file ownership; the journal stores only
the hash. The stable slot derives from a dedicated egress domain plus the signed
journal namespace and capability ID, **not** a changing operation or transaction.
Changing token, intent, runtime or other admitted scope conflicts under that slot
instead of allocating a retry.

The journal is independently preprovisioned root:root `0700`. Its canonical
absolute nonroot path is bounded to 4096 UTF-8 bytes and 64 components. Every
ancestor is opened with `O_NOFOLLOW`, root-owned, non-group/world-writable and
retained; held and named directory identities are rechecked, including `/`.
The final directory must match the signed device/inode. A nonblocking exclusive
directory `flock` is retained until completion or owner drop. No directory is
created or repaired by this primitive.

Each slot has at most three append-only root:root `0600`, single-link regular
files: `<64-lowercase-hex-slot>.reserve`, `.claim`, `.complete`. The closed journal
is bounded to 64 slots and 192 records, including incomplete states. Unknown
entries, partial records, changed associations and missing predecessors refuse.
Records use the distinct `SWNEGRS1` magic and stage byte. Reserve/claim are exactly
137 bytes: magic, stage, slot ID, operation hash, token hash and intended-transaction
hash. Completion is exactly 169 bytes, adding a nonzero observed-state hash.
`O_EXCL`/`O_NOFOLLOW` publication, file/directory fsync and exact independent
readback precede success. No failure unlinks, overwrites or repairs a record.

1. `reserve` writes or exactly matches the reservation. A complete reservation
   without a claim may proceed only under genuinely re-admitted original bounds;
   it has not permitted a firewall effect.
2. `claim(&mut self)` returns `Fresh` only after durable exclusive claim readback.
   An existing claim without exact completion is consumed/unknown and refuses.
   An exact completion returns `AlreadyComplete(observed_digest)`, never `Fresh`.
3. After the actual effect owner has verified exact current kernel state,
   `complete(self, observed_digest)` publishes completion, independently reads it
   back and returns the retained digest after final guard checks. It accepts no
   callback, raw rule text or success receipt. The returned hash is journal data,
   not kernel-success authority.

Completed replay is **read-only**: the parent must compare genuine current
readback against the retained digest and all original associations, never reinstall.
This journal stores hashes only. It does **not** retain the raw intended kernel
transaction or observed-state originals. A hash alone cannot prove them; this
format is not the `.252` kernel pipeline's raw-custody journal.

## Kernel raw-custody records: SWNEGRS2

The separate `kernel_reservation.rs` owner uses `SWNEGRS2` and a mandatory
preprovisioned protected `backend.lock`. It refuses SWNEGRS1 records rather than
reinterpreting them. Its 137-byte purpose/association prefix is followed by exact
transaction bytes in reserve (bounded to 64 KiB), no added bytes in claim, raw
transcript hash/bytes in observed (bounded to 1 MiB), and semantic/evidence hashes
in the 201-byte completion. The closed journal permits at most 64 slots and 256
records, apart from the fixed lock file. Raw capability tokens are not recorded.

The actual sequence is journal open → backend lock → stable empty-namespace
snapshot → exact-intent reserve → durable Fresh claim → single submission/all
ACKs → post-effect snapshot → raw `SWNEGBE1` observation → exact semantic verify
→ consuming completion. The retained `Installed` owner keeps the actual guard,
backend and both locks for read-only recheck. Completed replay uses the retained
transaction and current exact snapshot; no resubmit, repair or start is allowed.

Failure observation is best effort, bounded and permitted only while the genuine
guard remains live. It cannot promise persisted bytes after expiry, process
death, partial publication or storage failure. Unknown/partial states stay
consumed; a missing observed record never grants a fresh attempt.

## Remaining effect and recovery work

The fixed create-only transaction, backend ownership, full ordered kernel
expression readback and original-byte custody are privately source-connected,
not executed or publicly invocable. Cross-invocation launch admission, public
cold configuration/CLI, network attachment and exec/start remain open.
Only the signed setup's explicit host addresses at the delegated TCP port may
populate the intended rules; CIDRs remain membership limits, not broad allowlists.
No implicit traffic exception, canary or provider authority follows from this
foundation. The launcher must not start the target on incomplete or uncertain work.

The fixed backend explicitly excludes all IPv4 MF/nonzero-offset
fragments (DF allowed) and all IPv6 Fragment-header packets, including atomic
fragments, before accepts. Exact semantic readback must include these exclusion
expressions. Ordinary non-fragment IPv6 extension resolution uses `meta L4PROTO`.
This narrower profile refuses legitimate pre-fragmented traffic and does not
guarantee that fragmentation cannot occur after the output hook. The
[design's Linux v6.12 source references](native-egress-installation-design.md#exact-rules-one-transaction-actual-readback)
justify the explicit constraint, not a runtime result. The `.252` codec and
readback enforce this profile without widening the grant fields.

Failure after claim leaves it consumed, even if submission or readback might not
have completed. There is no reset, retry, automatic rollback, deletion, repair or
start authority. New boot/namespace, changed current kernel state, teardown and
cross-session recovery require separately authorized lifecycle work. Cooperative
locks do not exclude a hostile root; local fsync is not an off-host rollback
witness. Kubernetes ownership, real deny/allow/connectivity behavior, provider
canaries and independent acceptance remain open. No build, test, interpreter,
runtime, NSM, AWS/spend or production completion is claimed.
