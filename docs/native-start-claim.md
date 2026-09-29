# Native retained start owner and durable claims

Status: source-only; unbuilt and unexecuted. This connects authentic start and
executable-profile network originals to one claimed cgroup-preparation attempt.
It does not supply public start configuration, an executable child, installed
network effects, a guardian, a running workload or a cleanup receipt.

## Actual retained owners

[`StartOwner::bind`](../data-plane/decision-gate-rs/src/native_bootstrap_client/execution/start.rs)
consumes the actual `PreparedStart` and retains the actual `Arc<ExecutionParents>`.
The [explicit v4 parent profile](native-egress-execution-parents.md) joins the
genuine same-TLS proof, actual host/launcher and originals, separate attachment
permission, and launch-manifest v2. The same `Arc<OriginalClock>` must be retained;
the signed start deadline only narrows it. Old diagnostic grants and an existing
never-executed child do not become executable parents.

Start checks bind actual parent authorization digests, both manifests, launcher,
machine/host/boot/network namespace, root-key separation, capability/token
separation, dedicated journal identities and parent admission intervals. The
start owner retains the protected filesystem and its original entry/loader/cwd.
It owns no child or permit, so later journal checks do not form an ownership cycle.

The [parent owner](../data-plane/decision-gate-rs/src/native_bootstrap_client/execution/parent.rs)
retains every protected ancestor, actual final directory and mount identity. The
signed cgroup parent must be a protected cgroup-v2 domain with CPU, memory and
PID controllers already enabled for children. This path never creates ancestors,
enables a controller, moves tasks or substitutes caller-provided observations.

## Two irreversible claims before containment

[`start_reservation::claim`](../data-plane/decision-gate-rs/src/native_bootstrap_client/execution/start_reservation.rs)
first consumes the start owner's in-memory attempt. It opens the actual signed
root-owned `0700` start journal and retains its exclusive nonblocking lock.
The closed inventory permits at most 64 exact `64-lowercase-hex.claim` files;
foreign, incomplete, full or already-consumed inventories refuse without repair.

The stable start slot is SHA-256 of `serverware.nativeWorkloadStartSlot/v1`, one
NUL byte, then the journal namespace and capability ID, each prefixed by its
big-endian u32 byte length. New proof bytes or a changed token cannot make that
same slot fresh. A record is exactly 73 bytes: `SWNESTR1`, byte `1`, the 32-byte
slot and the 32-byte actual operation commitment. The operation commitment binds
the original signed start, start root, actual executable-parent operation and
retained execution manifest under its separate domain.

Only one `O_EXCL` creation and fixed-width write are attempted. File and directory
fsync plus exact retained-inode/name/byte readback precede the independent actual
execution-creation claim. The creation journal keeps its existing `SWNEGCR1`
stable slot: it cannot be reused by crossing the diagnostic/execution profile
boundary. Failure of either claim burns the corresponding attempt; neither
partial publication nor an uncertain fsync is deleted, repaired or retried.

`StartPermit` retains both genuine claims. `prepare_containment` passes the same
actual start owner and consumed permit to `ContainmentOwner::create`; only that
path may create the new leaf and write/read back the signed resource limits.
No serialized digest, successful diagnostic or generic callback can replace an
owner or permit. This is local protected durability, not off-host rollback proof.

## Admission expiry does not disable emergency cleanup

Admission checks poison their owner after failure and never renew the original
clock. The separate `check_cleanup_integrity` checks only retained identity and
claim originals; it grants no creation or execution permission. The leaf owner
must still attempt exact-owned emergency termination even if current admission
has expired or claim diagnostics fail. The separately signed absolute cleanup
deadline bounds waiting and any successful empty-leaf observation, not a right
to leave owned tasks running after that deadline.

An observed empty cgroup is not leader reaping, execution acknowledgment, healthy
application behavior or a final cleanup receipt. Those require the future actual
new-child and independent-guardian owners. Public orchestration, combined
CA/egress execution, lifecycle/recovery and runtime acceptance remain open.
