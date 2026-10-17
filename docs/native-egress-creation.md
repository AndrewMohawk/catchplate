# Native egress precreation claim

The creation journal is a separate trusted-host-local purpose. A genuine retained
precreation owner admits the v2 egress grant and its separately signed
`creationJournal` before requesting a claim. That owner retains the actual
connection/proof, packet/configuration and CA originals, host association,
protected capability token, launcher/manifest originals and original clock.
Neither a supplied successful verdict nor a digest by itself grants creation.

The v2 grant's creation journal must differ from the kernel journal by path,
directory device/inode and namespace. The directory is preprovisioned
root:root `0700`; no provisioning occurs here. The creation slot is SHA-256 over
the dedicated `catchplate.nativeEgressCreationSlot/v1` plus NUL domain followed
by each signed namespace and capability ID as a four-byte big-endian byte length
and exact bytes. Fresh proof hashes, child PIDs and namespace identities never
select a new slot. They cannot make a consumed capability reusable.

The original record is exactly 73 bytes: `SWNEGCR1`, one claim-stage byte (`1`),
the 32-byte slot digest and the 32-byte exact owner-scope digest. The scope binds
the admitted v2 grant, including token/launcher/manifest pins, and the actual
retained proof/packet/configuration/CA originals. Raw tokens are not recorded or
logged. Only `<slot-lowercase-hex>.claim` names are admitted, at most 64 records;
foreign, malformed, incomplete or uncertain records refuse admission.

The concrete sequence is:

1. Recheck the actual owner, process, root identity, signed directory and every
   no-follow held ancestor; acquire its nonblocking exclusive directory lock.
2. Require an unused slot, then publish with `O_EXCL`, root:root `0600`, one link
   and the signed filesystem device. No error path removes the inode.
3. Write the exact original, fsync the file and directory, and read back the same
   held/named inode and bytes while the original owner is still live.
4. Return a non-cloneable permit. The workload constructor consumes it and checks
   pointer identity against the actual owner before cloning the child. The child
   owner retains the permit, journal lock, original record and precreation owner
   for its entire live lifetime.

Any already-present slot refuses new creation, including one whose previous
attempt succeeded, failed before clone, failed after clone or has an unknown
outcome. This deliberately sacrifices retry availability. There is no completion
transition, cleanup, automatic retry, reattachment, recovery or record migration
API. The existing `SWNEGRS1` and `SWNEGRS2` kernel-effect journals are not reused or
relabeled; their claim still independently precedes firewall mutation.

The record/slot digests can describe a local observation but cannot stand in for
the permit or current owner. A durable creation claim authorizes neither workload
exec/start nor network attachment, kernel mutation, recovery or production
acceptance. Filesystem fsync and cooperative local locks are not off-host rollback
protection or hostile-host proof. Source implementation alone proves no runtime
or provisioning outcome.
