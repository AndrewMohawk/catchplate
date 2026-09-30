# Native Persistence launch inputs

This source connects the fixed fresh resource producer to the explicit
`serverware.nativeShadowPersistenceGuestLaunch/v2` receiver. It does not launch
anything during authoring, provision keys, establish deployment acceptance, or
replace the separate operational Store/Verify grant. Existing v1 is unchanged.

## Actual ownership and order

`native_shadow_persistence_inputs.PersistenceInputs.prepare` takes the actual
`native_shadow_proof_cohort_control.ParkedProofCohort` owner, not serialized
observations. It retains the same creator process/start/boot and original cohort
startup/lifetime. The independently supplied ExpectedPeer14 must match the real
parked bridge PID/start/sealed executable. UID/GID/cgroup/security-label/current
configuration expectations remain independently assigned; parked observations
do not attest future identity. Native inspectors verify the eventual real peer.

The producer opens protected root-owned parent directories, creates only a
fresh fixed listener and journal, and holds the exclusive actual empty named
lock. Parents must already exist; existing listener/journal refuses. Paths are
`/run/serverware-shadow-persistence/listener.sock` and
`/var/lib/serverware/native-shadow-persistence/journal`. Both fixed parent leaves
are root:root 0711. Journal is assigned role-owned 0700, lock 0600, genesis 0400;
listener path is assigned service UID/peer GID 0660. Socket is nonblocking
SEQPACKET with credential/PIDFD delivery, not listening yet.

The finite sequence resolves a real ordering dependency:

1. Retain real resources and obtain actual C9 activation metadata.
2. Independently authorize/sign exact C9 with the existing cold delivery key.
3. Supply exact independently approved genesis and current-head originals for
   that complete signed guest association. Fresh head is exactly sequence zero
   and the genesis hash; never derive authority from an absent file.
4. Write genesis O_EXCL, sync file/metadata/directory, retain exact readback.
5. Independently authorize Store/Verify with the already assigned supervisor
   key, whose raw public key must differ from C9 authority. Full admitted scope,
   local Store key, current trust/revocation and unchanged expiry still apply.
6. Take one `PersistenceTransfer`. The actual cohort sender consumes
   `begin_release()` once immediately before its sole whole-cohort SCM_RIGHTS
   send, installing actual listener6/journal7/lock8. It retains owners through
   actual child cleanup. A send error/unknown result cannot authorize resend.

`PersistenceTransfer.signed_originals()` exposes only the retained exact public
C9/grant bytes so the real sender can match pinned launch originals before
release. It does not reconstruct signatures or manufacture an approval.

The producer signs no attestation. Scope decoding reuses data mechanics only,
not Retrieval permission, key roles, fs-verity acceptance or activation journal
semantics. The service grant remains the existing narrow Persistence family.

## Continuous lock and uncertainty

FD8 is a duplicate of the same already-locked open-file-description. The v2
receiver compares it with the actual named lock inode/mode/owner and requires a
separate open to conflict before idempotently checking the inherited lock. It
retains that original throughout service life; it never drops the producer lock
before admission. v1 continues to open its own lock and accepts only its old two
activation slots.

Each exact journal-population check opens a fresh directory description beneath
the retained directory FD and verifies its identity. This avoids a shared
`scandir` offset making subsequent checks appear empty; it never releases or
reopens the lock.

Any partial resource or genesis failure leaves the listener/journal/files in
place; there is no unlink, repair, adoption or implicit retry. One-shot signing,
genesis, transfer and release attempts retain the original deadlines. Transfer
`check()`/`descriptors()` are pre-release checks, not post-launch observations;
after release the service legitimately changes listener/journal state. Cleanup
closes retained descriptors only after the real cohort stops/reaps its children.

## Remaining deployment and recovery boundaries

The separate actual parked-cohort control/release producer is a required source
join, not a caller-supplied success flag. Deployment still needs independently
enrolled C9/supervisor/role keys, admitted exact grants/assignment/scope/peer and
closure originals, protected image/config paths, provisioned fixed directories,
genuine clock/NSM/current trust, and underlying storage acceptance. ext4/XFS/
Btrfs refusal filters plus fsync/readback are not independent power-loss,
anti-rollback or cross-instance evidence.

This producer intentionally cannot restart a historical journal by allocating
different C9-bound resource identities. Genuine same-guest retained-resource
restart and independent historical head/rollback admission remain separate work.
No old head is reset, rebound to a new boot, or declared recovered from absence.
Storage/runtime limits stay 128 commits, 32 MiB retained total and existing
4 MiB frames/files. This batch is source-only and unexecuted.
