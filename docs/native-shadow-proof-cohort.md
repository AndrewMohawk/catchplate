# Native parked proof cohort

This is a source-only five-child preparation and one-shot release owner. It is
not a ready bridge or an operational deployment. The generation-install slot
currently refuses before **any** child gate is released: the real coordinator
service selector, durable owner and assigned peer remain a required join. The
five ordinary custody services are a different cohort and are not produced here.

## Actual order and authority

The fixed order is Retrieval, Persistence, TrustedTime,
GenerationInstallEnvelope, Bridge. `serverware-native-shadow-proof-cohort`
accepts no arguments, an empty environment, and only inherited FD3 besides
stdio. FD3 is the actual private root-peer seqpacket channel. It admits the
protected fixed configuration and independently signed precreation, arms the
original absolute `CLOCK_BOOTTIME` lifetime watchdog, and creates five real
parked children using the existing clone/PIDFD/parent-death/gate owners. Each
child owns a distinct sealed executable inode. No PID or inode is predicted.

The observation is the actual canonical `nativeShadowProofCohortOriginals/v1`
record. Each child contributes its PID, start ticks, and retained sealed
executable device/inode/length/SHA. These are still-root parked identities, not
final credentials, cgroup, label, TEE evidence, installed service or readiness.
The parked child directly `execveat`s the fixed guest after release: its PID,
start ticks and executable inode become the actual guest endpoint. It does not
spawn an intermediate guest supervisor. The retained privileged inspector must
still measure the strict final nondumpable peer after exec/drop.

The existing independently provisioned C9 delivery authority signs a separate
release only after approving the actual observation and all five protected
launch/image originals. The closed authoring functions are in
`serverware/native_shadow_proof_cohort_assignment.py`; they generate no key and
do not authenticate caller JSON as a kernel observation. The actual Rust owner
compares the release with its retained children and originals again. All five
grants, C9 inventories, peers, images and original windows are admitted before
the first gate send. A partial gate-send failure cancels the whole cohort; it is
not an atomic readiness result and is never automatically retried.

The precreation and release signature preimages are respectively
`serverware.nativeShadowProofCohortPrecreation.signature/v1`, NUL, canonical
payload, and `serverware.nativeShadowProofCohortRelease.signature/v1`, NUL,
canonical payload. These are distinct from service grants, role possession,
trusted time, verifier, dispatch and generation effect authority. The source
requires the same actual boot/time namespace, invocation, issued time, original
startup deadline (at most 30 seconds after issue), and absolute lifetime in
every C9 delivery. Cleanup reserves the existing final 250 milliseconds; it
never creates a renewed effect interval.

## Real operator caller and descriptor handoff

`native_shadow_proof_cohort_control.ParkedProofCohort.start()` opens only the
fixed protected operator selection, retains its full named-file ancestry and
pins, seals the fixed static cohort executable, and starts that actual executable
with a fresh private FD3. There is no shell, generic argv, environment-selected
path, key read, or observation/ready/PID constructor. The owner authenticates
the single observation against its actual child PIDFD/start/parent and received
SCM credentials/PIDFD, then retains actual PIDFDs for all five parked children.
`check()`, `original_bytes()`, `bridge_original()` and the original deadline
accessors are available only on that live, source-private owner.

The Persistence/v2 producer requires this exact owner, not duck-typed JSON.
Its one-shot `PersistenceTransfer` supplies the actual listener6, journal7 and
held same-OFD lock8, plus retained exact public delivery/grant originals. The
receiver uses `PersistenceLocked`, never the v1 reopen/flock path. Other
already-produced descriptor inventories can be retained with
`retain_activation_fds(role=..., launch_pin=..., descriptors=...)`: this only
duplicates actual FDs matching independently signed C9 metadata; it is not a
resource creator, service verifier or substitute for the original resource
producer. Those producers and their owners remain required, including the
generation coordinator producer. Keep every original producer alive as well
as the returned transfer throughout the cohort lifetime.

`release(release_original=..., transfers=...)` verifies the exact independent
release and each protected launch/C9/grant original, consumes each source
capability's `begin_release()`, and makes exactly one SCM_RIGHTS send. Rights are
concatenated in the fixed five-role order, with each C9's signed consecutive
FD6..69 order; the packet is at most 32 KiB and total rights are 5..128. The
Persistence adapter's signed originals must equal the files actually pinned by
its launch. All socket, directory and lock identities must match the signed
inventory and remain distinct. EAGAIN, interruption, partial send, lost contact
or later failure is unknown/nonretryable, not permission for another send.

No ACK, ready frame or success result exists. The operator retains the channel,
all transfers and actual process owners until explicit cleanup. EOF or an
unexpected subsequent packet cancels the Rust owner. The parent signals all
children before waiting, reaps through their same PIDFDs and retains every image
and original through termination. The operator `close()` requests EOF cleanup,
then, if necessary, uses its actual PIDFDs for SIGKILL; it releases resources
only after all observed children are terminal and its direct supervisor child
has been kernel-reaped. Its bounded cleanup waits do not authorize any service
effect after expiry. Failure retains the live owner and refuses a new start;
there is no numeric-PID fallback, automatic unlink, mount-retirement claim or
claimed successful application result. A separate context-manager scope must
remain open for the intended serving interval; exiting it immediately cancels.

## Fixed installation inputs

All configuration, precreation and post-create launch/image originals are
protected root-owned files with mode0400, one link and no symlink ancestors.
The fixed operator executable is root0555. The static guest executable and
runtime-image contracts remain unchanged. Required fixed paths are:

- `/etc/serverware/native-shadow-proof-cohort-control.json`: closed control4,
  independently pins the cohort executable and exact configuration/precreation.
- `/etc/serverware/native-shadow-proof-cohort.json`: closed configuration8,
  with five separate cold C9 configurations and the guest executable SHA.
- `/etc/serverware/native-shadow-proof-cohort-precreation.json`: signed window9.
- `/opt/serverware/serverware-native-shadow-proof-cohort`: actual static binary.
- Existing fixed guest executable, launch placeholder and immutable-image
  placeholder used by the real parked-child owner.

The Docker `native-shadow-proof-cohort-artifact` target declares the actual
static binary build/artifact, separate from guest and Python helper images.
It does not install files, provision authorities, create resource listeners,
issue live assignments or establish kernel/mount/fs-verity support.
The paired schema is `native-shadow-proof-cohort.v1.schema.json` with
`controlConfiguration`, `configuration`, `precreation`, `observations`, and
`release` definitions. Explicit cold selection leaves old single-guest and
retrieval-pair profiles unchanged.

No build, parser, test, process launch, provider or cloud execution has been
performed for this source slice. The missing actual generation owner and
ordinary five-service launch/call chain remain implementation work, followed
by integrated build and runtime/deployment verification. This slice claims no
full bridge readiness or production acceptance.
