# Actual driver bootstrap and retained phase-two handoff

This v1 source slice breaks the **measurement ordering** cycle. It does not
construct an operational native bridge or complete a generation install.
The old guest/supervisor, five/six-proof cohorts, ordinary generation/commitment
launchers and runtime profiles are unchanged. Nothing was built or executed.

The explicit [v2 operational continuation](native-shadow-driver-continuation.md)
now connects the same retained measurement to native context/key admission and
the inspected bridge constructor. It preserves the v1 retention-only behavior.
Full-purpose configuration activation, complete operational settlement/reaper
ownership and connected-pilot verification remain required.

## Actual caller and owner

`serverware.native_shadow_driver_bootstrap.DriverBootstrap.start()` opens fixed
protected control/configuration/window originals and executes the pinned sealed
`serverware-native-shadow-guest-supervisor --driver-bootstrap`, empty environment,
with only its actual authenticated parent seqpacket channel. The fixed Rust
parent uses the existing `parent_process::Child` clone/PIDFD/exit/reap owner to
execute the existing fixed guest with the same explicit selector. This is not a
new arbitrary command launcher or the proof cohort's parked identity.

The guest admits the separately signed cold bootstrap, opens the pinned immutable
image, retains real self PIDFD/executable/cgroup/root descriptors, changes root,
irreversibly drops to the signed UID/GID, clears capabilities, and installs the
exact structurally verified bootstrap filter. No service credential is opened,
no business FD is inherited, and no service connection is made. Original
`CLOCK_BOOTTIME` startup/lifetime SIGKILL timers and parent-death ownership remain.

Only then does `driver_identity::Owner::measure` call the existing
`ProductionCustodyKernelDriverIdentity::from_verified_kernel_descriptors` with
actual process start/PIDFD inode, retained executable hash, actual boot, cgroup
mount/inode and kernel cgroup ID. `name_to_handle_at(AT_EMPTY_PATH)` must return
the exact eight-byte `FILEID_KERNFS` handle, not an inode/hash approximation.
This follows Linux's [kernfs handle encoding](https://raw.githubusercontent.com/torvalds/linux/master/fs/kernfs/mount.c)
and [FILEID_KERNFS definition](https://raw.githubusercontent.com/torvalds/linux/master/include/linux/exportfs.h).
Only a non-root canonical cgroup-v2 leaf is accepted; no cgroup is provisioned.
The measurement does not prove exclusive membership, subtree drain or grant
cgroup-kill authority; an operational reaper must establish its actual scope.

The descriptor manifest is explicitly the four **bootstrap driver originals**,
in order: self PIDFD, executable, cgroup directory, immutable root. It is not a
full operational FD inventory, stable-reaper identity or settlement manifest.
Adding business descriptors later requires their genuine separate owner and
complete operation/generation descriptor accounting; this digest cannot replace
that accounting.

The root parent authenticates the child's actual SCM credentials/PIDFD, checks
the retained clone start, rereads final executable/root/cgroup/status, validates
the identity hash and forwards the exact observation. The Python caller retains
the actual supervisor and measured-child PIDFDs. An observation copied from
JSON cannot construct this owner. The supervisor remains powerful trusted-host
root, not a read-only sandbox, hardware signer, NSM service or TEE claim.

## Cold contracts and one contact

Fixed originals are `/etc/serverware/native-shadow-driver-bootstrap-control.json`,
`native-shadow-driver-bootstrap.json` and `native-shadow-driver-bootstrap-window.json`.
The separately provisioned executable is
`/opt/serverware/serverware-native-shadow-guest-supervisor`.
Configuration/window wire shapes are closed in
`schemas/native-shadow-driver-bootstrap.v1.schema.json`.

The immutable image's runtime original is the distinct exact
`nativeShadowDriverBootstrapRuntime/v1` purpose object, not the future operational
runtime. Bootstrap and phase-two authority keys must differ. The signed window
pins the actual boot/time namespace, invocation, original issue/startup/lifetime;
startup is at most 30 seconds. This source does not create any signing key,
assignment, image, seccomp permission, cgroup or authorization.

After obtaining the genuine observation, independent authorities prepare the
operational runtime/C9/five generation grants. `retain_scope` takes their exact
canonical public originals and an independently signed
`nativeShadowDriverScope/v1`, makes one real fully sealed root-owned mode0400
memfd, and attempts one SCM_RIGHTS transfer. The scope commits the full original
observation, actual driver identity, original cold/window/invocation/deadlines,
all seven original digests and complete public-bundle digest. Parent and child
check it separately. The actual C9 signature and boot/UID/GID/invocation/deadline
binding are also checked, without adopting its credentials or activation FDs.

Bounds remain explicit: configuration 64 KiB, window/scope 32 KiB, observation
64 KiB, each inner public original 64 KiB, whole canonical bundle 1 MiB, exactly
one transferred FD and one attempt. There is no resend after EINTR/EAGAIN, lost
reply or uncertainty, no new timer and no fallback to an older profile.
`nativeShadowDriverPhaseTwoRetained/v1` reports only retention. It does not
disarm the startup timer or announce constructed/generation-ready. Until the
next connection is implemented, the retained child is killed at that unchanged
startup deadline. Cancellation retains originals until actual child death and
supervisor reap; this is not a signed per-operation five-service settlement.

## V1 boundary and its explicit successor

The v2 successor separates pre-drop resource preparation from continuation in
the same final process. It retains the measured identity/image/filter, adopts
the real C9 files and activation descriptors, verifies the current assignment
and closure, admits one native key owner, and constructs the inspected bridge.
Its native configuration comes from the real
`from_native_closure_with_settlement_authority` constructor, not a deserialized
legacy software closure. The raw v1 `PhaseTwo` owner grants none of this.

That configuration remains unactivated until a genuine full-purpose verifier
result is connected. Complete operational descriptors, generation/settlement
ownership and a genuine stable reaper remain required; none can be synthesized
from this four-descriptor measurement. Packaging, signed deployment inputs and
connected-pilot execution are still unperformed.
