# Software five-service C9 generation launch

This source connects the five existing software service loops to their real C9
owner and generation-v5 gates. It does **not** produce native custody/NSM
evidence, complete generation installation, provide rollback-resistant storage,
or establish pilot readiness. The service reports remain `TrustedHostNoTee`.
The native proof cohort and its bridge are separate owners.

## Actual ownership and order

The fixed root-protected `0400`, single-link original
`/etc/serverware/custody-generation-five.json` selects the closed launch profile
in `custody-five-service-launch.v1.schema.json`. It pins all five independent C9
configurations and the five existing `/usr/local/bin/serverware-policy-custody-<role>`
executables. No request, environment variable or generic executable path selects
a different program. The executable must be an actual root-owned `0755`,
single-link fs-verity-protected ELF. A content digest is not substituted for
fs-verity or IMA evidence.

`FiveServiceLaunch.start()` requires an initially single-threaded root operator.
It opens/retains the full inventory, forks each actual child, obtains its PIDFD
and start ticks, and receives that child's kernel-credential-authenticated
parked notice. The same child later directly executes the retained executable;
there is no second fork or guessed future PID. `parked_originals()` reports only
these observed identities and the retained intended executable, not final
UID/GID/cgroup/security-label/IMA measurements. Existing strict service peer
admission must obtain those genuine additional originals independently.

`GenerationInputs.prepare(launcher, business_descriptors=...)` requires that
exact retained owner. The business descriptors are real existing listening Unix
seqpacket sockets and real role-owned `0700` state/journal directories; their
contents are never adopted from a supplied JSON description. Runtime pinning
and the existing service storage owners still perform their complete admission.
Preparation allocates one real empty grant memfd per role, fixes its role
ownership and `0400` mode, and creates the one fresh `generation-journal` below
each preprovisioned root-owned `0711` directory
`/var/lib/serverware/custody-generation/<role>`. The generation directory must
not already exist. Existing partial files are evidence, not restart permission.
Only ext4, XFS and Btrfs storage is admitted by this bounded producer; the actual
service journal also retains its own filesystem/durability checks.

The finite authoring API is:

1. Read `activation(role)`, `directory_identities(role)` and
   `launcher.parked_originals()` to construct independently approved runtime,
   credential and peer originals. These are observations, not authority tokens.
2. Install the exact independently selected runtime and credentials. Call
   `sign_delivery(role, approved_payload_original=..., delivery_authority=...)`
   with the existing independently supplied C9 authority. The method checks the
   real allocated descriptors, runtime directory/listener identities, original
   boot/deadlines and invocation. It publishes the exact signed C9 original
   exclusively at `/etc/serverware/custody-<role>-delivery.json`.
3. Obtain the actual `guest_original(role)` and authorize the complete scope18
   grant using the independently supplied authority-history root. Call
   `seal_grant(role, approved_grant_payload_original=..., history_root_authority=...)`.
   This key must match the actual original manifest's root SPKI and runtime
   root pins and be distinct from both C9 and service signing keys. It is not
   generated, logged, delivered to a child or relabeled as an NSM key.
4. The actual bounded grant is written into the previously allocated memfd,
   read back and permanently sealed against write/grow/shrink/seal changes.
   Only then is the fixed protected guest launch original published. All five
   grants must bind the same complete installation scope. `grant_sha256s()`
   returns the exact five pins for the existing bridge-v5 generation selection.
5. `launcher.release(inputs.transfer())` consumes the actual typed transfer
   before its first possible send. Each child gets one packet with the actual
   launch original at FD4 and exact signed activation slots6..69. FD3 remains the
   actual root parent channel. Partial/unknown send poisons the whole launch;
   there is no resend, new claim or renewed deadline.

The fixed `--guest-c9-generation` branch on each existing binary admits the
same named/FD4 launch original, verifies C9/credentials/descriptors before drop,
installs original absolute BOOTTIME kill timers, permanently removes root,
groups and capabilities, and calls the actual existing `run_after_drop` owner.
The ordinary default/systemd binary path is unchanged. This generation-only
profile does not admit a future dispatch-grant activation or native HMAC role.

The parent watchdog retains every actual child PIDFD through startup and the
original lifetime, including the exec interval. Each child separately retains
its lifetime timer through the actual service loop. Only the real service's
authenticated `constructed` notice disarms startup bounds. `constructed()` is
not generation commit/certification. The actual B coordinator and five signed
generation effects/certification still have to complete through their own
admitted protocol. A timer expiry, child exit, malformed notice or uncertainty
kills/reaps the same children and never manufactures a successful outcome.

## Two distinct history commitments

Only actual Guest-backed runtime-v5 selects the constructibility correction.
The signed C9 credential pin authenticates the SHA-256 of the **complete exact
manifest file bytes**. The full existing `RuntimeAuthorityHistory` independently
checks every retained history signature/root and the **semantic manifest SHA**,
which hashes its canonical eight-field tuple under the existing domain. The
grant and runtime pin that semantic digest. These two commitments are not equal
by definition; neither is removed or truncated. Legacy runtime-v4 is unchanged.

The generation signature uses the existing custody signature framing, not the
native envelope framing: `serverware-signature-v1` plus NUL, u64be domain length,
the exact purpose domain, u64be payload length and canonical payload bytes.
ASCII integral JSON preserves u64 values and rejects floating-point input;
the existing epoch-nanosecond fields retain their i64 bounds. No private seed is
read by the parent to produce a service key assertion; final-role service key
loading remains the actual existing owner.

## Explicit deployment and execution boundary

The caller must supply independently provisioned signing authority objects,
complete signed history/assignment/runtime/credential originals, genuine
business listeners/state, protected fresh directories and installed fs-verity
executables. The operator must keep the retained launcher/input owners alive;
`close()` kills and reaps actual children before releasing journal/lock/file
descriptors. Public partial files and journal directories are never unlinked,
repaired or silently reused. This initial producer is fresh-only, not a
same-guest restart or cross-boot recovery procedure.

The whole flow is source-only: no processes were launched, no keys generated,
no provider contacted, and no build/test/runtime acceptance is claimed. The
native bridge/proof services, actual coordinator/certification, kernel feature
availability, provisioning and end-to-end pilot execution remain distinct
integration/deployment requirements.

The ordinary inherited-seqpacket peer reader also still needs a genuine
privileged-inspector ownership join. It currently opens and rechecks the peer's
`/proc/<pid>/exe` after the service has dropped its capabilities, while the
isolated bridge is non-dumpable. Parked-child observations cannot supply the
missing final peer measurements, and this launcher neither relaxes that check
nor grants services broader capabilities. This is an explicit remaining source
connection, not something operator-supplied JSON can resolve.
