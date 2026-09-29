# Native policy-custody closure owner

This is a finite source implementation of immutable execution-closure preparation
and its actual configuration-admission seam. It is **not** a working measured
shadow-custody service, a custody key producer, or TEE evidence. No build, parser,
kernel, enclave or provider execution is claimed.

The existing host IMA/fs-verity manifest and constructor are unchanged in
meaning. The new `sealed-memfd-squashfs-static-amd64-v1` profile never sets their
verity/appraisal booleans. Native selection requires both an independently
verified Nitro-mode policy assignment and a separate signed native-purpose
authorization. It is not selected by old capability bytes or environment.

## Closed authority and byte contracts

`native-custody-closure.v1.schema.json` pairs Configuration3, Manifest8,
Assignment2, assignment payload15 and the guest binding13 with the Rust types.
The native payload binds the original policy assignment ID, payload digest and
revision; the new manifest digest; the exact retained signed guest config,
delivery, runtime configuration, role/UID/GID, boot, time namespace, invocation
and unchanged startup/lifetime window; original current trust checkpoint and
revocation state; wall-clock validity; and the assigned supervisor key ID/SPKI.

The existing independently assigned `CustodySupervisorCapability` role is
resolved at the actual current checkpoint, including actual public-key material
association. It signs a NEW domain:
`serverware.nativeCustodyClosureAssignment.signature/v1`.
The exact Ed25519 preimage is the existing `signature_preimage` recipe:
`serverware.signedEnvelope/v1`, NUL, new domain, NUL,
`serverware.canonicalJson/ascii-integer-v1`, NUL, canonical payload bytes.
Signature encoding is canonical unpadded base64url64 with no prefix.
This grants closure preparation only, not a role-signing key or provider effect.

The manifest commitment is `hash_domain_frames` under
`serverware.nativeCustodyExecutionClosure/v1` with one canonical JSON array
frame, in this order: apiVersion, profile, imageSha256, workerExecutableSha256,
seccompPolicy, runtimeConfigurationSha256, buildProvenance. The old structural
seccomp and build-provenance hash recipes remain unchanged. The policy
assignment itself must pin this new manifest and the exact structural policy.
The ordinary TEE configuration binding still includes the resulting manifest,
executable and seccomp hashes plus all previous assignment/key/backend/driver
bindings. The existing independently signed TEE result remains mandatory.

## Actual producer and retained owner

`PreparedNativeCustodyClosure::open` accepts only a real
`PreparedGuestServiceDelivery` in the same root preparation process. Its
nonserializable association retains the SAME private Arc, actual PIDFD/start,
boot/time namespace, parent-channel/PIDFD and config/delivery/runtime/credential
originals. No scalar BOOTTIME value, ready DTO, replacement process or copied
path can construct that association. Keys are not read by this closure producer.

The purpose-fixed library mechanism copies the entire independently pinned image
to an owned sealed memfd (all four immutable seals), binds its exact inode/dev,
offset zero/full length to a read-only autoclearing loop, and retains an actual
read-only, nodev, nosuid SquashFS detached root. It does not reuse a broker
helper, issue key RPCs, or imply that the image is already installed as `/`.
The complete image is limited to 512 MiB. It retains these fixed image files:

| Original | Fixed path |
| --- | --- |
| Image outside the root | `/opt/serverware/native-shadow-custody-runtime.squashfs` |
| Static guest executable | `/usr/local/bin/serverware-policy-shadow-custody-guest` |
| Exact BPF | `/opt/serverware/native-shadow-custody/seccomp.bpf` |
| Runtime config | `/opt/serverware/native-shadow-custody/runtime.json` |
| Dependency lock | `/opt/serverware/native-shadow-custody/Cargo.lock` |
| Build recipe | `/opt/serverware/native-shadow-custody/build-recipe.json` |
| Provenance statement | `/opt/serverware/native-shadow-custody/provenance.json` |

These files and the new image/binary are **required future packaging inputs**,
not presumed artifacts. The runtime config must be the exact same digest as
the guest delivery's original config; no normalized substitute is accepted.
Image originals must be root-owned and non-writable by group/other. BPF bytes
must equal every structurally validated little-endian eight-byte instruction,
not merely a supplied policy hash. Lock/recipe/provenance files match the
independently assigned build-provenance pins; this slice does not claim to have
performed a reproducible build or verified a transparency log independently.

The actual currently running guest executable must itself be a root:root0500,
zero-link memfd with all four seals. Its complete bytes (at most 128 MiB) must
equal the pinned in-image executable, pass the existing static AMD64 ELF
validator (no PT_INTERP/DT_NEEDED), and remain the actual `/proc/self/exe` inode.
Executable process mappings must refer to that same inode or the kernel's
`[vdso]`/`[vsyscall]` mappings. This does not attest kernel bytes independently.

`root()` exposes a borrowed actual root only during the original root/startup
window. The future source-owned launcher must really install this root in the
same process, keep genuine proc access for original-owner checks, make the
permanent signed role UID/GID drop with no groups/capabilities, NNP and
nondumpability, then consume `bind_current_process` before threads or untrusted
service input. The producer does not exec or reset the prepared owner. Binding
checks actual `/` inode/dev against the retained root, current sealed executable
and mappings, exact final C9 identity, and one thread; then actually installs
the independently assigned, structurally checked BPF. It observes the exact
filter-count increment. No boolean says a caller installed the filter.

The assigned policy must permit the owner's real held-file/stat, readonly-loop
inspection, proc/PIDFD, clock and service operations. This module neither
widens that policy nor synthesizes a successful install. A policy that kills a
required syscall is a failed deployment, not grounds for fallback. The native
owner shares only an Arc to originals, checks same process/lifetime/root/
executable/filter identity repeatedly, and permanently poisons on such a failed
check. Preparation, service operations and cleanup receive no new allowance.

## Actual admission seam and required continuation

`ProductionCustodyConfiguration::from_native_closure_with_settlement_authority`
consumes that genuine native owner and all the SAME existing actual settlement
driver/backend/interval arguments. The private retained-closure enum keeps
legacy and native sources distinct. Legacy-only `execution_closure_manifest()`
now returns `Result` and refuses native owners; there were no callsites. The
profile-aware native accessor cannot reconstruct an owner. Configuration clones
retain the same Arc; native owner equality is identity, not deserialized data.
The normal configuration revalidation rechecks the native owner and its
current, nonrevoked supervisor authority; trusted-time checks also recheck its
original signed expiry. TEE activation still requires an independently verified
quote-bound result and the actual complete key-set root. The new constructor
does not create `VerifiedCustodyAttestation`.
The native supervisor instance pin is SHA-256 of the retained invocation's ASCII
bytes; its boot pin is SHA-256 of the retained raw 16-byte boot ID. Neither is a
caller-selected replacement. Post-drop executable rechecks stat the kernel's
current-executable link against the original retained sealed FD, without trying
to reopen a root-private executable for content. Filter checks use the actual
calling thread's status; child threads inherit the installed filter.

Still required, and NOT replaced by this slice:

1. A source-owned launcher/packager must supply the fixed static guest, image,
   sealed executing memfd, signed delivery/closure assignment, root installation,
   permanent role drop and real private activation descriptors. Its serving
   caller must retain the returned closure in the actual custody configuration.
2. [Native shadow-role ownership](native-shadow-role-keys.md) now supplies a
   same-delivery local key subset, fixed possession signatures and original NSM
   evidence bound to the independently assigned complete 18-key public root.
   This is not full private-key possession or encrypted provisioning. Purpose-
   specific KMS delivery, the genuine independent verifier producer and concrete
   signer/store/retrieval/trusted-time receipt servers remain required. The
   independent verifier key must never be generated by the claimant.
3. Dedicated fixed-peer inspection must authenticate the real nondumpable native
   gate and distinct custody processes. A local peer label, worker response or
   guest delivery is not measurement evidence.
4. Source-owned same-origin launch/lifetime, teardown/reap and settlement joins
   must retain the exact owners and original operation/cleanup deadlines.

Existing guest services continue to identify as `TrustedHostNoTee` and refuse
measured admission until those genuine counterparts are connected. This source
slice is not whole-shadow or N06 completion, and does not make a pilot runnable.
