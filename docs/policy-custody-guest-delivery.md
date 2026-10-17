# Guest shadow-service delivery and construction

This is the first of four native shadow-custody prerequisites. It supplies real
held guest-local inputs to the five service constructors and production bridge.
It is not a native custody admission, a guest launcher, encrypted provisioning,
or a replacement for independently verified custody effects.

## Actual owner and caller boundary

`policy_shadow::PreparedGuestServiceDelivery::admit` receives configuration path
and exact SHA, then signed delivery path and exact SHA, from the future cold
parent assignment. It runs as root and returns a non-Clone, non-serializable
owner. Its `role_uid()`, `role_gid()` and `startup_deadline_boottime_ns()` expose
only admitted metadata. The future fixed child must permanently drop to those
IDs, remove supplementary groups and every capability (including bounding and
ambient), set no-new-privileges and nondumpability, then consume the SAME owner
with `run_after_drop()`. No reconstructed owner, post-fork reuse, environment
fallback, or later deadline is accepted.

The owner retains the actual self PIDFD, start time, boot and time namespace;
root-owned 0400 configuration, delivery and runtime-config originals; and
role-UID:role-GID 0400 credential FDs. Every pathname component is opened without
symlinks through protected ancestors; aliases, mutable modes and multiple links
are refused. Credentials are opened during preparation but their contents are
read only after the actual final-identity check. Subsequent reads use those FDs,
not a fresh lookup. The held originals are checked throughout construction and
serving. This is retained-original custody, not proof that external current
generation/key grants remain authorized: existing service checks still own that.

The root assignment is exact5 `catchplate.policyCustodyGuestConfiguration/v1`:
apiVersion, authority, serviceRole, uid and gid. The authority is an independently
provisioned Ed25519 public key and SHA256(raw32) key ID, distinct from every
delivered signer. IDs 0, 65534, 64988–64990 and UINT32_MAX are refused. The future cohort must
also enforce distinctness from every other independently signed service role;
this module does not invent a global UID assignment.

The exact3 delivery envelope contains apiVersion, payload and signatureBase64url.
The exact15 payload binds configuration SHA, authority key ID, closed service
role, final UID/GID, raw16 kernel boot ID, time-namespace device/inode, original
issued/startup/lifetime BOOTTIME decimal strings, nonzero invocation ID, exact
runtime-config pin, credential inventory and activation inventory. Ed25519 signs
`catchplate.policyCustodyGuestDelivery.signature/v1` followed by NUL and the
repository's exact UTF-8 canonical JSON payload (no newline). All base64url is
unpadded and canonical. The signed startup interval is at most 30 seconds and
must fit the existing runtime startup budget; it is never restarted at load.
Startup must be live and no later than the separately signed lifetime.

Each credential is exact4 `{name,original:{path,sha256},length,signing}`. Signing
is required-null or exact2 `{publicKeyBase64url,keyId}`. A signing credential is
exactly 32 raw seed bytes: the actual derived public key and configured role key
ID must equal the independently signed assignment. Public/history credentials
remain verified by the original constructors. Bounds are 64 credentials,
4 MiB each and 16 MiB aggregate; delivery/configuration are 64 KiB and runtime config
4 MiB. No keys are generated, copied into images, or delivered by this slice.

## Descriptor and progress contract

FD3 is the private same-guest parent AF_UNIX SOCK_SEQPACKET link. Admission binds
actual SO_PEERPIDFD, SO_PEERCRED root UID/GID, getppid and retained parent start
time. Parent liveness and the original channel remain required after child drop;
there is no caller-supplied target PID or relay identity. The future launcher
must own that real endpoint and must not export it.

Activation is an ordered exact inventory of slots 6..69, with exact names and
kernel device/inode/mode/UID/GID. No aliases, arbitrary path reads, or additional
named capability are admitted by the real per-role constructors. Those
constructors still verify exact listener pathname, directory/mount identity,
peer executable/cgroup/label and current signed endpoint identities. Delivery
does not weaken any of these checks. The future fixed-exec launcher remains
responsible for closing all unlisted ambient descriptors before admission.

The purpose-fixed exact5 `catchplate.policyCustodyGuestStartup/v1` notice binds
delivery SHA, role and signed invocation ID, with phase `constructed`. It is
sent once on FD3 only at the original real readiness callsite, after journal
recovery, required peer handshakes and backend construction. The future parent
must enable/verify kernel SCM_CREDENTIALS and SCM_PIDFD against its owned child
PIDFD at the final assigned UID; JSON does not prove readiness or process
identity. No incoming command/retry/readiness protocol is introduced.

## Existing semantics preserved

Host entrypoints still load systemd credentials/activation and use systemd
invocation/readiness. Guest entrypoints call the typed loaded constructors
directly and never call a host loader or synthesize an environment. Both use
the actual durable store, cleanup authorization consumer, recovery target,
current-signature authority, bounded cleanup helper and production bridge.
Existing reports remain explicitly `TrustedHostNoTee`. Those labels MUST NOT
be presented to a native verifier as measured evidence.

Guest scope refuses request deadlines beyond the original signed lifetime;
existing operation/cleanup intervals are not rewritten or renewed. This local
guard does not provide process kill/reap, in-flight cancellation or terminal
cleanup evidence. The bounded-helper scheduling seam receives the same private
Bootstrap owner, refuses requests and every pending-effect progression whose
exact deadline exceeds the original guest lifetime, and retains the existing
signed internal deadlines. It cannot become native-ready until the full
lifetime/settlement owner below is joined.

## Remaining complete native-custody work

1. **Delivered here:** signed guest originals and real service construction.
   Independent provisioning, fixed executable launch, privilege drop and parent
   authenticated progress consumption still require their actual producers.
2. **Measured key-set and closure:** genuine per-role non-exporting keys, own
   NSM identity and independently authorized complete custody execution closure,
   fed to the existing TEE verifier. The gate's identity/currentness keys and
   verifier workers are not substitutes.
3. **Fixed-peer inspection:** real distinct-UID nondumpable guest peer evidence.
   Existing proc/executable/signal0 checks may refuse across those identities;
   no DAC, broad ptrace, same-UID or host-vsock identity fallback is supplied.
4. **Original native lifetime:** same Prepared origin and real parent lifetime,
   full operation-plus-cleanup interval admission, bounded stop/reap and genuine
   fence/settlement receipts. No service notice, worker exit or timeout substitutes
   for those proofs.

Source only. No parser/build/test/guest execution or kernel support verification
was performed for this slice, and no full native-shadow or pilot closure follows.
