# Scoped native CA installation destination

`native_bootstrap_client/install/destination.rs` is a private Linux filesystem
owner for the exact destination admitted by the parent installation operation.
It does not verify or create installation permission. The parent must retain its
separately root-signed host installation authority, signed setup scope, genuine
same-connection native attestation and actual runtime CA DER original, observed
host/namespace owner, original deadline and irreversible reservation claim.
This is source-only implementation, not an executed installation or acceptance
result. The existing legacy installer is unchanged.

## Fixed interface and preprovisioned resources

The data-only `Spec` contains the absolute destination, final UID/GID, mode 0644,
`replace_existing`, and optional expected existing certificate **DER** SHA-256.
The old digest is present exactly when replacement is authorized. UID/GID cannot
use the all-ones sentinel. Paths are bounded at 4096 bytes and 128 components;
empty/dot/dot-dot components, controls, backslashes and reserved recovery paths
are refused. No path, command or permission interface is exposed outside the
private parent module.

`Destination::prepare(spec, &InstallGuard)` borrows the parent's concrete live
guard and retains the actual root and every ancestor directory descriptor.
Every ancestor must be root:root, non-group/world-writable and free of special
mode bits; actual opens use `O_NOFOLLOW`. The destination itself must be absent
or one bounded canonical PEM certificate in a nonexecutable, single-link regular
file with no group/world write or special bits. Its exact bytes, inode, ownership,
mode, size and modification/change timestamps are retained. Preparation captures
the current state; the signed old-digest condition is enforced before installation,
not confused with a later read-only completed replay.

The destination's parent directory must already contain:

- `.serverware-native-ca-install/`, root:root mode 0700, on the same filesystem.
- Its fixed `destination.lock`, an empty single-link root:root mode-0600 regular
  file. The destination owner never creates a missing directory or lock.

The reservation owner's journal lock is acquired first. This owner then takes a
nonblocking exclusive `flock` on the fixed destination lock and holds it through
final readback and reservation completion. Contention refuses; there is no wait
loop or lock-order inversion. One lock serializes cooperating installations in
that destination parent, including different destination filenames.

Named and held directory/file identities are rechecked under the original guard.
This is observed local filesystem/namespace state, not proof against a privileged
host or an uncooperative writer. Blocking filesystem operations still require an
external execution watchdog; cooperative clock checks cannot interrupt a blocked
kernel call.

## Claim first, then one bounded publication

The parent calls `install(actual_ca_der, expected_der_sha256)` **only** after a
fresh durable claim. The method is single-attempt and becomes unusable after an
error. It checks the exact new DER digest, parses one complete bounded certificate
and derives its canonical PEM; no new key, CA, certificate authority or trust
input is selected here. Certificate DER/PEM caps are 16/64 KiB. Every operation
uses the retained original `InstallGuard`; no timeout or verification lifetime
is opened by this primitive.

Create requires the destination still be absent. Replacement requires the actual
retained old certificate DER hash to equal the explicitly signed old digest.
The owner first publishes a protected root:root 0600 copy of the exact old PEM,
using `O_CREAT|O_EXCL`, file fsync, named/held checks and exact readback, followed
by directory fsync. A new canonical certificate is independently staged with
the signed final UID/GID and mode 0644, also with exclusive creation, fsync and
readback. Recovery filenames are fixed prefixes plus a source-computed digest
of the exact destination, ownership, create/replace mode and old/new CA hashes;
neither filename is supplied by a request.

Linux `renameat2` performs the only destination effect:

- Create uses `RENAME_NOREPLACE`; any competing destination refuses.
- Replacement uses `RENAME_EXCHANGE`. The old destination becomes the retained
  staging name; its actual inode/content/metadata are checked again. The separate
  pre-effect protected old-PEM copy also remains available for explicit recovery.

There is no ordinary overwrite fallback, unlink, automatic rollback or cleanup.
Unsupported atomic operations and cross-filesystem publication refuse. Successful
publication synchronizes both directories, reads the exact installed certificate
back, and checks its DER hash and signed final ownership/mode. The recovery
directory accepts only fixed lock/recovery names and is bounded at 512 entries
and 16 MiB; capacity is checked before creating this operation's originals.

## Read-only replay and uncertain outcomes

`check()` revalidates the retained path, lock, certificate and recovery originals.
`installed_certificate_der_sha256()` is a guarded read-only observation and
requires the actual present certificate to have the signed final UID/GID/mode.
For `AlreadyComplete`, the parent must compare that digest to the independently
admitted native CA and must not call `install`. A missing or changed destination
does not authorize repair or reinstall.

Any failure during or after publication leaves the reservation consumed and the
available recovery originals intact. Failure after the atomic rename can mean
the new CA is already present even when completion was not recorded. Preserve
the journal, destination and recovery files; do not infer noninstallation, retry,
delete the claim or restore the old CA automatically. Local fsync/readback is not
independent off-host rollback protection or a cross-session recovery protocol.

This primitive neither installs a workload client certificate nor modifies proxy
egress rules, restarts a process, changes a namespace, runs a canary or claims
that applications consume the installed trust. Those effects, full runtime-policy
authentication, lifecycle/recovery and production verification remain separate.
