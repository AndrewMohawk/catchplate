# Native retrieval artifacts and object installation

The operator-side [artifact API](../serverware/native_shadow_retrieval_artifacts.py)
and [installer](../serverware/native_shadow_retrieval_store.py) prepare the first
[native immutable-retrieval service](native-shadow-retrieval-service.md). They are not a custody driver, an admission
verdict, a running service, or a production readiness result. Current source is
unbuilt and unexecuted.

## Inputs and outputs

1. Supply the independently retained original proof scope, receipt payload and
   assignment-bound authority payload. `object_original` packages those exact
   bytes; it does not invent a receipt or signature. `object_locator` derives the
   retrieval ID, proof digest and content-addressed filename using the same
   framing as the native reader. A scope is data, never a runtime owner.
2. `manifest_original` packages one to sixteen unique objects, each at most
   1 MiB. Pin the complete canonical manifest independently before installation.
   All canonical originals use the existing ASCII/integer profile without LF.
3. Independently provision an empty root:root mode-0700 target directory with
   protected, non-symlink ancestors on a filesystem supporting fs-verity. The
   installer does not create directories, enable filesystem features or mount
   anything. It only creates exact new content-addressed files, enables actual
   SHA-256 fs-verity, verifies their contents, freezes files to 0444 and the
   directory to 0555, then rechecks the complete bounded inventory.
4. Separately invoke `sign_service_grant` with independently pinned verifier-v2
   configuration, exact scope and measured expected-peer originals, an explicit
   current interval, and the already provisioned supervisor key object. This is
   an explicit new operational assignment, not automatic permission following
   key admission. The native guest still checks the actual current assignment,
   key/closure association, trust, time and parent-measured peer before serving.
5. Supply the resulting operational grant and actual object-directory descriptor
   through explicit `nativeShadowRetrievalGuestLaunch/v1` and signed C9 activation. The activation
   names are `retrieval-objects` and `retrieval-listener`; the guest itself must
   listen and accept under its final identity. Neither the installer report nor
   the object manifest authorizes that launch.

The [retained activation producer](native-shadow-retrieval-activation.md) now
creates that actual fixed listener, retains the existing object-directory
descriptor, and signs only an independently approved exact C9 payload before a
one-shot descriptor handoff. The complete outer supervised launch remains
separate; preparing descriptors does not claim a running service.

## Operator invocation

The installed `scripts/install_native_shadow_retrieval_store.py` requires Python
isolated mode (`-I`), root identity, an explicit `--directory` and
`--manifest-sha256`, and the original public manifest on inherited FD3. That
descriptor must be a read-only root:root0444 regular file with one link. No
private key or secret is accepted by this CLI. Run it only under an external
watchdog; kernel fs-verity setup is synchronous and no hard time limit is claimed.
This entrypoint currently targets Linux x86-64, matching the native image ABI.

The returned canonical `nativeShadowRetrievalStoreInstalled/v1` report records
the actual directory/file identities, object hashes and kernel-measured verity
digests; `releaseAuthority` and `serviceReady` are always false. Preserve it
outside the frozen object directory. The fs-verity digest is not the ordinary
object SHA-256. See the [Linux fs-verity API](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html).

All objects are validated before the first write. Installation uses exclusive
creation and never replaces a name. Unsupported fs-verity, existing entries,
changed identities, interrupted writes or uncertain output fail without repair
or deletion. Preserve partial state for explicit operator reconciliation; do
not retry automatically or treat a missing acknowledgement as permission to
reuse the directory. No service, key, signature authority or runtime acceptance
is established by an installed object store.
