# Fixed release resource intake

`oidc_session_activation_release_resources._intake_on_work(*, work,
live_window, transport_deadline_ns)` takes an exact inherited inventory and
returns an actual owned `_Resources` handle for the
[release startup](oidc-session-activation-release-startup.md). It accepts no
caller-selected descriptors, paths, successful admission object or callback.
This source is unbuilt, unexecuted and unprovisioned.

The five fixed descriptors are root public key `198`, signed launch bootstrap
`199`, raw 32-byte delivery AES key `200`, per-delivery outcome directory `201`
and listener `202`. Public originals and the private key must be immutable
root-owned sealed memfds; their actual sizes are charged before native reads.
The directory must match the root-admitted device/inode/UID/GID and private
mode `0700`. It is already open: intake creates no directory and selects no
global journal path.

The listener is only validated and preserved. It must be a nonblocking,
listening Unix stream at
`/run/serverware/oidc-session-activation-token-release/release.sock`, with
root-pinned socket/path identities and a `65502:65532`, mode `0660` pathname
under protected root-owned ancestors. Intake performs no accept, peer/body
processing, transport exchange or token opening.

Actual [root launch admission](oidc-session-activation-release-bootstrap.md)
precedes reading delivery-key bytes. The fixed descriptor, directory and
listener joins are completed under the supplied processing allowance; the key
is then joined to the genuinely admitted original custody. Live release and
recovery remain root-selected profiles, not environment or request switches.
No historical/bundle AES key, signer, TLS credential, SQL connection or state
client is admitted by this resource profile.

The process starts with real/effective/saved root UID/GID and the exact eight
source environment entries. Any socket-activation environment must be consumed
by a future launcher before this call. All five descriptors become
close-on-exec, supplemental groups are cleared and UID/GID are permanently
dropped to `65502` in the same PID. The inherited no-new-privileges condition
and absence of effective/permitted/inheritable/ambient capabilities are checked;
intake does not install that launch prerequisite. There is no post-drop exec,
new interpreter, fresh ledger or renewed clock bracket.

The immutable configuration exposes `root_public_key`, `bootstrap_bytes`,
`delivery_key`, `directory_fd`, `listener_fd`, `live_window`, `deadline_ns` and
the exact `work` object. `_snapshot_configuration()` returns the same sealed
configuration identity; no admitted bootstrap material is returned as proof.
Startup genuinely verifies the original bootstrap and constructs the actual
store and fixed live-release or recovery owner.

`_check_on_work(*, work)` requires that identical work object and returns the
current epoch only after real launch/time, process/environment and all five
descriptor checks. The original processing pair is retained and only narrowed
by actual bootstrap admission. Full exact-inventory checks occur during
intake; afterward startup must account for its genuine journal duplicate while
this handle checks its five original descriptors. Directory timestamps and
size are not frozen across legitimate publication; the actual store separately
owns complete record/inventory continuity.

The actual startup owns the resource handle after transfer. On failure or
`close()`, intake closes only still-identical owned descriptors, never a
replacement occupying the same number. A changed or unidentifiable descriptor
is not retried or guessed. Explicit `close()` raises if identity or successful
closure cannot be established for every owned descriptor. That failure is
sticky: another `close()` reports it without retrying. Failure-path cleanup
remains best effort and preserves the original exception, while recording any
uncertain cleanup for the startup's final cleanup check.
Store-owned duplicates are closed by their own
owners before resource cleanup; retained outcome bytes are not removed.
This is resource intake, not a service, listener worker, response protocol,
public handoff or production-verification claim.
