# Current-root state service startup

Source `.142` adds a dedicated **trusted-host-local** cold lifecycle for the
current-root decision service. This is source-only: unbuilt and unexecuted, with
unrendered, uninstalled service templates. It is not production approval,
native measurement, a TEE/HSM result or an independent rollback witness.

The [explicit v2 finalization-reserve profile](current-root-finalization-peer.md)
adds a separately root-admitted peer and signed-operation restriction. The v1
profile described below remains unchanged; v2 is not enabled by a socket ACL
or environment setting.

## Separate enrollment and startup authority

The existing [current-root enrollment](authority-current-root-decisions.md)
independently fixes the database, generation, complete initial vector and
separate computation, completion and state signing keys. A dedicated root-signed
startup bootstrap carries the **original enrollment bytes**, an independently
current exact sequence/head checkpoint and the fixed launch contract. The
bootstrap provider must independently possess that latest checkpoint; it cannot
derive authority from the journal it is about to admit, unsigned `inspect()`
output, an empty directory or a previously valid signed prefix.

The [bootstrap codec](../serverware/current_root_state_bootstrap.py) uses
`serverware.signedCurrentRootStateBootstrap/v1`, payload
`serverware.currentRootStateBootstrap/v1` and launch
`serverware.currentRootStateLaunch/v1`. Original enrollment is retained as
canonical base64url with exact byte count, raw SHA-256 and its distinct framed
enrollment identity. The checkpoint cannot exceed enrolled journal capacity.
The provisioner-only `_produce_on_work` takes the independently supplied
checkpoint explicitly; it has no journal reader or latest-state lookup.

The independently delivered root public key authenticates the bootstrap before
signed directory, listener or checkpoint values are used. Actual enrollment
admission and state-key pairing remain mandatory. Runtime-closure and measurement
identities in the trusted-host-local launch contract are root assertions, not
new native measurements or proof of hardware isolation. The signed `trustMode`
is exactly `trusted-host-local`; `hardwareBacked`, `nativeStageZero`,
`hsmBackedKeys`, `teeVerified` and `externalWitnessVerified` must all be false.

The original launch interval is at most 300 seconds. Cold recovery, idle
acceptance and request handling must remain within it. Startup retains that
original epoch/monotonic projection; each service request can only shorten its
deadline using the inherited launch deadline and configured integer request
timeout of 1–30 seconds.
Neither a new connection, restart nor replay renews the launch. A timeout after
durable publication can leave an accepted decision whose response was not seen.

## Fixed descriptors and Unix identities

The [root delivery entrypoint](../serverware/current_root_state_entrypoint.py)
starts with only systemd's activated stream FD `3` above stdio, named
`serverware-current-root-state`, with the actual current `LISTEN_PID` and exactly
one listener. The final original inherited inventory is exactly:

| FD | Retained material | Fixed source or endpoint |
| --- | --- | --- |
| 198 | Root public key, sealed, at most 16 KiB | `/run/serverware/current-root-trust/root-public-key.pem` |
| 199 | Original signed bootstrap, sealed, at most 256 KiB | `/run/serverware/current-root-trust/bootstrap.json` |
| 200 | Nonblocking activated Unix stream listener | `/run/serverware/current-root/state.sock` |
| 201 | Dedicated state private key, sealed, at most 4096 bytes | `/run/secrets/serverware-current-root-state-signing-key` |
| 202 | Existing private journal directory | `/var/lib/serverware/current-root-state` |

Root delivery seals the original root/bootstrap/key bytes, reserves only free
destination slots and never overwrites another inherited descriptor. It checks
stable protected sources and their parent paths without following symlinks;
unknown inherited descriptors fail closed. The original private key is root-owned,
single-link, mode `0400`. The directory is already provisioned
as mode `0700`, UID/GID `65516:65516`, with its independently signed device/inode.
Delivery does not create a journal, key, account, socket or checkpoint, repair
permissions, or choose a replacement descriptor.

Delivery drops supplementary groups and root IDs/capabilities. The state process
runs as UID/GID `65516:65516`; its socket is `65516:65516`, mode `0660`.
Reserve callers use primary
UID/GID `65514:65514`; completion and lookup callers use `65515:65515`. Those
caller services separately require externally provisioned supplementary socket
group `65516` to reach the protected socket. Group membership permits pathname
access only: serving still checks actual `SO_PEERCRED` before request bytes and
restricts each transport purpose to its configured peer.

The signed listener descriptor identity and socket pathname identity are
different objects: the inherited socket FD has its own sockfs device/inode,
while the filesystem pathname has separate device/inode and ownership/mode.
Both bindings are checked independently; one must not be substituted for the
other. The listener's retained nonblocking state is not changed by cold startup.

The rebuilt environment exposes
`SERVERWARE_CURRENT_ROOT_STATE_ROOT_PUBLIC_KEY_FD=198` and
`SERVERWARE_CURRENT_ROOT_STATE_BOOTSTRAP_FD=199`, process mode
`policy-authority-current-root-state`, and fixed interpreter settings. There is
no ambient root/key path, DSN or generic-role fallback. The isolated launcher
`/runtime/authority-bootstrap/current_root_state_launcher.py` accepts only
`--root-delivery` and `--run`, and supplies only fixed `/vendor` and `/app`
application/dependency paths to `/runtime/python/bin/python3 -I`.

## Actual recovery and lifecycle

[Cold startup](../serverware/current_root_state_startup.py) exposes
`initialize_from_environment()`, `require_started()` and `close()`; the admitted
singleton supplies `serve_once()`. There is no lazy or replacement admission.
It verifies the bootstrap again and pairs the actual unencrypted PKCS8 Ed25519
state key before publishing the owner. Startup constructs a fresh, unrecovered
[`CurrentRootJournal`](../serverware/authority_current_root_journal.py) over the
borrowed directory FD and its exact identity. The journal owns an independent
open-file description and exclusive nonblocking lease, not the borrowed FD.
Its configured capacity is 2–1,024 records of at most 1 MiB each; unknown files,
noncontiguous sequences or unstable immutable records deny admission.

The actual
[`CurrentRootDecisionOwner`](../serverware/authority_current_root_decisions.py)
takes ownership of that journal, original enrollment, independent root key,
actual state private key and exact expected sequence/head. It verifies the
enrollment/key pair, requires journal capacity to equal enrollment capacity,
reconstructs state from every genuine original request/receipt, and only then
requires **equality** with the independent checkpoint. It does not accept a
minimum sequence. Sequence zero explicitly means the enrolled initial vector
and framed original enrollment identity, not an inferred empty-store genesis.

The existing serving core invokes the actual owner for reserve, completion and
signed lookup. A decision response follows durable append; lookup is read-only.
Pending state survives control expiry. Shutdown releases only owned listener
handles and the owner/journal's independent handles, not borrowed delivery
descriptors or published records. There is no automatic journal reset, deletion,
generation rollover, replacement decision or SQL retry.

## Deployment and remaining boundaries

The [socket template](../ops/systemd/serverware-current-root-state.socket) and
[service template](../ops/systemd/serverware-current-root-state.service.in) are
deployment inputs, not installed services. The service requires an approved
complete image export at `@CURRENT_ROOT_RELEASE_ROOT@`, not a checkout.
The production Dockerfile now packages the fixed launcher and both templates
from the verified source stage; that source edit has not been built or executed.
`@CURRENT_ROOT_TRUST_DIR@`, `@CURRENT_ROOT_KEY_FILE@` and
`@CURRENT_ROOT_JOURNAL_DIR@` bind the separately provisioned sources to the fixed
paths above. The activated socket directory is also bound into that root;
`MountAPIVFS=yes` supplies API filesystems for descriptor checks and
`NonBlocking=yes` preserves the listener contract. Socket recreation changes its
signed identities and requires newly admitted launch material.

`Type=exec` is not admitted readiness. `Restart=no` and the one-start limit are
operational backoff, not durable anti-replay authority. Manually restarting or
clearing a manager counter cannot renew the original launch or replace the
required current checkpoint. The [runner](../serverware/current_root_state_runner.py)
performs one cold admission and serial serving; lifecycle failure is terminal.
An independent provisioner must supply protected original bootstrap/key/root
material, stable journal storage, the exact latest checkpoint, accounts/groups
and a complete approved immutable runtime/dependency closure. No source helper
can enroll itself or manufacture checkpoint freshness.

This lifecycle does not provision computation/completion callers, authenticate
public enrollment, activate browser finalization, authorize database mutations,
or prove protected storage against a hostile host. Existing
[successor execution](authority-successor-execution.md),
[committed-state completion](authority-current-root-completion.md) and
[delivery/reconciliation](authority-current-root-delivery.md) retain their
separate original-authorization, checkpoint and uncertainty boundaries.
Production deployment and frozen verification remain outstanding.
