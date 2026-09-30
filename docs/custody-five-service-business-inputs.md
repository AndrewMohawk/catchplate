# Actual five-service business inputs

This generation-only software source creates the real resources consumed by
`GenerationInputs.prepare`, then retains them through the actual parked-child
release and cleanup. It does not produce service journal records, native
measurements, signatures, generation commits or readiness.

`BusinessResources.prepare(launcher)` requires the genuine `FiveServiceLaunch`
owner from the explicit C9 launch profile. The independently installed,
root-owned `0400`, single-link original
`/etc/serverware/custody-generation-business.json` binds the exact retained
launch configuration hash and original invocation. Its `clientConfiguration`
pins the actual independently provisioned production-bridge C9 cold
configuration. The intended bridge UID/GID controls socket DAC only; it is not
an observed final peer identity or an authority to skip the existing verifier.

The independently preprovisioned roots are root-owned `0711` directories:

| Root | Source-created children |
| --- | --- |
| `/run/serverware-custody-business` | Five fresh root-owned role directories, each containing one real listening `listener.sock` |
| `/var/lib/serverware/custody-business` | Five fresh root-owned role directories with the exact business state/journal directories below |

Both roots must initially be empty and are retained/locked. Existing files,
role directories, sockets, symlinks and unknown inventories refuse admission.
There is no repair, adoption, unlink, cleanup retry or implicitly authorized
restart. Storage must be ext4, XFS or Btrfs; tmpfs/overlay is not substituted for
the durable service store. Directory/file sync is a source operation, not a
power-loss or rollback-resistance claim.

The inventory is the actual `run_*_loaded` contract:

| Service | Business activation names |
| --- | --- |
| durable-recovery-store | listener, journal |
| cleanup-authorization-consumer | listener, state, journal |
| recovery-target-provider | listener, journal |
| current-signature-authority | listener |
| bounded-cleanup-helper | listener, journal |

Listeners are nonblocking AF_UNIX SOCK_SEQPACKET sockets with an actual
`listen(1)` call, bound at the source-fixed
`/run/serverware-custody-business/<role>/listener.sock`. Socket path ownership is
the actual configured service UID and the independently configured bridge GID,
mode `0660`; protected root-owned ancestors prevent replacement by either role.
The receiver's credentials+rights ancillary grammar is preserved. It still
obtains its real peer PIDFD separately through its existing `SO_PEERPIDFD` path.

State/journal directories are fresh empty `0700` directories owned by the actual
service C9 UID/GID. Their original directory FDs, exact mount/device/inode/owner
identities and preparation locks are retained. No fabricated genesis or empty
success record is written. Existing runtime seeds, current-head authorization,
cleanup genesis predecessor, full authority history and the actual service
journal constructors remain independently required and unchanged.

The connected operator call sequence is:

1. `launcher = FiveServiceLaunch.start()` obtains real parked process owners.
2. `resources = BusinessResources.prepare(launcher)` creates the closed resources.
3. `inputs = resources.generation_inputs()` passes the actual retained FDs into
   `GenerationInputs.prepare`, not a serialized descriptor assertion. The same
   input owner now also retains this resource owner. No second transfer exists.
4. Use `resources.runtime_inputs(role)` for the observed listener path and
   business directory identities, and `inputs.directory_identities(role)` for
   the complete identity set including the separately allocated generation
   journal. Independently authorize/pin the actual runtime, credentials and
   generation scope; complete the existing C9/grant signing and sealing sequence.
5. `launcher.release(inputs.transfer())` performs the one-shot actual child
   transfer. `inputs.close()` or `resources.close()` first stops/reaps those same
   children, then releases generation resources and finally these business
   listeners/directories/locks. Partial artifacts remain on disk for independent
   reconciliation. Calling only `launcher.close()` intentionally does not
   silently erase or release the other retained resource owners.

The actual launcher watchdog checks these retained namespace/socket/directory
originals throughout its original lifetime. Fresh directories must stay empty
until that same genuine input owner irreversibly starts release. Once released,
only the existing service journal/state owners interpret their contents. The
producer adds no deadline, health flag, storage-format compatibility or legacy
default selection.

## Precise remaining peer-admission join

The parked process observation binds the real child PID/start and intended
immutable executable. It does not observe the post-exec security label, final
cgroup membership or IMA evidence. Signed `expectedPeer` and
`EndpointProcessIdentity` originals still need their genuine independent
producers/admission. Neither this resource owner nor a supplied C9 client
configuration can manufacture those facts.

There is also a concrete execution-access seam in
`services/common.rs::AuthenticatedInheritedSeqpacket::from_inherited`: it calls
`open_process_executable(peer_credentials.pid)`, captures the cgroup and
`SO_PEERSEC`, and rechecks retained peer facts in `revalidate_peer`. The ordinary
entry has already permanently dropped capabilities when it reaches
`services/mod.rs::authenticated_capability`; the native bridge is an isolated,
different-UID, non-dumpable process. This batch does not provide a retained
privileged inspector for that software transport owner. A genuine
purpose-bound privileged-inspector join is required; relaxing the expected peer
checks, granting broad worker capabilities or projecting parked values into
final measurements is not a substitute.

Everything here is source-only. No sockets/directories were created by running
the project, no processes launched, and no build/test/runtime success is claimed.
Real provisioning, the peer-inspection join, native bridge/coordinator
certification and final connected-pilot acceptance remain separate work.
