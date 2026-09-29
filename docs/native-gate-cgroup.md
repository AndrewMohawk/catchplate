# Explicit native gate cgroup

Native startup v14 retains every v13 owner and requires the closed
`gateCgroup: {"apiVersion":"serverware.nativeGateCgroup/v1"}` profile.
The fixed image selector is `--gate-cgroup-v14`; its gate selector is
`--native-gate-cgroup-startup-v14`. The four original configuration/launch
artifact flags and optional public-identity flag are unchanged. Default startup
and v1–v13 pass `None` and do not acquire this new process-placement behavior.
This is separate from Setup, staging, target-dispatch and retirement grants.

The producer lives in `native_gate_cgroup` and accepts only the actual native
serving `Prepared` owner and its unchanged absolute BOOTTIME deadline. Its
configuration contains no path, PID, UID/GID, supplied measurement, writable
descriptor, deadline or generic control operation.

## Actual startup sequence

1. Before launching any guest role, prepare the real `/sys/fs/cgroup`
   hierarchy. Either admit its actual protected writable cgroup2 mount, or
   mount source-fixed cgroup2 on the genuine protected sysfs mountpoint with
   `nosuid,nodev,noexec`. Require one private hierarchy root exactly there;
   refuse child-bind roots, overmounts, shared propagation, duplicate cgroup2
   mounts and missing kernel/filesystem support. No placeholder file or
   successful-check DTO substitutes for the actual filesystem and mount IDs.
2. Create the fresh root-owned `serverware-native-gate` leaf. Refuse any
   preexisting leaf; do not adopt, chown, delegate, reset or reuse it. Retain
   actual root/leaf/control/namespace originals. The gate remains at the
   unified hierarchy root while the inspector, seven-role cohort, boot-key
   provisioner, explicitly selected [shadow worker](native-shadow-workers.md)
   and credential-broker child are created. StateCas can now open its genuine
   system-root cgroup observer during cohort startup.
3. After `PreparedBroker::open` and before `drop_permanently`, write only the
   actual gate PID once to the exact held leaf's `cgroup.procs`. Check the actual
   proc record, sole process membership, domain type and absence of descendants.
   An uncertain write does not authorize retry or move-back. Close the writable
   control descriptor before continuing; no cgroup write/kill FD is exported.
4. Bind the retained read-only owner to the same permanent serving identity and
   same `NativeRuntimeLifetimeV1`. This happens before response-v2 client
   initialization, long-lived native identity owners and serving threads.
   Runtime checks compare real path/descriptor mount identities, namespace
   originals, readonly control identities, exact proc bytes and sole gate
   membership. A failure poisons the owner and stops its original lifetime.

The inspector and all role/helper children must stay outside this leaf. If they
inherited it, their survival could keep the group populated after gate death,
preventing the state authority's existing death-and-empty observation.

## Independent process binding

The exact actual proc record is `b"0::/serverware-native-gate\n"`. Its cgroup ID
for `Reserve.owner_cgroup_id` is the concrete relative path
`serverware-native-gate`, not the SHA digest. The independently provisioned
response client assignment must separately pin `SHA256` of those complete raw
bytes, including LF. `native_gate_cgroup::proc_cgroup_sha256()` provides the
source-fixed data recipe, not an accepted measurement or assignment signature.

The existing inspector continues to measure the real same-guest gate through
socket credentials/PIDFDs and hashes its actual proc record. The separately
selected [native public staging](response-v2-native-public-staging.md) caller
reads its real PIDFD/start time/proc record; the router compares its
signature-bound owner with the actual inspector. Nested staging v3 requires
outer v14/v15 and this actual retained cgroup owner before serving. The
state authority's `LinuxCgroupV2Observer` resolves the relative ID under its
real `/sys/fs/cgroup`, checks the live PID/start time and reads actual
`cgroup.events`. Cgroup preparation does not manufacture Reserve originals,
assign native keys, admit a generation or waive any of those checks.

## Cleanup and evidence limits

A complete prepared owner may remove only its own unchanged, empty,
never-attached leaf during the original startup allowance. An incomplete
construction can leave a fresh tombstone; it is not adopted on another attempt.
The system hierarchy is not unmounted because actual guest observers may retain
it. Once gate attachment is attempted, no destructor moves the gate, removes the
leaf, kills its members or claims cleanup success. Read-only originals close on
drop; the leaf remains nonreusable until guest teardown. A live process cannot
truthfully report its own death or empty its group without breaking its original
owner. Earlier reclamation would require a separate genuine outer root reaper
after observed death/empty state; the current image entrypoint execs the gate
and provides no such reaper.

No supplementary groups, DAC capability, root-serving worker or new writable
control capability is retained. This batch establishes source connections only:
cgroup2 mount/kernel support, group behavior,
guest provisioning, build/dependency closure and end-to-end isolated credential
flows remain unexecuted and unverified. This does not close N06 or establish a
testable credential pilot.
