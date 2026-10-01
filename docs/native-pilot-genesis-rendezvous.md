# Observation-first cold rendezvous

The `.413` integration fixes a concrete startup dependency: the old listener
requested approval of the receiver PID before accepting its connection, while
the nested receiving conductor waited for the core before emitting an operator
request. Its actual PID was retained by its parent but not observable through
the independent approval interface. A predicted PID or reconstructed process
owner is not a solution.

## Selected executable flow

The new `--run-native-genesis-rendezvous` mode requires independently approved
`serverware.nativePilotGenesisListenerConfiguration/v2`. The three existing
cold modes retain their previous grammar. The new mode performs these steps
under the original BOOTTIME and UNIX deadlines:

1. The actual cold process binds the protected listener and emits its original
   sender observation. The independent operator uses it to start its intended
   receiving conductor with the separately approved intake configuration.
2. The listener accepts exactly one connection and retains the actual accepted
   socket and mandatory kernel `SO_PEERPIDFD`. It checks kernel peer credentials,
   process start identity, all UID/GID fields, boot/time namespace and socket
   identity. This is observation only: no `GenesisCoreChannel` is opened and
   no core or descriptor custody is transferred.
3. It emits a distinct rendezvous request containing the literal sender request,
   receiver observation and listener configuration, plus all three hashes. The
   independent operator must establish that this is the receiver it intended
   to launch. Root credentials alone are not approval of that provenance.
4. The operator supplies a complete independently approved Execution/v2 and
   rendezvous Approval/v1 bound to that exact transcript and observed receiver.
   The dedicated installer exclusively publishes the fixed input first and
   approval last. It neither chooses a peer nor generates approval.
5. The cold process verifies the protected originals and the still-live peer,
   then promotes the **same accepted socket** into the existing core channel.
   The existing 66 cold jobs and actual custody transfer follow. The adopted
   operational catalogue remains 176 jobs/123 key purposes.

A wrong first connection consumes the attempt; there is no re-accept, reconnect,
new deadline, inferred approval or replacement of a partial publication. The
two observations use distinct closed wire APIs, not an ordinary job or a fake
successful core result. Legacy request-0 approvals cannot approve this flow.

## Independent approved-pair installation

`scripts/install_native_pilot_genesis_rendezvous.py` requires three distinct
protected descriptor/SHA-256 pairs: `--request-fd/--request-sha256`,
`--input-fd/--input-sha256`, and `--approval-fd/--approval-sha256`.
Descriptors are independently provisioned originals, not secrets in command
arguments. The only destinations are:

- `/etc/serverware/native-genesis-authority/listener-execution.input.json`
- `/etc/serverware/native-genesis-authority/listener-execution.approval.json`

Both names must be absent and their protected parent must already exist. The
installer creates root-owned mode-0400 files, reads them back and retains actual
source/ancestor handles through cleanup. Its output is one newline-framed
RendezvousReply/v1. The independent caller must buffer that output until actual
successful exit/reap, and discard partial output or any nonzero outcome; a
reply is not proof that a still-running installer has cleaned up. Unknown
cleanup retains the process for investigation. Filesystem stalls require the
external watchdog; no timeout authorizes a retry or deletion.

This is an executable installer and listener dialogue, not a provisioned
independent operator, automated decision authority or complete lifecycle runner.

## Provisioning boundary

The [resource-root helper](native-pilot-resource-roots.md) now has an explicit
`--profile adopted-cold` selection. It includes the cold ordinary roots,
publication endpoint store/socket parent and mode-0700 handoff directory. Its
default operation remains inspection. Only explicit `--create` may create the
fixed missing directories; it never repairs, replaces or removes existing data
or creates credentials, configurations, sockets, journals or runtime authority.

The canonical host currently lacks the required installed runtime and protected
configuration roots. No privileged host directories or cloud resources were
created for this source batch. Actual installation, independently approved
inventories/inputs, key capabilities, fs-verity/cgroup prerequisites and the
independent operator remain deployment work.

## Verification

Source is assembled before one focused frozen check batch. New controls cover
the closed all-original transcript and installer association, genuine local
child/socket/PIDFD observation, and real FD-relative directory operations in a
redirected temporary tree. These do not prove protected full-listener execution,
fs-verity core transfer, signing, an operational cohort or production acceptance.

Current Python-only engineering exports are being prepared separately from
native compilation and runtime execution. Their unpublished dependency candidate
cannot become approved release material through a successful build. Full source
checkpoints remain **36/46**, independent production acceptance **0/6**.
