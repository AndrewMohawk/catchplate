# Retained pilot resources

The native pilot now has concrete resource producers for its remaining fixed
server and bridge activations. These are source implementations, not evidence
that a pilot has run. The executable operator conductor, admitted artifacts and
independently operated authorities remain required.

## Allocation precedes approval

`NativePilotLaunch.prepare_resources()` retains the ordinary five, spool,
CommitRequest, GenerationInstall and bridge resource owners in the same process.
The genuine driver must already have received its authenticated gate binding.
The operator provides independently admitted Retrieval objects and the existing
Persistence/TrustedTime inputs separately. No producer invents a process
identity, credential, service grant or successful journal operation.

| Owner | Actual resources | Handoff |
| --- | --- | --- |
| `SpoolInputs.prepare_retrieval(...)` | Retrieval listener and immutable objects, plus duplicates of the same held spool store/lock | Verify independent four-FD C9, initialize spool using that original, then `take_for_cohort(launch_pin=...)` |
| `CommitRequestInputs` | Bound non-listening `commit-request-listener` | `transfer(launch_pin=...)` retains the actual purpose owner until release and cleanup |
| `GenerationInstallInputs` | Bound non-listening `shadow-generation-install-listener`, durable `generation-install-journal` | `initialize_journal(...)` binds supplied genesis/history to retained launch originals; `retain(launch_pin=...)` supplies the actual descriptors |
| `BridgeResources` | Listening production facade, fresh durable production journal, ten unconnected native client sockets and their real peer directories, held generation-origin channel | `OperationalInputs.prepare_pilot(...)` joins these to the real ordinary outgoing owner and independently signed C9 |

Retrieval's old two-FD path stays separate. The new four-FD path duplicates the
existing locked open-file description; it does not close and reopen the lock.
GenerationInstall creates a new empty lock file but does not take the Rust
writer's lock. It installs only supplied, exactly bound journal originals, not
synthetic generation history.

The cohort retains each purpose owner and checks it immediately before its
one-shot descriptor release. Its public `activation_originals(...)` returns the
same retained launch, authenticated C9 and pinned service-grant bytes. Pinning a
grant is not a substitute for the native service's final authority validation.

## Bridge ordering

1. Allocate the fixed facade and journal with `prepare_resources()`. Read
   `bridge_resources.journal_identity()` for the independent runtime producer.
2. Prepare all ten real endpoint paths and install the independently selected
   outgoing runtime. It must bind the actual peers, fixed facade path and
   observed journal identity.
3. Call `prepare_bridge_connections()`. Ordinary and native client sockets stay
   unconnected; only the actual final-role Rust process connects them.
4. Obtain `bridge_activation()`. This is the complete 41-entry inventory, sorted
   by name with actual C9 target descriptors starting at FD6. Have the independent
   authority sign the exact delivery and install its pinned launch originals.
5. Call `prepare_operational_inputs(launch_pin=..., production=...)`, obtain its
   exact `operation_original()` for the independent phase-two authority, then
   supply the genuine endpoint transfers and signed phase originals to
   `release(...)`.

The bridge inventory has 23 native/business resources and 18 ordinary outgoing
resources. It includes ten native socket/directory pairs, not server listener
substitutes or caller-supplied descriptor dictionaries.

The production facade differs from the ten native endpoint listeners: the
existing Rust admission requires it to be listening already and then re-listens
in the final role. Its ordinary ancillary grammar excludes `SCM_PIDFD`; native
proof sockets require it. Neither listening nor allocation grants permission to
dispatch a request.

## Fixed paths and cleanup

Use the [resource-root helper](native-pilot-resource-roots.md) to inspect or
explicitly create only missing protected parent directories. Resource owners
still create their own fresh children exclusively. The bridge uses
`/run/catchplate-native-pilot-bridge/listener.sock` and
`/var/lib/catchplate/native-pilot-bridge/production-journal`. GenerationInstall
uses `/run/catchplate-shadow-generation-install/listener.sock` and
`/var/lib/catchplate/native-shadow-generation-install/journal`.

An existing socket, non-empty preparation directory, changed original, expired
window or failed handoff is not repaired or adopted. Attempts remain consumed.
Partial owners are retained through actual process cleanup; no automatic unlink,
history rewrite, authority renewal or relaunch occurs. The bridge subtree retires
before shared endpoint resources can close. Unknown cleanup remains unknown.

These methods do not extend the original startup window for human approvals.
Independent services must supply the required originals within it. Resource
creation, filesystem checks and signed input reception do not establish Nitro
custody, generation installation, Setup completion or accepted proxy traffic.
