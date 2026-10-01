# Cold commissioning and protected installation

This connects the [cold launch assembly](native-pilot-genesis-assembly.md) and
[ordinary-service retirement](native-pilot-genesis-retirement.md) to a distinct
authority-coordinator execution mode. It is source integration, not a provisioned
approval service, running pilot, or operational adoption of a cold baseline.

## Execution order and ownership

The source-fixed catalogue has **64 cold jobs and 36 signing purposes**, separate
from the operational inventory. It admits complete independently approved inputs
in dependency order, never a caller-supplied list of jobs or commands.

1. Authenticate the static closure set, assignment and cold binding; sign and
   exclusively install the coordinator's precreation original.
2. Start the actual parked coordinator and prepare the actual two ordinary
   services and two native endpoints. Export their observed originals, not
   invented process, cgroup or descriptor identities.
3. Produce the ordinary initial histories, runtime and C9 deliveries. Admit
   the endpoint deliveries and initialize the retained Retrieval store.
4. Authenticate endpoint key/launch authorizations; produce Publication, then
   Retrieval grants, followed by ordinary grants. Install public components
   before their launch originals and release the actual retained services.
5. Observe the coordinator's real outgoing resources, admit separately approved
   peers, and compose its late Runtime/v2, C9, key and launch inputs. Transfer
   only the eight actual outgoing descriptors; its native result pair already
   belongs to the same parked controller.
6. Perform the signed release and consume the ordinary services' actual
   construction notices within the original startup interval. Only then request
   the lifetime-bounded completion approval and collect the controller's actual
   Bundle, EOF, successful exit and consuming reap. Retire the ordinary
   services/helpers and endpoints before reporting completed cold assembly.

One executor retains the actual owners across these steps. Observation JSON
and producer results cannot reconstruct an owner or substitute for descriptor
custody. All operations retain the original boot/time namespace, invocation,
startup and lifetime ceilings, plus applicable UNIX expiry bounds. Reading an
installed original later does not renew its authorization or its write window.
Byte bounds and before/after clock checks do not bound a stalled kernel
filesystem call. The independently operated supervisor must enforce the
original-window external watchdog; this tool does not create a replacement
timer or claim to verify that external deployment capability.

The assignment path now admits the complete public trust/closure/authority
input before reading private signing-key bytes. Each cold signing job likewise
checks its complete public input and exact predecessors before its selected
sealed key is read. These are Python/OpenSSL authorities, not demonstrated
hardware key custody.

## Separate invocation and approval exchange

The existing packaged authority entrypoint selects cold commissioning only with
`--run-native-genesis`. The operational `--run-native-pilot` command, hot job
protocol and operational inventories remain distinct.

Cold invocation requires:

- `--supervisor-inventory-fd` and `--supervisor-inventory-sha256`, selecting the
  independently approved **supervisor package**, which includes the authority
  scripts and cold producers;
- `--genesis-configuration-fd` and `--genesis-configuration-sha256`, selecting a
  protected `serverware.nativePilotGenesisExecution/v1` original containing
  exactly `apiVersion`, the original seven-field `window`, and
  `expiresAtUnixNanos`;
- `--authority-key PURPOSE=FD` for every source-selected cold key purpose.
  Shared key descriptors across deliberately selected purposes are permitted;
  a key cannot alias either public-input descriptor.

No example descriptor numbers here constitute a runnable provisioned setup.
The installed package is admitted before key access. The coordinator does not
derive an approved package inventory from whichever source happens to exist.

Each `serverware.nativePilotGenesisJobRequest/v1` has six fields:
`apiVersion`, `sequence`, `job`, `deadlineBoottimeNs`, `observation`, and
`previousResult`. Observations contain newly available literal public originals;
the previous result retains its exact bytes and SHA-256. The independent
supervisor must retain the earlier transcript and approve the complete next
input, including actual observations and preceding signatures.

Before replying, that supervisor must install these root-owned `0400` files:

```text
/etc/serverware/native-genesis-authority/<fixed-job>.input.json
/etc/serverware/native-genesis-authority/<fixed-job>.approval.json
```

The reply binds `sequence`, `job`, `requestSha256`, `inputSha256` and
`approvalSha256` under `serverware.nativePilotGenesisJobReply/v1`. The separate
approval original binds the request, input, sequence, job and original deadline
under `serverware.nativePilotGenesisJobApproval/v1`. Unknown jobs, supplied
paths, extra fields, queued future replies and changed originals are refused.
Every input is retained through actual cleanup. Frames and aggregate retained
bytes are bounded; a partial exchange authorizes no retry.

Root-owned pipes establish transport ownership, **not independently operated
approval provenance**. The independent cold supervisor's complete composition,
deployment policy and protected installation capability remain required. The
existing operational supervisor cannot be relabeled as that cold approver.

## Fixed public installation

All output names must be absent before a job writes. Creation is exclusive;
the installer writes, synchronizes, applies final ownership/mode, reopens and
checks exact bytes and identities. Components precede the launch file. Partial
outputs are retained on failure; there is no overwrite, adoption, rollback or
automatic removal path.

| Output | Final ownership |
| --- | --- |
| Parent precreation original | Root, `0400` |
| Ordinary runtime, C9 delivery and inspected launch | Root, `0400` |
| Ordinary initial history and peer-inspection credential originals | Actual signed service UID/GID, `0400` |
| Cold native runtime and other public launch components | Root, `0400` |
| Cold native encrypted credential inventory | Actual signed guest UID/GID, `0400` |

This corrects an incompatible ordinary Python check: native C9 opens the
runtime as root, while only credential originals are service-owned. The
installer neither writes plaintext private seeds nor changes that distinction.

Parent and ordinary files use fixed names directly under `/etc/serverware`.
Cold native components use fixed role/component names under
`/etc/serverware/native-pilot-inputs`. Configuration and trust remain separately
provisioned prerequisites. The native image's
`/etc/serverware/native-shadow-guest-launch.json` is a preexisting mount target,
**not** an output to create or replace. The actual native parent selects the
distinct host launch original through its retained release/FD4 path.

## Cleanup and remaining acceptance

Known process/helper retirement precedes release of keys, input descriptors,
installed-file owners and package custody. Unknown cleanup keeps the actual
owner reachable and does not retry, renew a deadline, or report success. A
successful cold terminal response exports the actual public Bundle and its
digest; pilot and production acceptance flags remain false.

Crucially, this standalone assembly endpoint is not the complete pilot handoff.
Operational adoption still needs a retained owner to acquire and transfer the
actual fs-verity cold-core descriptor **before endpoint cleanup**. Bundle JSON
cannot replace that capability. Adoption-validator/signing ownership,
operational recovery and authority transitions remain separate integration
work. Independent cold supervisor composition and provisioning, approved
dependency/release artifacts, Nitro/KMS/signing/witness services and connected
application allow/deny, lifecycle, provider and physical-hardware acceptance
also remain open.

## Verification

The assembled source is awaiting its focused post-freeze check batch. No
protected installation, private-key entrypoint, live owner, native service,
cloud resource or paid test has been run for this slice. Unchanged native code
and full runtime artifacts are not being rebuilt during wiring. Earlier
engineering artifacts do not contain these new modules.

Source checkpoints remain **36/46**, production acceptance **0/6**. Neither the
job count nor a successful public-input control is a product-readiness percentage.
