# Independent commissioning approval provider

This is the fixed provider for the [cold-to-adopted lifecycle](native-pilot-lifecycle.md),
not an application credential broker or an independently deployed service by itself.
Its executable caller is implemented; a protected installation and complete live
commissioning/application run remain required before a pilot can be offered.

## What runs

The supervisor entrypoint has an explicit `approval-provider` mode. It runs only
`run_native_pilot_approval_provider.py`, inside the admitted supervisor package.
There are no arbitrary commands, signing-key arguments, network listeners or
child launchers in this provider.

The process consumes five protected public originals, each with an independently
supplied SHA-256 pin, followed by two already-connected Unix seqpacket sockets.
The exact argument order is:

```text
approval-provider
  --policy-fd FD --policy-sha256 sha256:HEX
  --supervisor-inventory-fd FD --supervisor-inventory-sha256 sha256:HEX
  --recipe-fd FD --recipe-sha256 sha256:HEX
  --conductor-inventory-fd FD --conductor-inventory-sha256 sha256:HEX
  --authority-inventory-fd FD --authority-inventory-sha256 sha256:HEX
  --approval-socket-fd FD
  --current-head-socket-fd FD
```

This is an argument contract, not a copy-paste launch recipe: the operator must
first provision the real originals, matching installed runtimes and authenticated
connected peers. All seven descriptors must be distinct. Public inputs require
the existing root-owned, protected-file or sealed-memory-file admission. The
policy names both expected peer PID/UID/GID/start identities; actual kernel peer
credentials, PIDFDs, per-message credentials and process starts must match.

The [three-process startup launcher](native-pilot-startup.md) now supplies that
connection path: actual children create the sockets before independently
authorized late files bind their observed identities. It resumes this same
provider CLI in the observed process; it does not generate its delegation policy
or the independent fresh-head decisions.

## Where permission comes from

The independently provisioned `nativePilotApprovalDelegationPolicy/v1` pins the
source, catalogue, inventories, measured recipe, listener configuration, adopted
key bindings, exact job selections and original validity windows. Its closed
rules permit only the fixed candidate derivations. A successful compiler or
matching digest is not itself permission to execute.

The provider retains the actual protected policy and rechecks it before and
after composition. Only then does it serialize the existing approval format and
seal the outgoing public originals. It does not possess the keys used by the
separate commissioning authorities. Their actual signature/key admission remains
with the existing producers and consumers.

The rendezvous rule explicitly delegates selection of the observed receiver to
the pinned lifecycle peer for this invocation. The actual lifecycle owns receiver
lineage checks. Ordinary driver identity derives from authenticated observations;
cgroup-path, security-label and configuration-generation hashes remain explicit
independent expectations, still matched by the downstream native runtime.
Interactive stop derives only the observed origin-handoff hash; its stop time
and expiry are fixed by the independently selected bootstrap policy.

Eight current-head jobs are **not delegated**. For each, the provider calls
[`CandidateTranscript.current_head_evidence`](../serverware/native_pilot_approval_transcript.py)
over accepted predecessors and the actual current request's result/observation
delta. It returns the existing `nativePilotCurrentHeadObservedRequest/v1`, with
literal runtime/history/request sources, without advancing the transcript or
supplying currentness. The provider explicitly selects the `evidence=True`
current-head transport and sends that evidence with the actual pending request
to the separately pinned decision peer; the old mode is not silently upgraded.

That peer must return complete protected Input/v3 and Approval/v2 originals.
The provider validates their exact request/currentness associations and requires
the input to equal the candidate derived from its retained transcript. It
forwards the original pair unchanged and never manufactures currentness from
signed history. Waiting is bounded by the inner trust request as well as the
outer job and both original clocks.

## Independent decision-service workflow

The selected packaged receiver is
[`native_pilot_current_head_decision_service`](../serverware/native_pilot_current_head_decision_service.py).
Its supervisor entrypoint argument contract is:

```text
current-head-decision-service
  --supervisor-inventory-fd FD --supervisor-inventory-sha256 sha256:HEX
  --configuration-fd FD --configuration-sha256 sha256:HEX
  --approval-socket-fd FD
```

All three descriptors must be distinct. The service admits the actual installed
supervisor inventory, retains the protected configuration, and authenticates the
connected provider through kernel credentials, PIDFD and process-start identity.
Its closed `nativePilotCurrentHeadDecisionService/v1` configuration pins the
inventory SHA, actual provider PID/UID/GID/start, directory device/inode, boot and
time namespace, and original BOOTTIME and UNIX validity intervals.

Before starting, the operator must provision the empty fixed directory
`/etc/serverware/native-pilot-current-head-decisions`, owned by root:root with
mode `0700`, and independently approve its identity and configuration pin.
The service does not create or clear this directory. The independent backend
and its fresh-state policy must already be ready before commissioning starts:
the signed driver window allows at most **30 seconds for the entire startup**,
not 30 seconds for each decision. This is an automation handoff, not a manual
file-editing workflow during the run.

For each of the fixed eight jobs, in source-defined order:

1. The service exclusively creates `<job>.request.json` and
   `<job>.evidence.json` as root:root `0400` files. These contain the literal
   AuthorityJobRequest/v2 from `pending.requestOriginal` (not the transport
   envelope) and transcript-derived public originals, respectively.
2. The independently operated backend reads the complete originals, establishes
   fresh state under its own approved policy, and supplies a complete Input/v3
   plus its independent Approval/v2. It atomically publishes
   `<job>.input.json` first and `<job>.approval.json` last, without replacing
   existing paths. Both must be root:root `0400`, regular, single-link files;
   stage temporary files outside the watched directory. Extra or future-job
   files are refused.
3. The service validates the complete pair, including literal evidence/input
   joins and the request's original limits, then sends the retained descriptors
   to the provider. The provider still performs its own full candidate equality
   and approval checks. A descriptor receipt is not successful job execution.

There is no fresh-head backend, signing engine, generated currentness or approval
in this service. Same-host root permissions do not establish independent
organizational custody. No restart, overwrite, deadline extension or automatic
cleanup repairs a failed exchange; existing and partial files remain for
diagnosis, and uncertain resource cleanup remains explicit.

## Ordering and cleanup

The real runner handles all 244 exchanges: bootstrap, rendezvous, 66 cold jobs
and 176 adopted jobs. A retained candidate transcript consumes the actual next
request's prior result. It requires the separate cold and adopted completion
originals after exchanges 68 and 244, validates their associations, then explicitly
acknowledges them. Delivery receipts never substitute for execution results.

Final-action limits remain active through the completion receipt. The cold
completion's transport deadline does not replace the transferred core's later
operational lifetime. The final installed-runtime check must finish inside the
adopted final-action limits. There is no retry, reconnect or deadline renewal.

Actual descriptors and partial acquisitions remain reachable until known local
close. Unknown cleanup keeps the process and owner retained; it cannot emit a
successful exit. Successful public-transcript completion still reports
`pilotAcceptanceVerified=false` and `productionReleaseEligible=false`.

## Remaining deployment boundary

The earlier frozen `bb54b76a` passed 107 focused controls in ten suites, including
real local socket/PIDFD/descriptor exchanges with synthetic public payloads. Provider
invocation/serializer and source-order checks are not an executed protected
provider process. No complete valid cold66/adopted176 ceremony is claimed.

The `.422` evidence projection, explicitly selected transport and protected-file
receiver described above are implemented in source. Frozen `a6610852` passes
**130 controls in thirteen focused suites in 46.984 seconds**, with no failures,
errors, skips or reruns. Fourteen-file grammar/both Make inventories and ten
imports pass. Actual selected-mode local sockets carry synthetic evidence and
protected pairs; the receiver's profile, entrypoint and source-order checks do
not execute an installed protected filesystem service or a full commissioning
run. They replace the missing public-source handoff; they do not
implement the external fresh-head state backend or establish a deployed
independent decision service. Installed-package admission and live-pilot success
remain unverified.

The source does not provision independent policy/current-head operators, issue
their decisions, approve dependency publication, install compatible packages,
configure Nitro/KMS/signing/witness services, or demonstrate application traffic.
Those remain real deployment requirements, not values supplied by a test fixture.
See [production progress](production-status.md) for the frozen-source verification
record and the separate limited-pilot milestones.
