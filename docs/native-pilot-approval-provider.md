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

Eight current-head jobs are **not delegated**. For each, the provider forwards
the actual request and observation to the separately pinned decision peer. That
peer must return complete protected Input/v3 and Approval/v2 originals. The
provider validates the exact request/currentness associations and requires the
input to equal the candidate derived from its retained transcript. It forwards
the original pair unchanged and never manufactures currentness from signed
history. Waiting is bounded by the inner trust request as well as the outer job.

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

Frozen `bb54b76a` passes 107 focused controls in ten suites, including real local
socket/PIDFD/descriptor exchanges with synthetic public payloads. Provider
invocation/serializer and source-order checks are not an executed protected
provider process. No complete valid cold66/adopted176 ceremony is claimed.

The source does not provision independent policy/current-head operators, issue
their decisions, approve dependency publication, install compatible packages,
configure Nitro/KMS/signing/witness services, or demonstrate application traffic.
Those remain real deployment requirements, not values supplied by a test fixture.
See [production progress](production-status.md) for the frozen-source verification
record and the separate limited-pilot milestones.
