# Operational input composition

The `.418` candidate compiler covers the existing **176 operational jobs** after
the [cold-start compiler](native-pilot-genesis-inputs.md). It fills the existing
input formats from literal earlier results and actual supervisor observations.
It does not create approvals, sign inputs, reconstruct process owners, install
public originals or replace the native adoption validator.

## Caller contract

`catchplate.native_pilot_adopted_inputs.compose` accepts:

- The pending request returned by the actual adopted supervisor.
- Independently selected policy and Recipe3 originals and their expected hashes.
- A closed selection fragment for the requested job; `selection_fields(name)`
  lists its exact fields. Decisions, image pins, verifier settings, credentials,
  encrypted transport and absolute validity intervals remain independent inputs.
- The completed operational prefix: `{job: {input: bytes, result: dict}}`.
- The previous snapshot: `{phase: supervisor_observation_original_bytes}`.
- The complete retained cold66 prefix, with literal input and result bytes.
- Explicit boot identity, BOOTTIME and UNIX clock samples.

The result contains `inputOriginal`, `inputSha256`, `deadline`, `epochLimit` and
the updated `observations` snapshot. Persist that snapshot and the separately
approved input/result pair. Repetition does not grant retry or signing authority.
Caps intersect original policy/intake/request and current producer limits; the
live executor's potentially narrower retained limits remain authoritative.

The compiler checks fixed job order, exact previous-result association, public
result validation and unchanged observation bytes within a phase. It recomputes
the measured configuration from the pinned recipe and observed driver identity.
It does not accept future observations or renew original windows.

## Important handoffs

Adoption uses the actual cold runtime, native/retrieval grants, completed bundle
and acquired core observation. Operational target histories and their keys come
from the installed ordinary-runtime inputs. Current authorities come from the
selected signed assignment and trust. The native validator must still admit
the complete candidate before the independently operated authority signs it.

Endpoint pins preserve the common peer identity in all five ordinary runtimes.
The ordinary installation selection supplies `runtimePolicy` and three static
`peerExpectations`: cgroup-path, security-label and configuration-generation
hashes. Actual driver PID/start, credentials, executable and cgroup mount/inode
come from the authenticated bootstrap/cohort observations. No future PID or
complete peer original must be predicted, and static expectations are not
misrepresented as observed facts.
The `.419` [protected publication job](native-pilot-adopted-endpoint-publication.md)
publishes the peer, measured proof scope, assignment and exact fresh retrieval
manifest only after independent approval. The empty object directory remains
an explicit provisioning prerequisite. Compiler selections must match the fixed
destinations and generated manifest pin. Computing their hashes is not
publication or installation evidence.

Cohort release requires explicit image pins matched to prior closure manifests.
Constructed-driver admission requires the existing independent continuation
policy; launch, scope, verifier inputs and exported originals are joined to
their real predecessors. Shutdown remains stop-only unless an explicit
interactive policy and matching action authorize a bounded interval.

## Integration corrections and verification boundary

The batch also connects the explicit adopted profiles through generation-scope
derivation, persistence material projection, five-member publication inputs,
Runtime14/Launch10 scope and constructed-driver validation, Closure5 admission,
and the existing phase-two public publisher. Legacy defaults stay closed.

Focused verification results are recorded in [production progress](production-status.md).
Frozen `3811b8e8` ran 111 controls in 65.704 seconds. A missing explicit adopted
identity selector caused nine error entries. Corrected `6b6963d0` passes all 13
controls in the affected suite in 8.763 seconds; 99 unaffected controls passed
earlier and were not rerun. This is 112 distinct controls across two snapshots,
not a full corrected-tree run. Grammar/both Make inventories cover 21 changed
Python files, and all eight new modules import.
The authored controls include real deterministic test signatures and explicit
synthetic observations. They do **not** constitute a complete positive 176-job
ceremony: full native adoption, operational grants, bridge business state and
constructed-driver attestation/census still need connected runtime evidence.

An independently operated decision service, compatible approved packages,
protected deployment and an application credential-replacement demonstration
remain required. Source **36/46** and production acceptance **0/6** are unchanged.
