# Operational input composition

The `.418` candidate compiler covers the existing **176 operational jobs** after
the [cold-start compiler](native-pilot-genesis-inputs.md). It fills the existing
input formats from literal earlier results and actual supervisor observations.
It does not create approvals, sign inputs, reconstruct process owners, install
public originals or replace the native adoption validator.

## Caller contract

`serverware.native_pilot_adopted_inputs.compose` accepts:

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
The peer, measured proof scope, assignment and retrieval manifest must actually
be published and the object directory provisioned separately. Computing their
hashes is not publication or installation evidence.

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
The authored controls include real deterministic test signatures and explicit
synthetic observations. They do **not** constitute a complete positive 176-job
ceremony: full native adoption, operational grants, bridge business state and
constructed-driver attestation/census still need connected runtime evidence.

An independently operated decision service, compatible approved packages,
protected deployment and an application credential-replacement demonstration
remain required. Source **36/46** and production acceptance **0/6** are unchanged.
