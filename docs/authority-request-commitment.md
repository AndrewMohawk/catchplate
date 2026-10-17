# Registry-free request commitments

Status: source implementation and coverage transition, unbuilt and unexecuted.
This is not a startup repair, planner admission or a new authorization protocol.

## Import boundary

The inactive revocation semantic verifier needs actual request commitment and
operation-ID computation, not planner activation. Importing those workers from
`authority_planner` also imports `authority_transition_registry`, whose closure
guard correctly rejects the four missing WebAuthn kernels. That coupling made
the standalone verifier and its isolated fixtures unreachable.

The shared [`authority_request_commitment`](../catchplate/authority_request_commitment.py)
module owns the existing request,
business-intent, authorization-argument, canonicalization and framing bodies.
The planner re-exports those names and keeps its public `typed_request_digest`
registration check before the shared computation. The semantic verifier uses
the shared worker directly. There is one commitment recipe, not an alternate
serializer or caller-supplied successful-result shortcut.

Preserve the existing domains, ASCII canonical bytes, operation-ID UTF-8 frames,
authentication-field exclusions, challenge semantics, mapping behavior of the
unmeasured worker and exact-type metered boundary. Work preparation, ordering,
remaining-budget accounting and errors stay with the actual bodies. The legacy
`AuthorityPlannerError` name remains available from the planner as the shared
exception class; its definition moves to the registry-free module.

Returning a digest cannot authorize a request. The public registry check,
kernel closure, receipt verification, capability admission and independent
before-root/time requirements remain separate and unchanged. No operation is
registered, removed, disabled or assigned a substitute implementation here.

## Reviewed coverage transition

All nine existing `TypedRequestWorkTests` method IDs and all twenty existing
semantic fixture method IDs are retained. Their independent arithmetic, real
cryptographic work, genuine proof/kernel/capacity calls, ownership controls and
negative cases remain. Only their import/call ownership moves to the actual
shared component.

The old candidate-specific assertions combined two incompatible conditions:
revocation absent from the registry, and the closed registry successfully
imported so its public planner function could be called. The real registry
requires every declared operation except its explicit exclusions; it raises
before exporting an importable module while that candidate kernel is absent.
Those assertions therefore supplied no reachable callable-planner coverage.

The exact transition is:

| Existing location | Preserved or replacement coverage |
| --- | --- |
| Typed-work actual-digest method | Keeps its three original source-declared operation cases and independent measured/unmeasured commitments. Its registered-operation public calls are retained in the startup-dependent suite. |
| Typed-work public mapping method | Keeps the unmeasured mapping and metered exact-type boundaries. Its public planner mapping assertion is retained in the startup-dependent suite. |
| Typed-work registry-gate method | Keeps genuine private commitment, then requires real, unmocked import denial with the exact current missing-kernel diagnostic. |
| Semantic observation method | Keeps real semantics, detached observations and rejection of result objects as input; replaces unreachable candidate exports with actual import-denial evidence. |
| Startup-dependent integration suite | Adds actual registered-operation public calls, public mapping compatibility and callable rejection of the intentionally disabled `jit.consume` operation. |

Four added methods in `TypedRequestPlannerIntegrationTests` also retain
operation-ID comparisons and check shared callable/exception identity and the
original raw encoder errors. The startup suite retains its original 26 methods;
it now declares 30, without a new suite, timeout change or coverage exclusion.

Import denial is **not** evidence that a callable public facade accepted or
rejected a request. Source inspection supplements but does not replace runtime
coverage. The startup-dependent assertions are neither skipped nor marked as
expected failures: that suite still cannot pass until the real registry and
startup prerequisites are implemented. No mock registry or placeholder kernel
is allowed to make either lane collect or pass.

The current missing-four-kernel diagnostic is an explicit source-era expectation,
not a permanent product requirement. When the real kernels and admission paths
are completed, update those diagnostic expectations through a reviewed coverage
transition while retaining the now-reachable public integration assertions.

## Verification still required

Source review cannot prove imports, exception compatibility, hash-count parity
or test success. The prepared verification phase must run both standalone and
full-startup coverage against the same frozen source and dependencies. All
original immutable snapshot, sealed launcher/controller and no-build execution
requirements remain mandatory. Production signing, Nitro/KMS and independent
witness deployment remain outside this component's authority.
