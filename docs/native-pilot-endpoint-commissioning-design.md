# Endpoint commissioning: two unresolved admission joins

The endpoint-input and first-three-delivery composers are held, unadmitted
source, preserved outside the canonical checkout. They do not extend supervisor coverage from three to seven
jobs. Full-run coverage still refuses startup. These are concrete source
design blockers, not missing operator credentials or permission to fill in
predicted values. No signing, build, test or live commissioning established
these findings; they follow from the current consumer/producer joins below.

The local engineering draft is retained under the user's
`codex-offload/serverware/engineering-drafts/endpoint-commissioning-d235e576/`
directory: the proposed tracked-file patch, three new Python modules and two
guides. The active checkout keeps the original v1 policy and native contracts;
the draft is not installed, admitted or an immutable release artifact.

## 1. A pre-start policy cannot pin the future measured configuration

The proposed endpoint policy requires a complete `production` original,
`proofScopeOriginal` and nonempty scope-bound retrieval manifest before the
coordinator is started. Its validator equates the proof scope's production
binding with the independently supplied `expectedConfigurationBindingSha256`.
That proposed v2 admission is preserved in the draft, not enabled in the active
[`SupervisorPolicy`](../serverware/native_pilot_supervisor_policy.py).

The real Rust `ConfigurationBinding` includes
`kernelRetainedDriverIdentitySha256`, alongside the assignment, instance/boot,
closure, worker, backend, operation-coverage and budget fields. The canonical
hash therefore depends on the actual newly measured driver identity, including
its process/start/PIDFD/cgroup commitments, not just independently chosen cold
configuration. See [the binding fields](../data-plane/decision-gate-rs/src/policy_shadow.rs#L7359)
and [the exact hash and proof-scope construction](../data-plane/decision-gate-rs/src/policy_shadow.rs#L7423).
The receiving factory reconstructs this hash with the actual retained driver
and requires equality with the supplied expected value; see
[the native factory](../data-plane/decision-gate-rs/src/policy_custody/native_remote_factory.rs#L88).

This is not solved by approving a placeholder or choosing an invocation ID in
advance. The process-specific inputs do not exist before the new attempt.
Retrieval artifacts also bind the exact scope into object contents, locators
and proof hashes, and require a nonempty manifest; see
[object construction](../serverware/native_shadow_retrieval_artifacts.py#L59)
and [manifest construction](../serverware/native_shadow_retrieval_artifacts.py#L86).
An old object directory cannot simply be relabelled with a newly derived scope.

The bounded next design is an explicit independently authorized derivation
profile, not a generic template: retain the approved assignment, trust,
static production settings, source-fixed hash recipe, original window and
image/closure inputs; then derive only the measured configuration binding and
scope after the real process owner supplies its authenticated observation.
The complete derived input must remain bound to that exact request and prior
verified originals. The native receiver must independently recompute the same
binding from its live owner. Any required scope-bound retrieval originals and
fs-verity files must be genuinely supplied/provisioned and checked after the
scope is known, within the unchanged original window. Missing originals or
insufficient remaining time must reject, not create receipts, accept an empty
manifest, renew the window, or reuse a stale driver identity.

## 2. One assignment closure hash cannot identify every role's closure

The endpoint v1 manifest hash includes the runtime configuration hash. The
native admission requires the guest runtime hash to match that manifest, then
requires the assignment's single `executionClosureManifestSha256` to equal
the same manifest. See [manifest hashing](../data-plane/decision-gate-rs/src/policy_custody/native_closure.rs#L28)
and [assignment/guest equality](../data-plane/decision-gate-rs/src/policy_custody/native_closure.rs#L87).

Distinct `nativePilotEndpointRuntime/v1` role markers have distinct bytes and
runtime hashes, hence distinct endpoint manifest commitments. The current
Retrieval and Persistence consumers share one proof scope, but each requires
its assignment and actual local closure to match that scope. See
[the retained scope checks](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/retrieval_scope.rs#L26).
Different per-endpoint assignments do not solve this join: the scope also binds
the exact assignment payload hash.

A common role-agnostic marker with identical bytes across all ten endpoints
could remove the endpoint-to-endpoint runtime difference **only if all other
manifest inputs also match**. It would need explicit source-selected consumer
semantics; it is not an invitation to ignore role checks. It still does not
solve the bridge join. The bridge uses manifest v2 and a different profile/hash
domain with its approved bootstrap runtime, whereas endpoint manifests use v1.
The bridge v2 manifest itself can be approved from static image, bootstrap
runtime, seccomp and provenance inputs; future process IDs are not its problem.
See [the two native manifest domains](../data-plane/decision-gate-rs/src/policy_custody/native_closure.rs#L30)
and [the bridge producer's static associations](../serverware/native_pilot_closure_authority.py#L137).

The bounded next design requires an independently authorized closure-set root
with exact per-role/per-guest manifest membership. A versioned assignment and
proof-scope contract must distinguish the common production closure-set
commitment from each actual guest's measured leaf manifest. Each native guest
must still verify its own image, runtime, seccomp, provenance, guest-bound
authorization and membership in the approved set; the bridge's receiving
factory must verify the same common root and its own v2 membership. This is a
new explicit admission contract requiring matching producer and consumer work,
not replacement of the existing equality checks with an unchecked lookup.

## Preserved limits and decision boundary

Neither proposal is implemented or independently approved by this document.
The exact old profiles, original expiry/currentness checks, nonempty retrieval
requirements and real-FD/process ownership remain unchanged. No zero IDs,
predicted hashes, fabricated history, locally self-approved snapshot, automatic
retry or deadline extension is a valid commissioning input. The existing
three-job coverage and full-workflow refusal must remain explicit until both
joins have coherent, independently authorized producers and native consumers.
