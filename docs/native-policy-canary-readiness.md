# Native readiness: complete consumer, explicit remaining producers

This source slice is a prerequisite, not a completed native readiness or
activation feature. It has not been built or runtime-verified. It preserves
the legacy Fleet-signed checkpoint/readiness/activation paths unchanged.

## Selection and actual caller

The fixed image selector `--canary-readiness-v21` selects
`--native-canary-readiness-startup-v21`, then the closed native startup/v21
decoder. It requires nativeCanaryDurableDelivery/v3 and the same real retained
owners as v20. Delivery/v3 and genuine terminal drain/finalization are the
paired finalization slice. v19 still requires delivery/v1; v20 requires v2.
Nothing infers a profile from an HTTP request.

The finalizer closes its own one-shot chain before calling
`native_canary_readiness::submit(state, &final_checkpoint_original, deadline)`
once, after definite final cumulative consumption and after releasing its
delivery/generation guards. The argument is the actual final checkpoint
original and the SAME remaining original deadline. There is no new timer,
poll, replay, retry, automatic promotion, or reconstruction of a lost result.

The real delivery owner retains the independently signed authority
configuration. Its new `native_readiness_policy()` accessor returns only
the exact admitted `policyCanaryNativeReadinessPolicy`. A separate explicit
policy/v1 authorizes derivation for exact canary/assignment pairs. The native
intake proof authenticates the request; it does not assert readiness.
The policy is compared byte-for-byte by the actual verifier and planner.
It is not selected by a browser, an environment boolean, or a supplied key.

## Complete protected derivation

One native `readiness` event carries identifiers, the exact final-checkpoint
SHA, and the exact independently admitted derivation policy. The unchanged
intake program acquires every table's complete before-root in the actual
transaction. All existing row, work, proof, original and response ceilings
remain unchanged. The nominal limits of 32 fleet members and 64 detailed
observations per member do not promise that their product fits: any actual
combined population, original size, signature work or query budget overflow
refuses before effects; no truncated inventory is accepted.

The kernel selects every exact signed assignment member and a unique
previously consumed final cumulative/v2 checkpoint for each. Its fixed
finalization verifier rechecks current assignment/load/publication authority,
the real closed admission/drained lifecycle census, complete signed ledger
originals, latest final heartbeat/checkpoint and the original seal deadline.
The verifier and planner separately re-admit the finalization proof's current
independent purpose. Readiness reconstructs heartbeat sequence/digest/time
continuity from protected full originals, including the original coverage
start and window end; it never accepts a maximum-gap assertion.

The fixed detailed-original owner must independently verify every real
per-ingress observation and its exact opening/terminal/request/response
preimages. Only then does the consumer project the full actual observation
semantics. It reuses the existing pure compiler/response/pilot validators,
recomputes the exhaustive 16-cell outcome matrix, all disposition totals,
drop/error/exclusion counts, exact semantic expansion counters and pilot
membership, assigned response-obligation coverage and the five latency
histograms. It applies every original per-member and fleet threshold,
including original duration, expansion read/write caps and p99 limits.
An absent response capture or unknown timing is not a comparable response.

The current compiler signature, assignment, actual finalized predecessor
publication and complete current revocation checkpoint are part of the
derived core. Readiness expiry is bounded by that original assignment,
compiler and independently authorized derivation policy; no receipt expiry
or native lifetime is extended. The output is retained atomically in the
existing intake journal with its exact request and signed controlled result.

## Required interfaces and unfinished continuation

The fixed paired finalization helper is
`authority_transition_policy_canary_native_finalization.validate_readiness_checkpoint(state, record)`.
It returns data exact6: context, assignment, load, publication, accounting,
seal. Its actual scope/proof checks, not the shape of the returned dictionary,
establish provenance.

The required detailed producer/receiver is
`authority_transition_policy_canary_native_detail.readiness_observations(state, checkpoint, compiler_row)`.
It must return an ordered tuple of actual independently reverified data exact4:
ingressSequence, recordSha256, factsState, result. Every admitted opening must
have exactly one result. Result uses the complete real ObservationResult
semantics, never hashes expanded into invented facts. This producer is not
implemented by this slice. The fixed import refuses when it is absent.

In particular, actual native exact transport capture must reach the shadow
response evaluator; the legacy reqwest unavailable path cannot stand in for
it. The genuine compiled route classifier must emit the independently bound
compiledSemanticProfileSha256; an expansion cell or a policy-plan digest is
not a substitute. Real timing capture and complete response-validation
preimages must be retained and independently authenticated. Root owns those
producer prerequisites, and this consumer does not manufacture them.

The result is explicitly nonactionable: okForAction=false,
activationApprovalConsumed=false, automaticRetryAllowed=false. It does not
create an old policy_canary_readiness row, change a canary head to READY,
consume a WebAuthn approval, dispatch a publication, or reload a native
policy. The explicit native READY successor and real human/independent
activation request continuation remain REQUIRED owned follow-on work.
The existing Fleet activation code must not receive a relabelled native
derivation result. Until those joins and the actual producers are complete,
this is not a source-complete readiness feature or a testable pilot claim.
