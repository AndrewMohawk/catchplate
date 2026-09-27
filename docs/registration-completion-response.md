# Authenticating returned registration completion originals

[`authority_registration_completion_response._verify_on_work`](../serverware/authority_registration_completion_response.py)
is a private, registration-only receiver for the
[cold completion service's raw4 response](registration-execution-completion-service.md).
It authenticates the returned originals for
`webauthn.registration.evidence.admit`; it performs no transport, SQL, signing,
storage or retry and creates no work allowance or clock window. This source
has not been built or executed and activates no public caller.

## Required independent inputs

The keyword-only API requires:

- `response_originals`: exact raw4 state, completion-request ID, original
  completion request and original state receipt.
- `plan_originals`: the historical registration plan raw3—plan, original
  typed inputs and evaluation context—not a successful replay result.
- Original reserve request/receipt, computation snapshot, current-root
  enrollment, execution grant and grant enrollment.
- Independently admitted historical `expectations`, actual planner/evidence/root
  public keys, authorization digest, database/generation and exact expected
  pending sequence/head/fence.
- The caller's existing `live_window` and `work`, plus optional inherited
  `transport_deadline_ns`.

The expected authorization digest and pending scope must not be copied from
the returned controls merely to make them match. Local journal IDs and previous
successful-verification objects are not substitutes. Every original inventory,
scalar and the complete 64 MiB aggregate is bounded before native callbacks;
the historical expectation graph is detached through the actual replay helper.
Processing keeps the same original epoch/monotonic bracket and work ledger.

An `uncertain` response raises `RegistrationCompletionUncertainError` with a
fixed message. It yields no receipt, identity, successful result or retry
permission. Other malformed or unauthenticated originals fail closed.

## What is actually verified

The implementation composes the existing genuine verifiers in order:

```text
independent historical plan + reserve + snapshot + grant scope
    -> real pending-plan replay and reconstructed marker/full after-vector
    -> historical grant signature and authorization/capability joins
    -> original completion signature + original state acknowledgment
    -> exact completion/marker/vector and embedded observation joins
    -> unchanged originals and authenticated framed content IDs
```

`authority_current_root_execution_admission._admit_for_completion_on_work`
authenticates the original pending controls and genuinely replays the historical
plan. `authority_current_root_completion._verify_grant_on_work` binds the actual
historical grant to that same-call computation and independent authorization
digest. Neither helper renews expired execution authority or returns executable
mutations to this receiver.

`authority_current_root_delivery_records._verify_ack_on_work` authenticates
both response originals and joins the state acknowledgment to the independently
held pending sequence/head. The returned request ID must equal the actual
domain-framed identity of the signed request; it is not accepted as a claimed
hash. The completion's operation, database, generation, enrollment, pending
request/decision, fence, snapshot, result and before/after digests must match
the genuine replay marker.

The generic completion-control verifier already authenticates the exact embedded
writer-observation bytes and their hash. This receiver additionally enforces
the actual producer's observation profile:

- Exact `serverware.policyAuthorityCurrentRootCommitObservation/v1` schema and
  current source revision; closed five-field object and complete marker.
- At most 16 KiB, 256 JSON nodes and depth 3; exact canonical encoding from the
  real completion producer, not an alternate unsigned observation format.
- Exact reconstructed marker and digest of the genuinely replayed full
  after-vector.
- `observedAtEpochNs` inside the **original signed completion interval**.

This is authentication of an enrolled key's statement about its observation.
The receiver does not independently query the database, witness current roots
or establish that the statement's time is independently trusted.

## Output and historical limits

The private frozen `_VerifiedCompletionResponse` contains only:

| Field | Meaning |
| --- | --- |
| `completion_request_bytes` | Unchanged authenticated signed completion original |
| `state_receipt_bytes` | Unchanged authenticated state acknowledgment original |
| `completion_request_digest` | Actual framed completion-request content identity |
| `state_receipt_digest` | Actual framed state-receipt content identity |

It is an ordinary observation, not a downstream admission token. No admission
API accepts it instead of genuine originals and independent scope.

There is deliberately **no packet-ID claim**: the signed completion wire does
not include a packet locator. This API authenticates the exact independently
scoped plan/grant/reserve completion; it cannot prove that an unrelated packet
ID selected that response.

Historical completion or grant expiry does not by itself invalidate genuine
historical signatures. The caller's live processing window must remain valid,
but accepting those originals does not renew their intervals or establish a
currently pending head, current action permission or a state lease. In
particular, response-derived pins cannot supply a missing independent checkpoint.

## Remaining integration and deferred verification

Actual caller transport integration, durable retention/association of these
response originals, present-purpose admission and any public action remain
separate work. This receiver does not activate completion, public execution,
credential finalization or session/workload enrollment. Finalization still
requires its own genuine committed-evidence and exact signer-original joins.
No production acceptance gate is closed.

After source freeze and prerequisite admission, planned verification covers
genuine historical registration responses; wrong plan/grant/reserve/key/scope
and response IDs; malformed, oversized, noncanonical or mismatched observations;
observation times outside the original completion interval; uncertain-response
rejection; caller graph mutation during callbacks; and original-window expiry
or clock reversal without renewal. This is planned coverage only—no tests,
imports or runtime verification were performed for this source batch.
