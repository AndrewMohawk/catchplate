# Configured activation plan owner

[`OidcSessionActivationPlanOwner`](../catchplate/authority_oidc_session_activation_plan_owner.py)
composes the actual read-only activation reader, complete indexed write replay,
planner signature and encrypted original journal. This reusable source owner
checks supplied configuration joins; it does **not** independently admit that
configuration, authenticate a present caller, prove retained-finalization
ownership or supply off-host action-time currentness. No SQL, token release or
successful session activation occurs here.

Construction requires the actual `OidcSessionActivationReadPlanner`, actual
`ActivationOriginalJournal`, independent planner key pair/identity/SPKI and
configuration digest, the matching delivery custody key, fixed RP/origin and
authentication/trust policy, plan-age/skew policy and a 5–60 second delivery TTL.
It also requires original state enrollment, its independently admitted root key
and the complete root-vector original. Its held configuration is exactly 21
elements: the prior 18 plus those three independent pins, never learned from
the incoming observation. Construction authenticates the actual enrollment and
rejects a planner key shared with an enrolled state/computation/completion role.
It uses supplied work/window/deadline, checks the real key pair and read/journal
configuration, and retains private fixed inputs. Journal/delivery keys remain
private configuration only; neither enters a stored original or public result.
PID checks, a nonblocking operation lock and before/after configuration
continuity reject forks, concurrent use, replacement or a closed/poisoned journal.
`close()` closes the transferred journal owner and drops the owner's key
references; Python memory zeroization is not claimed.

## Prepare and retain

`prepare` accepts original assertion/old-token bytes, five independently admitted
user/session/credential/credential-record/challenge IDs, independent primary
roots and all 13 before-head expectations, plus the original work/window/deadline.
Required `head_query_bytes` and `head_observation_bytes` retain the actual fresh
cold exchange. Genuine state admission precedes token generation and is repeated
by the signed-plan producer against the exact scope/input/vector context. A
pending, mismatched or expired observation cannot reach signed planning.
It generates the new token internally and derives the exact typed request from
those originals and its fixed TTL. No successful assertion, transition or proof
result can replace original inputs.

The real `acquire_transition` uses one read-only snapshot and normal cleanup,
derives/authenticates the exact encrypted delivery and full six-mutation kernel,
and acquires all 12 write frontiers. The owner encodes those originals and calls
the [genuine signed-plan producer](oidc-session-activation-plan.md), which replays
the original assertion, read proofs and [indexed writes](oidc-session-activation-writes.md).
Independent expected heads are retained separately; signed/stored heads never
admit their own authority.

Before returning, the owner durably appends the exact closed 16-field v2 private
original document to the [encrypted journal](oidc-session-activation-journal.md),
including the actual signed envelope and exact nine-field read-input inventory.
The four state originals are enrollment, complete vector, head query and head
observation; none is replaced by a claimed successful state result.
It checks the unchanged processing bound and actual signed expiry before and
after retention. The frozen `PreparedActivationPlan` contains only immutable
`request_bytes`, `scope_bytes`, `envelope_bytes`, `plan_digest` and
`journal_digest`. Request/scope bytes are canonical token-free descriptions,
not operation authority; plaintext old/new tokens stay in the encrypted private
inventory. A local journal digest proves neither signature admission nor SQL.

There is no automatic retry. Publication followed by expiry, I/O uncertainty or
another failure may leave durable originals without a returned locator. This
owner neither deletes such originals nor generates/re-signs a replacement as
recovery, and does not claim general lost-locator discovery.

## Verify a known retained original

`verify_retained` requires the known exact signed `envelope_bytes` and separate
independent expected request, scope, primary roots and 13 before heads. It first
authenticates that original signature, configured planner/configuration pins,
request/operation identities and active interval before journal lookup/decryption.
After exact local readback it joins the stored request/scope/roots/heads to those
independent inputs and reconstructs only bounded original read records.

The actual signed-plan verifier then repeats the original signature/body checks,
assertion/encrypted-delivery verification, complete read admission, six-mutation
kernel/capacity derivation and indexed after-root replay. It returns the actual
recomputed `KernelTransition`, not an execution capability. Journal AEAD and
stored roots are never substituted for that admission. This method generates
no token, signs nothing and performs no SQL.

The shared private retained-original path runs under the actual owner operation
lock. It calls `_verify_full_on_work` once and uses only that invocation's
authenticated payload, original inputs, indexed replay and live guard. The
existing owner method's `verify_retained` signature remains unchanged
and still projects only the actual `KernelTransition`; the full internal result
is never accepted as an incoming proof or execution capability.

## Prepare a private execution-bundle candidate

```text
prepare_execution_bundle(*, envelope_bytes, expected_request, expected_scope,
    business_before_roots, authorization_before_roots, expected_counted_heads,
    expected_journal_digest, bundle_key, live_window, work,
    transport_deadline_ns) -> bytes
```

This is private candidate preparation, **not a durable export or service**.
The independently supplied canonical journal ciphertext digest and exact
32-byte bundle key are held before readiness/clock callbacks. The actual key
must differ from both configured delivery and journal keys. Its independent
provenance remains an upstream admission obligation; inequality is not key
enrollment.

The owner retains its operation lock and configuration continuity across the
whole call. The shared path authenticates the known original plan signature
before journal lookup. This branch uses the actual journal `read_bound`, so the
real retained ciphertext hash, first scope/digest and file identity match the
independent locator before decryption. It then joins original request, scope,
enrollment, complete vector, primary roots and thirteen heads, reconstructs the
bounded originals and performs one genuine full plan/transition replay.

Only afterward does the owner construct the codec's fixed seven-field context
from its schema/operation, actual journal scope and expected journal digest.
The [execution-bundle codec](oidc-session-activation-execution-bundle.md) seals
the exact unchanged private document. Original replay liveness, signed-plan
expiry, observation/delivery bounds and owner continuity are rechecked before
and after sealing and through return, on the same work/window and inherited
deadline. No expired output may be returned, and no key or plaintext is a
public result.

Fresh encryption can produce a different ciphertext on repeated candidate
preparation, even for identical originals. There is no first-exact bundle
publication, durable bundle identity, acknowledgment, retry policy or discovery
in this method. **Actual immutable first-exact publication and separately
admitted recovery remain required before any transport serves a bundle.** The
separate [first-exact exporter](oidc-session-activation-execution-export.md)
and [private planner service](oidc-session-activation-planner-service.md) now
provide that live-only storage/export composition; this candidate method
itself remains nondurable and is not a retry or historical-recovery endpoint.
Candidate bytes are not one-use execution authority, a committed delivery or a
session-activation result.

## Live-only boundary and deferred verification

This is **live-only** retained verification. The caller's current processing
window cannot renew the original plan, assertion, challenge, session or delivery
interval; an expired original remains rejected. A historical admission and
delivery/reconciliation protocol, present permission, retained-finalization
admission and protected one-use execution remain separate integration. The
[cold service](oidc-session-activation-planner-delivery.md) now composes genuine
v3 root-bootstrap admission, fixed independent state enrollment and a fresh
nonce-bound head observation. The v2 journal retains all four state originals;
receiving replay compares stored enrollment/vector bytes to the independently
configured originals before repeating observation signatures and complete-root
joins. The plan is clipped to observation expiry, not renewed on readback.
This observes the admitted local owner; off-host rollback protection and
action-time one-use currentness remain separate. No public activation route is
enabled by this owner.
Source-only; builds/tests/runtime verification remain deferred.

Frozen verification should cover genuine acquisition/sign/append/readback,
wrong keys/configuration/PID, concurrent calls, altered stored or independent
heads, forged known envelopes rejected before journal reads, missing/conflicting
originals, write-proof tampering, late publication/expiry, shared-work exhaustion
and absence of plaintext tokens from results and errors. Candidate coverage
must also reject reused custody keys, wrong journal digests before decryption,
changed original state/root scopes, and expiry during sealing; it must preserve
the transition-only retained verifier and distinguish randomized candidates from
durable first-exact exports. None has run yet.
