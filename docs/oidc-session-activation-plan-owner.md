# Configured activation plan owner

[`OidcSessionActivationPlanOwner`](../serverware/authority_oidc_session_activation_plan_owner.py)
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

Before returning, the owner durably appends the exact closed 12-field private
original document to the [encrypted journal](oidc-session-activation-journal.md),
including the actual signed envelope and exact nine-field read-input inventory.
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

This is **live-only** retained verification. The caller's current processing
window cannot renew the original plan, assertion, challenge, session or delivery
interval; an expired original remains rejected. A historical admission and
delivery/reconciliation protocol, a genuinely cold-admitted service, present
permission, retained-finalization admission, currentness and protected one-use
execution remain separate integration. No public activation route is enabled by
this owner. Source-only; builds/tests/runtime verification remain deferred.

Frozen verification should cover genuine acquisition/sign/append/readback,
wrong keys/configuration/PID, concurrent calls, altered stored or independent
heads, forged known envelopes rejected before journal reads, missing/conflicting
originals, write-proof tampering, late publication/expiry, shared-work exhaustion
and absence of plaintext tokens from results and errors. None has run yet.
