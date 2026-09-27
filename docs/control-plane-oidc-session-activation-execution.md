# Live activation permission and cold caller composition

[`control_plane_oidc_session_activation_execution.py`](../serverware/control_plane_oidc_session_activation_execution.py)
uses the actual control-plane owner and its distinct root-enrolled activation
caller key. It supplies no planner callback, grant request, reservation, SQL,
activation/recovery route or token release. Source remains unbuilt, unexecuted
and unprovisioned.

## Fixed owner and key custody

The explicit [v6 cold configuration](control-plane-oidc-session-activation-execution-bootstrap.md)
admits the original current-root, grant and activation caller enrollments,
dedicated planner public key, operation root and sealed caller key FD 205.
`_scope_on_owner` holds the actual key and resource identities before callbacks,
checks the genuine key pair, and retains the same PID, UID/GID 65532, owner,
custody binding, original runtime receipt and sealed descriptor continuity.
The actual provisioned HTTP response-key SPKI is rechecked on the same work;
drift or reuse by the activation caller is rejected. Other-purpose keys are
not borrowed for signing.

Cold activation-key enablement is not present permission or usable retained
history. The genuine retained-target inspector keeps its existing enabled
finalization/issuer and custody prerequisites; this slice does not weaken them
when another purpose is disabled.

## Permission before planning, authorization after planning

The actual parent exposes this private context entry:

```text
_oidc_session_activation_permission(
    *, request, permission_bytes, live_window, transport_deadline_ns, work
) -> live context manager
```

It delegates to `_permission_on_owner(owner, ...)`. Entering acquires the real
owner lock and fixed trust read-lock, installs the exact active identity in
`owner._activation_permission`, and invokes the genuine
[target-bound permission path](control-plane-oidc-session-activation-permission.md).
The original request body supplies assertion/approval originals only, never a
plan, root, vector, actor or successful authority object.

The actual assertion consumes its challenge and updates the target credential
counter **before** this context becomes usable. A future fixed activation
composition must obtain its genuine plan after that update, inside this same
live context and cumulative allowance. There is no automatic planning callback
or placeholder planner in this slice.

The sole effectful method is:

```text
authorize(*, originals, expectations, before_vector_bytes)
    -> original signed activation authorization bytes
```

No replacement HTTP request, work, window, deadline, key or permission result
can be supplied to that method. It is single-use, spent before input capture or
signing. Raw2, the complete before-vector and all enrollment originals are
bounded together with the original permission body and reserved output before
callbacks. The complete independent expectation graph is detached before
native/hash work.

The method joins the actual typed plan target to the retained user/session,
credential identifier, current credential-record identity and current old-token
commitment. It genuinely authenticates the known planner signature and rejects
a plan issued before the completed fresh permission/counter update. The actual
post-plan caller producer then authenticates the original enrollment and exact
plan/raw2/journal/vector bindings, creates its own fresh nonce and signs with
the retained actual caller key. This public-plan signature readback is not
encrypted-history replay; the separate receiving execution path still owes
genuine full original replay and current-state admission.

The producer retains a restrictive bidirectional clock-floor connection to the
actual owner and current session/credential checks. Returned floors cannot pass
its current narrowed epoch/monotonic deadlines. Authorization expiry remains
bounded by the original plan, pending session, caller policy and supplied
processing window. The method tail-returns the genuine producer's original,
not a successful verification carrier followed by weaker checks.

## Finite lifecycle and remaining boundary

The active context is exact-parent-, PID- and thread-bound. Reentry, overlapping
contexts, transfer, a second sign or use after exit fails. Failure or exit
revokes the parent slot and releases acquired locks; borrowed keys and custody
descriptors are never closed. No external API accepts this context or a prior
permission result as authority. Assertion/approval consumption is not rolled
back on a later failure, and no retry or replacement authorization is implied.

An authorization is not an execution grant, current-root reservation, committed
activation, token delivery or current authenticated session. Step 22 must still
connect actual post-permission planning and public activation dispatch, and
step 23 must separately authorize public recovery. Portal work and the six
independent production acceptance gates remain open.
