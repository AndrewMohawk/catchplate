# Same-call consume grant, reserve and SQL dispatch

[`control_plane_oidc_session_activation_consume_dispatch.py`](../catchplate/control_plane_oidc_session_activation_consume_dispatch.py)
connects the actual signed consume authorization to the isolated grant,
reservation and SQL roles. This is source-only, unbuilt, unexecuted and
unprovisioned. It adds no consume completion, token release, public route,
active-session cookie or recovery dispatch. Activation step 22 remains
incomplete; production acceptance remains 0/6 verified.

## An actual continuation, not a new permission input

The live permission exposes `dispatch_consume() -> raw4`; its parent facade
delegates to the exact active context. There are no original-response,
expectation, key, work, window or successful-result arguments. The actual
context must already have performed acknowledged activation completion,
consume prepare/export and
[consume authorization](control-plane-oidc-session-activation-consume-authorization.md).
Returned tuples and read-only recovered journal records cannot restore it.

A separate one-use latch is spent before dispatch callbacks. The fixed nested
consume-execution `/v2` configuration supplies root-held reservation and SQL
endpoints plus the independent predecessor `(sequence, headDigest, nextFence)`.
The strict `/v1` profile has no downstream endpoints and cannot dispatch.
No new key or descriptor is introduced. The original consume caller key,
parent identity, inherited FDs, runtime receipt, old-cookie possession and
root planner/history lifetimes remain held through the final context check.

The coordinator reconstructs closed expectations from the sealed prepared
originals and genuinely verifies the retained signed authorization against
the actual exported plan/ciphertext and consume before-vector. No cached
authorization or replay result is accepted as proof. The same cumulative work
and original clock opening are retained; each policy/expiry intersection can
only shorten the deadline, age or skew allowance. Bidirectional clock floors
survive every original-admission and transport stage.

## Public signed controls, isolated private replay

The grant response is admitted with the actual consume-only root enrollment
and fixed grant signature domain. Its configuration/database/generation,
authorizer measurement, caller-authorization identity, journal, plan, request,
operation, original raw2 descriptors and before-vector must match this call's
originals. The grant starts at the genuine plan's original issue time and may
not outlive the signed caller or original processing interval.

The reservation response is the actual consume reserve/snapshot/ACK raw3.
The caller verifies the signed reserve and state receipt using the original
root enrollment and independent predecessor/fence, joins its exact before
vector, and compares the consume-specific snapshot and vectors to the grant.
The reserve's signature binds that snapshot under its actual consume domain.
The derived ACK identity is an authenticated ancestry observation, not an
independently asserted current-pending checkpoint.

These checks authenticate public controls. They do not replay encrypted
business evidence or establish the private semantics of the result/after
vector. Genuine private replay and AES custody remain in the distinct grant,
reservation and SQL owners. The SQL service continues to require its own
independently root-pinned pending state; the caller does not learn authority
from the returned ACK. No generic activation snapshot fields or private replay
carrier are reused as consume authority.

## Durable order and terminal SQL uncertainty

Before network I/O, the whole held-original inventory reserves all three
maximum responses and framing headers within the existing aggregate bound.
The actual guarded transports charge the original work before allocation and
carry the actual current guard through native I/O, peer checks, exact EOF and
normal close. The fixed request inventories remain grant raw4, reservation
raw5 and SQL raw8; each service is contacted once.

| Retained stage | Original inventory and ordering |
| --- | --- |
| Grant | Raw1 is retained before signature or claim interpretation. |
| Reserved | Raw3 is retained before reserve/snapshot/ACK admission. |
| SQL claim | An irreversible empty marker is retained after genuine control admission and before any SQL send. |
| SQL outcome | Raw4 is retained before pending-identity consistency checks or any future interpretation. |

Every stage belongs to the same live consume claim and original activation
authorization identity. I/O is precharged before the fixed native journal
facades, with actual live guards before and after. The SQL claim rejects reuse,
including an identical attempt; recovered records remain read-only.

Only after that durable claim and the final original-authority check does the
context seal the exact SQL raw8 and its actual before-vector/current/narrowing
continuation. There is no public phase setter or result-object ingress. An
exception, missing response, identity mismatch, uncertain publication or
normal-close failure is terminal: no hidden resend, new signature or renewed
allowance is supplied.

The returned SQL raw4 is unsigned even if its status reports an observed
commit. Its pending identity is checked only for consistency against the
authenticated original reserve ACK. It is not commit/completion proof,
current session state, delivery acknowledgment, release permission or proof
of noncommit. Future completion must consume actual signed originals under
independent authority; no completion or token handoff is performed here.

Post-activation root issuance and matching independently provisioned private
workers remain external prerequisites. This source does not provision or
relaunch them and does not claim the complete public activation flow works.
