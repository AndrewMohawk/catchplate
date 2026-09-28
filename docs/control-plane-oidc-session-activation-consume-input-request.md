# Same-call consume-input request originals

Source only, unbuilt and unexecuted. The private data-extraction helper
`control_plane_oidc_session_activation_consume_input_request._originals_on_permission(permission)`
returns an immutable raw16 assembled from the actual active activation
permission. It accepts no supplied identity, successful result, original tuple,
clock, guard or resource configuration as a replacement for that owner.

The permission must already be in `consume-planning`, with its existing
`_consume_spent` latch true, exact sealed activation SQL raw8, acknowledged
completion raw4 and the original completion continuation. The helper retains
the actual owner, work, material, binding, custody, policy, request, target,
seals and cookie. The existing completion guard runs before and after the
bounded extraction, with those references and possession checked around it.
No new latch, ledger, window, deadline, signature or currentness claim is added.

The returned tuple contains:

| Frames | Original data |
| --- | --- |
| 0–12 | The actual consume plan's activation raw13, in its existing order and bounds |
| 13 | Exact activation-expectations original from sealed SQL raw8 index 3 |
| 14 | Exact before-vector original from the sealed completion continuation |
| 15 | The actual pending-session cookie's original 64-byte token |

The real activation-original shape helper and token grammar are reused. The
expectations and before-vector have their actual individual byte caps, and the
tuple retains the existing 64 MiB whole-original ceiling. This is not a
completion, root-original or history admission result. In particular, possession
bytes remain ephemeral: the tuple must never be journaled, logged or returned
through a public response.

The existing consume prepare/export path now consumes these exact slices,
retaining its independent root admission, target checks, original lifetime
narrowing, durable claim before prepare, response retention and verified export
order. Its existing whole-original/response allowance is not replaced with the
more restrictive future issuance wire reservation.

The [fixed consume-input transport](oidc-session-activation-consume-input-transport.md)
can frame its fixed purpose followed by this suffix; transport separately
reserves both headers and the full bounded reply within its exchange ceiling.
This helper does not call that transport, acquire root originals, provision a
service, resume a recovered permission or authorize a retry. The receiving
composition must independently authenticate any returned planner/history
originals under the same still-active permission and allowance.
