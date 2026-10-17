# Dynamic consume-worker delivery

This source-only path stages the exact issued consume planner bootstrap and
history custody originals, then continues the existing private planner in the
same process. It does not provision keys, resources or services, and has not
been built, installed or executed as part of this change.

## Independent intake

The isolated `oidc_session_activation_consume_dynamic_launcher.py
--root-delivery` entrypoint starts as root with exactly two activated sockets.
Descriptor names, not their order, select the existing
`catchplate-oidc-session-activation-delivery-planner` listener and the new
`catchplate-oidc-session-activation-consume-bootstrap` listener. The latter is
fixed at `/run/catchplate/oidc-session-activation/consume-bootstrap.sock`, with
root:65495 pathname ownership, mode `0660`, and issuer peer UID/GID 65495.

Before waiting, the receiver authenticates the independent signed issuer
policy against the fixed runtime root and historical activation planner
original. These three protected public files live under
`/run/catchplate/oidc-session-activation-consume-dynamic-trust`:

- `root-public-key.pem`
- `issuer-policy.json`
- `activation-planner-bootstrap.json`

One staging request carries the fixed purpose and exact planner/history pair.
The receiver bounds both bodies before allocation and genuinely admits their
root signatures, purposes, deterministic intervals, configuration, historical
activation original and independently configured resource pins. Without the
original request and old token, this receiving admission does not independently
re-derive request-specific facts or establish possession.

## Staging is not readiness

Only after pair admission may the receiver open the source-fixed signing/AES
keys, TLS files, journal and export directories. It checks the actual key
bindings, existing signed directory/listener identities, and TLS pins. It does
not create, replace, empty or declare any directory empty.

The root and two issued originals are sealed into the existing eleven-FD
planner inventory, FD 198 through 208. The response is exactly `staged` plus
the framed identities of the planner and history originals. This ACK means
those exact originals were admitted and sealed and the pinned resources held
before the permanent privilege drop. It is not worker readiness, request
replay, SQL commitment, token release or authorization to retry.

After the ACK, the staging connection and listener close. The process clears
supplementary groups, permanently becomes UID/GID 65501, installs the existing
closed worker environment, and calls the dynamic runner without `exec`.
Cleanup closes only descriptors whose actual owned identities still match;
uncertain close or replacement is terminal.

## One allowance, two exact exchanges

The dynamic runner calls the genuine service's
`_initialize_from_delivery_on_work` with the original work, window, deadline
and bound delivery guard, then invokes `serve_sequence()` once. The sequence
accepts bounded prepare followed by export of exactly the just-prepared
envelope/deadline/journal identity. Both exchanges share the original ledger,
sticky clock observations and narrowed lifetime. Failure, uncertainty or a
lost response/close grants no retry or fresh budget.

The private `_DeliveryContinuation.current` retains sealed-original, TLS,
resource, PID and work continuity. Its source-bound capacity helper measures
held originals and decoded graphs; service admission checks unchanged opening
samples and narrowing-only bounds. The service accounts for its additional
originals, state and response buffers within the same 64 MiB complete bound.
The delivery guard does not freeze the initial eleven-FD inventory while the
service owns its precise additional descriptors and private replay lifecycle.
It is neither a serialized permission nor a successful-result carrier.

The selected historical activation replay path explicitly retains this guard
through encrypted-bundle opening, historical plan/indexed-write and transition
checks, historical assertion/state guards and delivery-row AEAD opening.
These are restrictive optional continuations on the actual original-consuming
APIs; they do not replace historical signatures, private replay or leaf clock
checks. Existing callers that omit the continuation preserve their old path.

The legacy static launcher and `serve_once()` path are unchanged. Actual
deployment, matching independently provisioned resources and the remaining
public HTTP/cookie and recovery paths stay separate acceptance gates. See the
[staging admission contract](oidc-session-activation-consume-input-delivery-admission.md)
and [staging transport](oidc-session-activation-consume-input-delivery-transport.md).
