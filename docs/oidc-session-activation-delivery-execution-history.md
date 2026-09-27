# Historical consume originals

The dedicated consume history path authenticates and replays original
`oidc.session.activation-delivery.consume` plans and encrypted execution bundles.
It derives historical facts for the separate completion composition. It does
not renew a plan, admit a new execution, sign completion, retry SQL, release a
token or establish a current session. This is source-only work; it is unbuilt,
unexecuted and unprovisioned.

## Original-only interfaces

`authority_oidc_session_activation_delivery_execution_history._replay_on_work`
takes the actual `envelope_bytes` and `encrypted_originals_bytes`, independent
`expected_request`, `expected_scope` and `expected_journal_digest`, actual
`state_enrollment_bytes` and `before_vector_bytes`, the independent predecessor
`activation_expectations` and `activation_scope`, independently admitted
`planner_public_key`, `activation_planner_public_key`, `operation_public_key`
and `state_root_public_key`, the actual `historical_custody` owner, private
`bundle_key`, and the original current `live_window`,
`transport_deadline_ns` and `work`.

The owner must be the actual activation-history class admitted for the distinct
consume-completion v6 purpose. The worker checks its exact purpose before
private opening, binds the independently held consume request and root/state
enrollment, and rechecks its fresh current authority. Older planning, grant,
reserve, SQL and activation-completion purposes are not substitutes. The
execution bundle key must differ from the predecessor activation bundle and
delivery keys. No private key, plaintext token or owner appears in the result.

`_scope(owned, window, work)` validates original independent scope data.
`_authenticate(envelope_bytes, request, scope, planner_key, current, work)`
genuinely verifies the known consume signature and exact original identities
before decryption; it returns the authenticated payload and original plan
digest as same-call facts. These private helpers do not admit a role or issue
authority.

The returned `_HistoricalReplayedDelivery` contains `operation`, `request`,
the original raw2, `retained_record_digest`, before/after complete vector bytes
and digests, `result`, `original_interval`, `plan_digest`, `selected_rows`,
`mutations`, `work_units`, and current processing `live_window`, `deadline_ns`
and `live`. Its `valid_until_epoch_ns` is **original historical metadata**,
not a current expiry or renewed permission. No receiving API accepts this
result instead of original frames and independently admitted pins.

## Genuine replay and two separate timelines

The known original canonical signature, source cohort and independent request,
configuration, planner identity and key pins are checked before AEAD opening.
The distinct consume bundle codec authenticates the exact plan/journal context.
The bounded retained-record decoder restores the original data; stored request,
scope, activation expectations, state enrollment and vector must equal the
independently held inputs. Stored expectations never become authority.

`authority_oidc_session_activation_delivery_plan_history._verify_full_on_work`
accepts the same explicit original arguments as the live plan receiver. It
reverifies the actual original signature, complete state observation, predecessor
activation completion, old-token possession, primary and complete read proofs,
current-at-the-original-cutoff policy/trust/RBAC/session/delivery conditions,
three actual mutations and five indexed writes across seven heads. Every
signed body commitment and the full after-vector delta are recomputed.

The original plan interval must fit its independently admitted age and deadline,
the authenticated observation's original lifetime, and the actual original
delivery/session/provider lifetimes. The original database cutoff must fall
after plan issue minus the original policy skew and before plan expiry. The
state observation must have no pending reservation and a possible original
processing overlap with the plan. The plan issue is also checked against the
real current clock to reject future history.

The separate historical transition and indexed-write entries return distinct
result types and use that immutable original interval only for algebraic
checks. They never call live verification at an old issue/database time.
Current processing retains the supplied opening, cumulative work and inherited
deadline, narrowed only by actual fresh custody. Its final guards check real
current clocks; they never compare current time with an expired original plan.
All existing live entrypoint signatures and expiry checks remain in place.

## Completion boundary

Historical caller and grant admission belongs to the separate
[history exchange](oidc-session-activation-delivery-history-exchange.md), which
must authenticate those originals before private replay. A later dedicated
completion composition must independently prove the committed packet/marker
and current pending decision, use the enrolled completion signer, and retain
and deliver the first exact completion original durably. A sampled head or
these historical results cannot replace those obligations. Generic replay and
completion operation inventories are not widened by this path.
