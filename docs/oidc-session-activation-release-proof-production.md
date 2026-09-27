# Original-only committed-release proof production

`authority_oidc_session_activation_release_proof_production._produce_on_work`
connects fresh release authority and genuine committed-consumption verification
to the distinct [release-proof wire contract](oidc-session-activation-release-proof.md).
This is source-only implementation, unbuilt and unexecuted. It creates neither
a plaintext-release endpoint nor a durable release outcome.

The keyword API takes every original and independent pin of the
[committed-original verifier](oidc-session-activation-release-committed.md), plus
`release_custody_bytes`, `intent_bytes`, `intent_enrollment_bytes`,
`proof_enrollment_bytes`, the actual `proof_private_key`, independent
`expected_proof_scope`, `expected_caller_id`, and the actual `old_token_bytes`.
Proof scope has exactly configuration/database/generation/runtime identities,
producer ID, producer identity and receiver identity. No signed payload,
successful verification object or release AES key is accepted.

Before any typed-request hash or native callback, one bounded structural pass
owns all four mutable graphs: consume expectations, release target, consumption
binding and proof scope. Immutable originals, key handles and actual owners are
held first. Every original has its real contract cap; the existing seven
originals plus four new originals, old token and a reserved 64 KiB proof must
fit 64 MiB. Structural copies and all later verification use the supplied
cumulative work, never a fresh allowance.

The actual UID 65497 completion custodian must match the independently expected
producer identity. Its root/context/purpose admission and fixed commit-reader
snapshot remain live through return. Genuine root verification of the release
custody original admits its historical activation planner and fresh outer
interval. The producer joins the original current-root enrollment byte-for-byte
to the independently supplied control, then joins database, generation,
configuration, runtime, receiver and exact release-target pins. No expired
planner launch is renewed or substituted for the fresh outer authority.

The [actual intent verifier](oidc-session-activation-release-intent-admission.md)
authenticates the exact root-pinned intent, separately enrolled caller,
old-token possession and expected release scope. Actual state/planner keys and
the intent caller key are independently admitted; they are not learned from
the proof under construction. The [proof enrollment](oidc-session-activation-release-proof-enrollment.md)
must bind a distinct real signer, whose measurement matches the actual producer
identity and whose private/public pair is checked. Its forbidden keys include
the original activation planner, state/computation/completion, actual intent
signer, supplied consume planner and operation key, with metered internal SPKI
deduplication. Root is independently forbidden by enrollment. This is separation
from these observed roles, not discovery of every possible configured key.

The committed-original verifier runs **once**: original packet/control
admission, historical replay-derived effects, a normally closed real commit
marker/vector read, signed completion/state ACK and exact target comparison.
Only its same-call six-field release binding and state-receipt digest enter the
proof, alongside framed exact root-custody and intent identities. No stored
result or unsigned consumed flag substitutes for those originals.

Proof expiry is clipped to the original current window, fresh release-custody
interval, actual intent expiry, original delivery expiry and enrolled maximum
age. Existing guards and narrowed processing guards are retained, with sticky
epoch/monotonic checks and actual owner/reader identity continuity. Signing is
followed by the independent original proof verifier and exact payload readback
on that same allowance; this signature/control verification does not repeat
historical replay. Every authority remains checked through the final return.

The result is only the signed proof original. Receiving release-purpose custody
must independently authenticate it and its intent/root pins; a producer result
is not a reusable successful carrier. Durable exact outcome, guarded token
opening, uncertain-outcome recovery and cold private handoff remain separate
work. There is no token disclosure, SQL write/retry, provisioning, public
permission, measured-execution or production-verification claim here.
