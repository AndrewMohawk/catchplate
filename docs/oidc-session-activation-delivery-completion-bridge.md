# Completion of an original bridged consume plan

The completion bridge authenticates an original planner-v3/history-v7 consume
result under separately fresh completion authority. It does not renew the
original policy, plan, caller, grant or delivery expiry, issue another SQL
attempt, or infer non-execution from missing local records. This is source-only;
no build, test, runtime, provisioning or production result is claimed.

## Three independently joined roots

| Root | Authenticated role |
| --- | --- |
| R0 | Original activation evidence, selected by the genuinely signed issuer bridge policy |
| R1 | Original consume planner/history and caller/grant/state enrollments |
| R2 | Fresh completion launch, completion custody v2 and history custody v11 |

The roots may coincide, but no equality or fallback is assumed. The fresh
`signedOidcSessionActivationDeliveryCompletionCustody/v2` envelope adds exact
`bridgeEvidenceRoot` (`publicKeyBase64Url`, `spkiDigest`) and
`bridgePolicyInterval` (`issuedAtEpochNs`, `expiresAtEpochNs`) fields. Its R2
signature independently authorizes R1 and the original policy interval before
old bytes are admitted. The separate fresh v11 history original must carry the
same root and interval. Both histories must bind the same original policy,
activation bootstrap and consume request. The old policy's complete state
payload equality still forbids arbitrary database/generation/state migration.

Legacy custody v1 remains strict: historical planner/history v2 and fresh v6,
under its existing root. The new schema does not widen those verifiers or use
planning history v7 as a completion grant. The fixed completion UID/GID, mode,
16 KiB outer cap, original-frame caps, 64 MiB aggregate and descriptor inventory
remain unchanged.

## Expired evidence, fresh processing

The distinct historical policy, history and planner verifiers authenticate
actual signatures and preserve their original intervals. The original planner
launch must fit its pinned policy interval and match its historical planning
grant; future-issued originals are rejected. These intervals are evidence, not
a substitute clock or a new deadline. Only the actual fresh completion launch,
v2 custody and v11 history bound current processing. The historical policy's
current-processing guards remain attached through admission and receiving;
they do not compare current time with its expired original lifetime.

The completion bootstrap verifies original caller/grant/state enrollments with
R1 and retains that evidence root separately. Its genuinely enrolled completion
signer remains the original R1-authorized key, explicitly admitted by fresh R2
custody; no new R2 state enrollment or signing key is invented. Startup uses R2
for cold/receiving reauthentication and R1 for actual replay, completion-journal
admission and state delivery. Private selector, signed dispatch and release-hints
launch profiles retain their existing fixed transport behavior.

## Actual private replay

`delivery_execution_history._replay_on_work` accepts no new public arguments.
Only an actual v11 owner selects its bridge branch. Before ciphertext opening,
`_completion_context_on_work` re-admits that owner's immutable originals,
matches the supplied R1 root/state/configuration and derives genuine R0
provenance. The supplied consume operation key must match R1; the old planner
must match the derived original. The entry retains only the derived old key and
base guard, dropping the decoded context before full replay.

The lower `delivery_plan` historical branch independently repeats original
custody admission under the same allowance. It authenticates original state at
R1, activation provenance at R0, exact possession, original-cutoff policy and
indexed writes, and recomputes the `PrivateInputs/v2` commitment to the old
state enrollment and signed bridge policy. No result carrier replaces those
originals. Legacy v6 replay remains unchanged; v11 cannot enter live planning.

Held encoded originals and detached graphs are reserved before context decode;
the existing custody reservation is additive within the same 64 MiB limit.
Original work, clock floors, owner identity and narrowed bounds survive private
opening, replay and final receiving guards. These reservations are not a heap
measurement. Global claims and original uncertainty remain intact.

The public historical-consume gate remains closed. Later interrupted recovery
still selects `target.authority.completion_recovery.consume` and consume
execution/root/configuration pins from the activation target R0, while newly
produced consume originals belong to R1. It needs an independently admitted
consume-evidence selector and matching pins; a root found in a journal record
is not authority. This batch connects the same-call worker/completion stack,
not interrupted mixed-root public recovery or a current session. Token release
is a separate purpose. Explicit older-source adapters and later historical
release paths remain open.
