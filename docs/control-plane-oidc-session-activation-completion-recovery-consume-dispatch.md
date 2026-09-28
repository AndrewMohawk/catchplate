# Fresh consume protected dispatch

This source-only private continuation follows the fresh consume actor's
[prepare/export](control-plane-oidc-session-activation-completion-recovery-consume-planning.md)
and dedicated caller authorization. It does not restore an activation
permission, expose a public endpoint or return a token.

`control_plane_oidc_session_activation_completion_recovery_consume_dispatch.py`
accepts only the actual source-owned `_ConsumeAttempt`. Its root-owned dispatch
latch is spent once at entry. The authorization result supplies the immutable
signed original, not permission: the caller signature, plan and exact
expectations are re-admitted against the independently configured parent keys
and enrollment originals. The original processing window and delivery expiry
can only narrow.

The sequence is fixed:

1. Contact the configured consume grant owner once. Retain raw1 before admitting
   its signature, caller/plan/frame bindings and original interval.
2. Contact the configured reservation owner once. Retain reserve/snapshot/ACK
   raw3 before genuine state signatures, predecessor/fence, full vectors and
   grant/snapshot correspondence are admitted.
3. Irreversibly claim the existing consume SQL slot, including the actual
   configured completion-hints choice, before the sole SQL contact.
4. Retain the exact unsigned SQL raw4 before inspecting even its optional
   pending-decision locator. A matching locator is not commit or completion.

SQL raw8 is `(authorization, plan, ciphertext, canonical expectations, grant,
reserve, snapshot, ACK)`. The private sealed `_ConsumeDispatch` retains these
originals and genuine current controls for the root-owned completion phase.
It is usable only in the same active owner, including normal cleanup; it cannot
be restored from a successful DTO or reused after an uncertain attempt.
Signed complete/state originals remain a separate obligation. No public AES
custody, SQL retry, release-profile selection or cookie authority is added.

The original 64 MiB representation allowance includes an execution lane of
8 MiB reserved before the first historical body. Dispatch retains the prior
authorization reservation and reserves eight representations of its actual
caller inputs plus bounded responses, canonical graph pins and framing.
Grant responses retain their existing 64 KiB maximum; reservation responses
are tightened to a 64 KiB total **before any response body allocation**. SQL
keeps its small existing raw4 limits. The direct guarded journal calls use
2 MiB temporary I/O capacity, reclaimed before the later 4 MiB completion
lane (which includes its own I/O). Neither lane resets cumulative work.
Oversized otherwise valid originals fail closed; this is conservative byte
representation accounting, not a Python heap or RSS guarantee.

The genuine authorization, grant and reservation guards remain live, with
canonical snapshots of admitted mutable graphs. Descendant admission clocks
use a base-only ancestor; no dispatch child is attached back into its own
ancestor. Root retains the final full guard through normal actor/trust cleanup.
All uncertainty remains terminal for this attempt; absence is not proof of
nonexecution. No runtime, build, provisioning or production readiness is
established by this source change.
