# Activation originals in successor execution frames

This source-only change declares the activation original-byte family consistently
across existing successor packet boundaries. It is unbuilt and unexecuted, not
independent caller admission, a deployed executor or a completed session flow.

`authority_current_root_plan_replay._frame_maxima(operation)` is the shared,
source-closed inventory for revocation, evidence, transition and activation
families. Existing families retain their original ordering and caps. Activation
uses exactly two originals, in order:

1. The original signed activation plan, bounded by its actual 16 KiB contract.
2. The original [encrypted execution bundle](oidc-session-activation-execution-bundle.md),
   bounded by the actual bundle codec's frame ceiling.

The second frame is ciphertext, not a plaintext journal document, token or key.
Real receiving admission must open it under separately admitted private custody
and genuinely replay original proofs. Neither frame shape, an alleged digest nor
a returned successful-result object substitutes for that admission.

## One inventory, unchanged aggregate ceiling

The shared inventory now supplies the fixed count and each frame's byte cap to:

- `authority_current_root_computation._snapshot_shape`, including the aggregate
  `originalFrames` byte count;
- `authority_successor_execution_grant._grant_shape`, preserving original issue
  and expiry relationships;
- `authority_current_root_execution_admission._originals`, preserving the total
  plan-plus-enrollment/reserve/receipt/snapshot limit;
- `authority_successor_execution_recovery_packet._plan_maxima`, preserving
  pre-decode frame and total checks;
- `authority_store.successor_execution_sql._originals`, which generates its
  operation-specific frame maxima from the same actual source inventory.

All aggregate original limits remain 64 MiB. The canonical custody packet is
also bounded to 64 MiB **including base64 originals, controls, effects and
framing**. The bundle codec's allowance for its own framing overhead does not
increase either ceiling or the supplied cumulative work budget. A valid
standalone bundle is not guaranteed to fit an execution packet.

SQL verifies each opaque frame's exact declared length, canonical base64 and
SHA-256, then binds frame positions/counts/digests to the original snapshot and
grant. It never receives a bundle key or decrypts/parses ciphertext as JSON.
The six control originals retain their existing canonical JSON handling.
Packet effects and results remain actual original-replay outputs; plaintext
private tokens or keys must not be serialized into them.

## Authority and atomicity stay separate

These shape changes add no caller-controlled candidate input, signature bypass,
historical activation admission or expiry renewal. Retained-packet decoding is
ordinary data recovery, not permission for activation completion. Genuine live
receiving-owner admission remains required before protected packet issuance;
activation historical completion remains separately closed.

The existing actual executor still irrevocably claims its attempt before DB
access and supplies only genuine pending/packet identifiers. Protected SQL
continues to lock stored custody, reject reuse, enforce the original deadline,
compare the locked complete before-vector and exact selected rows, apply ordered
CAS effects, compare maintained after-roots and atomically insert its immutable
commit marker. No SQL-lock, privilege, one-use, mutation or retry rule is widened
by the frame inventory. Completion, token release, public permissions and portal
activation remain separate work.

No tests, parser, import, SQL execution, build or runtime verification were run.
