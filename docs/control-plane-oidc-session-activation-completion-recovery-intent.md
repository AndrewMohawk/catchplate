# Completion-recovery release intent

`serverware/control_plane_oidc_session_activation_completion_recovery_intent.py`
connects one genuine release intent to the distinct fresh completion-recovery
actor purpose `release-intent-proof`. It does not revive an activation permission,
repeat SQL, select a release profile or checkpoint, open a token, or set a cookie.
This is source-only integration; it has not been built, executed or provisioned.

## Source-owned input and lifetime

`_intent_on_inputs(inputs)` accepts only the actual private `_IntentInputs` from
[the input admission](control-plane-oidc-session-activation-completion-recovery-intent-inputs.md).
The root orchestrator consumes its one-use intent latch at entry, including on
read-only reuse. The input retains genuine historical controls, the actual
completion receiving guard, independently reconstructed release expectations,
old-token possession, cold scope/enrollment pins and the fresh actor association.
An externally supplied successful object or callback is not an ingress.

The signer is the actual owner's dedicated intent key on FD 207, with its
original descriptor identity and independent enrollment. Its signer cannot be
the HTTP response key. No private-key serialization or new key read is added.
The original work ledger, clock floors, processing window and transport bound
continue throughout. The intent lifetime samples `inputs.current()` around the
input's base-only floor continuation; its own admitted child is not fed back
into that ancestor.

## Durable one-use intent

The bounded loader returns the existing consume-family intent claim, intent,
proof claim, setup and proof records. Their finalization/activation association,
source revision and exact original shapes are checked. The same persisted intent
slot is shared with the existing LIVE path, not a second recovery signing slot.

For a missing intent, the independently configured proof-setup policy must be
present before any claim or signing. The durable intent claim is written before
nonce generation or signing; the genuine producer then signs and the exact raw1
intent is appended. A claim without its original is terminal: a fresh actor does
not authorize a replacement or an automatic retry.

A retained intent is instead genuinely verified against independent scope,
release expectations, root enrollment and the actual old-token bytes. Historical
admission does not renew its signed interval or the original delivery expiry.
New proof contact additionally calls `_live_for_proof` on that exact intent; an
expired retained intent cannot be regenerated to obtain a new proof. Retained
proofs have a separate genuine historical read-only admission path.

The returned `_IntentContinuation` is privately constructed and identity-sealed.
`_require_intent` checks its exact input association and full current guard. It
stays inside the actual actor call; it is not a public permission or success DTO.

## Separate release-only readmission

`_readmit_on_inputs(inputs)` requires a new actual actor with sealed purpose
`release`. Its one-use phase hook belongs only to the separate delivery
orchestrator; the preparation entrypoint refuses that purpose and cannot be used
to sign on its behalf. The bounded existing loader and independent historical
verifier are reused, but an absent intent immediately refuses. There is no new
claim, signing, publication, preparation retry or original-expiry renewal.

The same exact private continuation and guards remain attached to that fresh
release actor. Historical re-admission is not current token-release permission:
the release owner must separately admit the intent/proof as current and admit
independent root-signed LIVE/checkpoint-zero client/server authority. It must not
infer a release profile or private-store state from local record absence. A
closed preparation actor or its approval cannot supply the new release purpose.

## Original capacity

`_additional_original_bytes(owner)` measures only already-held public cold
originals and reserves an 8 MiB future intent/proof representation lane plus
bounded cold/key representation allowances. It performs no file read, clock
opening or private-key export. The root adds this once before the first
historical target body, alongside the input module's separate 4 MiB reservation;
the carried target reservation is not added again at signing.

Intent reads and publication subtract `INTENT_REPRESENTATION_BYTES` from that
8 MiB lane before invoking the directly metered custody methods. This leaves
space for actual signature admission and retained intent representations while
the selected setup/proof originals are held. The journal separately preflights
its selected encoded bodies and publication copies. These are conservative byte
representation bounds, not Python heap/RSS guarantees or renewed work budgets.
Oversized retained history fails closed.

The next module is [proof acquisition/admission](control-plane-oidc-session-activation-completion-recovery-proof.md).
Independently admitted LIVE/checkpoint-zero versus RECOVERY/checkpoint-one token
release remains separate; missing local intent or outcome is not non-execution.
