# Pre-intent recovery target originals

This source-only read-only selector supplies evidence to the earlier-stage
target inspector for [public recovery](oidc-session-activation-public-recovery.md).
It is unbuilt and unexecuted. It does not complete earlier-stage recovery,
authenticate a user, create authority, repeat SQL or release a token.

`control_plane_oidc_session_activation_completion_recovery_selection._select_on_owner`
takes the actual enrollment owner and keyword-only `local_digest`, `live_window`,
`transport_deadline_ns`, `work`, `current` and optional
`_additional_original_bytes=0`. Its result is `None` or an exact two-tuple:

1. `ActivationDispatchAttemptRecord`, the retained irreversible dispatch claim.
2. `ActivationRecord(kind="prepared")`, with exact raw5 authorization, signed
   plan, encrypted execution bundle, expectations and before-vector originals.

The finalization locator selects only the existing admitted target index. There
is no filesystem scan, whole activation/consume prefix load, SQL outcome read,
release-intent requirement or caller-supplied successful target object. The
encrypted bundle is retained opaque evidence here; selection does not decrypt
it or treat its presence as an effect, successful execution or permission.

The custody client and journal expose
`load_oidc_session_activation_completion_recovery_target(finalization_digest, *, work, current, maximum_original_bytes=None)`.
The remaining cap is an exact integer from zero through 64 MiB; `None` selects
that same 64 MiB ceiling. The source-owned selector subtracts its nonnegative
additional reservation from the ceiling, never creating a second allowance.
Before either body is allocated, the journal validates the source-fixed prefix
and known immutable identities, then requires three times the actual encoded
claim/prepared sizes plus 4096 metadata bytes to fit the remaining cap. The
selector exports that fixed `METADATA_RESERVATION_BYTES` value. The historical
inspector separately reserves already-held parent/cold/actor material and its
later genuine admission representations; this reader's cap is not a complete
cryptographic admission budget or a Python heap/RSS guarantee.

The same cumulative work is charged directly for bounded metadata, three times
the selected sizes plus exact EOF bytes, and two decode hashes. The existing
fixed-size guarded reader checks the original current guard around native
open, metadata and chunk reads, enforces exact EOF, and closes normally before
return. Only these two bodies are decoded. Other known stage identities receive
metadata checks without loading their bodies. All selected scope/source/kind
associations and immutable identities are rechecked before returning.

The supplied current callback must be an original owner/resource ancestor. It
must not replay admission, reselect records or reacquire the journal I/O lock.
The facade retains exact owner/material/binding/custody identity, work limits,
clock floors and deadline. Call it directly, not inside a work-free stable
native callback. Neither an unavailable result nor a capacity refusal renews
that work/window.

Absent required claim or prepared metadata returns `None` only after actual
owner/readiness and known-prefix checks. Valid but oversized selection or
preflight work exhaustion is refused before the first body read without poisoning unchanged
storage. Inconsistent indexes, changed files or corrupt originals poison the
journal. Missing data means unavailable, not nonexecution or permission to
retry. Recovered records remain read-only; no claim, record, quota, wire profile
or durable-effect mechanism is added.

The genuine historical inspector is the consumer: it independently replays the
finalization target and verifies the prepared authorization/plan against actual
cold configuration, original target and ephemeral old-token possession.
Selection itself authenticates none of those claims. Actual earlier-stage
completion/outcome recovery remains separate from this target foundation.
