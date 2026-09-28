# Retained recovery target selection

This is source-only read-only selection for the [public recovery foundation](oidc-session-activation-public-recovery.md).
It is unbuilt and unexecuted. It neither supplies actor permission nor completes
public recovery, issues a grant, changes a journal record or sends a token.

`control_plane_oidc_session_activation_recovery_selection._select_on_owner`
requires the actual enrollment owner plus keyword-only `local_digest`,
`live_window`, `transport_deadline_ns`, `work` and `current`, with optional
`maximum_original_bytes=None`. It returns `None`
or the exact ordinary tuple:

1. Original `ActivationDispatchAttemptRecord`.
2. Original consume `ConsumeRecord` with kind `claimed` and empty raw0.
3. Original consume `ConsumeRecord` with kind `release-intent` and exact raw1.

The original finalization locator selects the existing `_consume_targets`
index. That unique target-to-slot association is established by genuine journal
recovery or the first successful consume claim. There is no filesystem scan,
browser-supplied activation authorization digest or prepared-ciphertext load.
The selected authorization digest is only association data: the intent does not
authenticate it as past execution authority.

The actual custody client and journal expose the same fixed method:
`load_oidc_session_activation_recovery_target(finalization_digest, *, work, current, maximum_original_bytes=None)`.
They verify existing fixed-prefix metadata and immutable file identities, then
read only the two claims and release intent with exact EOF and normal close.
The original metadata sizes are checked against each existing codec maximum
before read allocation. The supplied cumulative work is directly precharged
for three times those actual sizes plus three EOF bytes and four decode hashes;
the fixed metadata walk is charged separately. No full-prefix maximum reservation,
new allowance, logical record, file, quota or wire encoding is introduced.

The historical-archive consumer passes its positive remaining representation
capacity, no larger than 64 MiB. Before the first body, the journal requires
`3 * sum(actual selected encoded sizes) + 16 KiB <= maximum_original_bytes`.
It checks every selected path's immutable identity before this decision and
uses the existing fixed-buffer guarded reader for descriptor identity, bounded
chunks, exact EOF, normal close and path recheck. Each decode and final return
remain within the original guard. Capacity refusal does not poison unchanged
storage. Omitted capacity preserves the existing call contract for other callers;
it does not allow the archive consumer to omit its own accounting.

The supplied guard must be the original owner-scope guard, not a closure that
reselects records, repeats historical replay or reacquires the journal I/O lock.
Selection retains actual owner/material/binding/custody identity and the original
clock/deadline. Guards surround each bounded read, metadata admission and return.
Because the methods charge work themselves, callers must not enclose them in a
stable work-free native callback.

An absent consume claim or retained intent returns `None` after owner/readiness
checks. It means only that this target-only slice is unavailable. Changed files,
corrupt records or inconsistent associations fail terminally and poison the
journal; capacity refusal precedes body reads and does not poison valid storage.
Missing or uncertain data never proves nonexecution, grants a retry, or permits
earlier-stage completion recovery. No recovered claim resumes publication.

The actual recovery history inspector separately replays the finalization target
and admits its exact retained acknowledgment, then authenticates the selected
intent against independently configured enrollment/scope and ephemeral old-token
possession. The selector returns no successful target/permission DTO and retains
no cookie, assertion, old/new token, private packet or release-outcome original.
Fresh target-bound WebAuthn and any configured approval remain separate from
historical signature admission. The activation workflow is source-landed, but
historical authority for its downstream completion/proof/grant/release stages
remains separate H05 work. Neither selection nor a historically authenticated
target supplies those independent authorities or a current session.

The retained target carries actual original bytes and a conservative full
reservation into the actual actor and release-acquisition path. The reservation
already includes the upstream request, measured parent and archive captures.
Acquisition retains it once, adds its new actor captures and private-operation
headroom, and bounds the next fixed original inventory before reading. Actor and
post-actor delivery checks pin both counts with the target fields. No phase
silently drops historical graphs from its allowance while a guard retains them.
