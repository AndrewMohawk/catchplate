# Historical finalization completion and recovery

This source-only continuation resolves retained finalization against independently
root-admitted historical authority. It does not retry SQL, renew an old execution
window, activate a session or prove an off-host current head. The implementation
is unbuilt and unexecuted; no production acceptance is claimed.

## Authority and actual caller

`control_plane_registration_finalization_completion._complete_on_owner` calls
the actual subject's `_inspect_material_on_owner` once under the cold owner's
lock. Its single combined loader retains the finalization, associated registration
execution/signer originals, reservations and observed outcomes together. The
resolver authenticates the archived configuration, generation, root and original
enrollments, the signer's regenerated request, associated registration completion,
and finalization grant/pending scope. Records remain data, not authority.

The selected historical material supplies verification configuration, pending
sequence/head/fence, completion authorization and packet identity. The current
owner still supplies the fixed completion endpoint and live resource ownership.
The public complete/recover routes independently authenticate the present user,
session and distinct action purpose; pending-session calls retain the actual
target credential, fresh assertion/bootstrap and approval checks. Neither route
compares historical configuration to current configuration or accepts a successful
subject object as permission.

The parent `finalizationHistory` scope is bound to the same independently admitted
`registrationHistory` archive. Unknown or ambiguous cohorts refuse; signed source
labels and original bytes are not rewritten. Explicit older-source adapters
remain open. See [historical authority resolution](historical-authority-resolution.md).

## One bounded continuation

The selected material's original work, narrowed window/deadline and full current
guard remain active through response admission and publication. There is no new
budget or clock opening. Before the first history body, the resolver reserves
held parent/archive/capture graphs, selected history representations, its fixed
`8 * MAX_RESPONSE_BYTES + 64 KiB` response lane and the separate journal slice
`FINALIZATION_COMPLETION_APPEND_BYTES`. That slice is
`6 * MAX_COMPLETION_OUTCOME_BYTES + 3 * MAX_CLAIM_BYTES + 16 KiB`; it is additive
inside the existing 64 MiB original-representation ceiling, not another allowance.
These source bounds are not a measured heap/RSS or runtime guarantee.

An already retained acknowledgment is genuinely reverified without a socket.
Otherwise at most one fixed-purpose completion exchange uses the selected old
packet pin and current endpoint. The caller precharges fixed request/response
framing on the same work; existing transport length caps, peer checks, exact EOF,
original deadline and normal close remain unchanged. No request contains SQL.
Initial completion refuses retained uncertainty; only the separately authorized
recovery action can request reconciliation.

The first bounded raw4 is retained as opaque data before semantic verification
while the original guard remains valid. The receiving verifier uses the selected
historical configuration, roots/enrollments and pending pins, not response-selected
expectations. A recovered acknowledgment is appended separately after genuine
verification. Uncertainty is never replaced. Failure or an absent local response
does not establish nonexecution, rollback or permission to retry SQL.

## Guarded persistence and cleanup

The two existing custody append methods accept optional `work`, `current` and
`maximum_original_bytes` keywords. Their new guarded branch avoids the legacy
append helper's duplicate full-history body reload; unchanged callers keep their
old behavior. It checks the exact admitted association and immutable metadata for
the fixed history inventory, then selects only the SQL claim and existing
completion/reconciliation bodies. Before any selected body or new encoding it
reserves three selected encoded footprints, three new publication footprints
when needed, and 16 KiB metadata. Existing slots compare original bytes directly
without allocating another encoding. No journal namespace or record grammar changes.

The journal directly charges the original work; it is not wrapped in a stable
callback that forbids ledger mutation. Reads keep native inode/size/EOF/close
checks. Publication reuses the exact native-owned `_CompletionPublication`
transitions, bounded metadata-only inventory checks, fsync, normal close and
published-inode/byte readback. Representation-capacity refusal precedes bodies;
journal quota refusal precedes publication. Malformed or changed retained state
and failed publication poison the journal. A failed
publication may be externally uncertain and is not undone.

The private `_CompletionReturn` carries only verified raw4 and the original full
guard to `_run`. After the actual owner lock exits normally, `_run` repeats that
guard and current owner/custody identity checks before exposing raw4. This private
return is never accepted as an input proof or reusable permission.

Activation consumers can use this same genuine finalization prerequisite and
retain its narrow cold continuity after consuming the acknowledgment and dropping
the full history graph. That does not complete activation's own historical
planner, caller, intent or release authority resolution. Those scopes and explicit
older-source replay remain H05 work; all production gates remain open.
