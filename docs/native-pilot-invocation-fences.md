# Native invocation identity and completion fences

The `.394` source strengthens the actual selected bridge, four ordinary-service
gates and native persistence. It does not implement terminal settlement or claim
a running pilot. Source checkpoints remain **36/46**; independent production
acceptance remains **0/6**.

The following `.395` [native settlement source](native-pilot-native-terminal.md)
now connects the successful-invocation producer and receiver described below.
This does not change `.394`'s recorded verification boundary.

## One invocation, one original result

The replay identity includes request content. Checking only that identity lets
a changed request present the same operation under another replay label. The
bridge now joins operation ID, termination fence and replay ID before cache
lookup, journal writes or authority contact. Any overlap must preserve the
entire dispatch binding and exact canonical RPC original. Recovery applies the
same rule before admitting a completed chain.

The bridge derives two in-memory indexes from verified completed originals.
Only the candidate replay and matching operation/fence entries need inspection:
at most three exact originals, not the whole 65,536-record/256-MiB bounded
journal on each request. The indexes are neither an additional durable store nor
independent evidence. Interrupted starts retain the earlier fail-closed behavior.

The same binding comparator is connected to CommitRequest service transitions,
DRS spool heads, current-signature spool transitions and active-effect cleanup.
Their recovered records reject operation/replay/fence aliases. An exact successful
command may return its retained reply without writing, still subject to the
original deadline, generation and owner checks. Enforcement is per gate; this
does not invent a cross-journal terminal census.

DRS retains its real two-stage allocation/commit protocol. A final Commit may
replay, but an earlier Claim cannot reopen after Commit. A reservation or barrier
produced by one completed invocation can still authorize a different invocation:
operation completion is not revocation of its business output. Separately, a
terminal ingress now refuses new spool reservations, including during recovery.
An unknown effect outcome is not reclassified as successful.

## Persistence uses its actual committed originals

Native persistence already stores authenticated final request/reply originals,
a signed commit and a synchronized linked head. Those records now also enforce
one final-original pair per operation. Exact replay returns the existing commit
without writes. Reusing an operation, replay or fence with a different original
pair fails before writes; duplicate or aliased physical records fail recovery.

Distinct invocations may legitimately reference an identical business receipt,
but each must persist its own final originals. Receipt-reference collisions with
different canonical receipt contents still fail, both live and during recovery.
Partial writes remain poisoned; separately admitted heads remain necessary for
anti-rollback. No grant, signature domain or wire format was widened, and no
new tombstone is being presented as proof of remote completion.

## What this permits next

Source review of the six fixed native signer roles found that their final Finish
handlers clear or mark invocation state before producing the authenticated final
reply. Their serve loops are serial, with no deferred operation work found after
that reply. The peer client accepts once, retains the actual peer PIDFD and has
no transparent reconnect path. The bridge serializes dispatch, caches completed
originals for no-contact replay and refuses unresolved starts on recovery.

Together these facts support investigating a successful-invocation terminal
successor using the actual final replies and durable bridge/persistence records,
without automatically adding another journal to every signer. This is a
source-derived design conclusion, **not a verified terminal proof**. It depends
on the selected measured implementation and authenticated originals, not a
caller asserting that its work is complete.

The reviewed native paths cover BeginIngress, CommitRequest, admitted spool
reservation/append, AppendTerminal, AppendActiveEffectBarrier, CommitActiveEffect
and ReconcileActiveEffect. Early Prepare/Complete replies are insufficient.
Generic VerifyObservationEvidence is not covered just because its routing role
is LedgerAppend. The four external roles—UnavailableIngress, SpoolCompaction,
PublicationReconciliation and ActivationPublication—require separate evidence.

Next implement a source-fixed participant/result verifier and authenticated
terminal producer, with explicit independently approved successor selection in
the receiver. Bind the original operation/request/fence/deadlines and actual
successful dispatch originals. Keep uncertain and aborted attempts unavailable
until their genuine recovery path exists. Preserve legacy process-reaped v4;
neither a final reply nor a service shutdown may be relabeled as process death.

Sources: [bridge](../data-plane/decision-gate-rs/src/policy_custody/services/production.rs),
[indexed identity guard](../data-plane/decision-gate-rs/src/policy_custody/services/production_replay.rs),
[shared comparator](../data-plane/decision-gate-rs/src/policy_custody/services/completed_operation.rs),
[persistence](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/persistence.rs),
[spool Finish](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/spool_signer.rs),
[effect Finish](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/active_effect_signer.rs),
[CommitRequest Finish](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/commit_request.rs),
[fixed peer](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/retrieval_peer.rs).

## Focused verification

Source commit: `475dc70e383d538d13dd237355ebe48ac5d7c243`.
The single assembled Rust 1.88 offline/locked/frozen native binary check passed
(exit **0**, compiler-reported **46.59 seconds**). The pinned container had one
CPU, 8 GiB, no extra swap, no network and read-only source/vendor mounts. Existing
warnings remain: 312 library and 2,440 binary warnings, including duplicates.
Both exact std-only modules compiled separately and all **13 new controls passed**
(six shared identity cases and seven persistence invocation cases).

These controls exercise synthetic identity/replay relations and bounded index
behavior. They do not execute signatures, journal I/O, process restart, real
service callers or provider requests. The actual bridge and service integrations
were source-reviewed and typechecked, not run against live owners. Terminal
acceptance and all six independent production gates remain open.

Exact source archive: **86,579,200 bytes**, SHA-256
`09429ca955a89f5a1d8aa1e6c8eea06eaf2b9680160b86f1f343cbeb18b22b12`.
Archive, scripts, logs, test executables and checksums are retained outside the
checkout at `codex-offload/catchplate/engineering-builds/475dc70e-invocation-fences-E8DRTz/`.
No cloud, paid test, new dependency resolution or unchanged broad suite ran.
