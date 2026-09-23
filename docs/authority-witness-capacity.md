# Replay witness completion-capacity accounting

Status: source implementation and read-only review only; unbuilt and unexecuted.
This extends the existing replay witness's local journal accounting. It does
not implement an initialization decision service, external latest-head authority
or a production witness deployment, and does not remove the startup blockers.

## The missing reservation

Previously each journal append checked only its own bytes and record slot.
The witness could therefore acknowledge a reservation that left no room for a
later commit, abort, reconciliation or credential-release consumption. More
unrelated reservations or a generation activation could exhaust that space.
The current generation contract also cannot finish an old generation's open
reservation merely by accepting a successor generation.

`authority_witness_capacity.py` supplies pure bounded accounting used by the
real `WitnessStateStore` append and recovery paths. Its frozen limit/usage values
are representation, not authorization or a reusable verified-state token. Every
entry point copies and validates exact integer primitives; booleans, floats,
negative values, incomplete constructor-bypassed objects and signed64 overflow
deny. There is no I/O, signer, clock or journal mutation in this helper.

An acknowledged open reservation holds one terminal record slot and the full
`MAX_STATE_RECORD_BYTES` allowance. With retained records `R`, retained bytes
`B`, open reservations `O` and maximum record bytes `M`, new publication requires
both `R + O <= record_limit` and `B + O * M <= byte_limit` after the transition.
The limits remain derived from the existing signed mutable-state quota and
source ceilings; this does not raise any quota or accepted message size.

Each of the existing `reserve`, `webauthn-trust-publish` and
`credential-release` phases adds one open hold. A valid `commit`, `abort`,
`reconcile` or `credential-release-consume` replaces its predecessor's hold
with the actual retained terminal record. A terminal record requires an open
reservation; exact predecessor, phase pairing, operation, request, generation,
signature and replay validation remain the witness protocol's responsibility.
The helper's count alone authenticates none of those relationships.

The full maximum is conservative: currently each hold is sixteen MiB under the
four-MiB message contract. A smaller actual terminal releases unused logical
allowance, but neither terminal nor reservation history is deleted. Eventual
retention exhaustion still requires separately admitted lifecycle management.

## Publication and restart ordering

All new records share the existing journal serialization lock. The witness
computes exact canonical record bytes, checks projected retained usage plus
remaining completion holds, and only then publishes the immutable record using
the [journal durability protocol](authority-witness-journal-durability.md).
After durable publication it fully admits the stored record/request/receipt,
checks that its actual phase agrees with the planned capacity kind, and adopts
the new immutable usage. No response escapes before that sequence completes.
Any publication or post-publication admission failure poisons the handle; a
partially updated in-memory view cannot acknowledge a retry.

Exact historical retries return the retained response without another append
or charge. Reopening reconstructs usage from every authenticated retained
record, rather than trusting an independently mutable counter file. Actual
byte/record limits apply at every historical prefix, but completion holds apply
to the final recovered head. This permits an old, fully drained history whose
intermediate prefixes lacked today's conservative reservation budget. A final
head with insufficient room for its outstanding reservations remains unready;
the recovery directory barrier cannot turn that failure into success.

A new generation-activation record requires zero open reservations, both during
new publication and historical replay. An already retained activation of the
same generation costs nothing and can resume its existing reservations. This
is a drain-before-successor guard, not an implemented transfer protocol. Old
history that advanced generations over unresolved reservations now fails closed.
Do not discard those records, lower the usage or manufacture terminal receipts
to make it start; an independently admitted repair/handover remains necessary.

Existing wire schemas, phase sets, key purposes, source operation registry and
launch/network permissions are unchanged. Changed source/import measurements
must be included in new approved launch artifacts. Old manifests do not
authorize these source changes, and no migration is performed automatically.

## Verification and limits of the claim

The new component fixture covers exact byte/slot boundaries, multiple open
reservations, largest terminals, replay accounting, malformed contexts and
generation drain. It contains sixteen pure accounting tests and four
supplemental source-linkage tests. Those source assertions inspect the actual guarded
witness's append, recovery and replay linkage; they do not import it with a
bypassed launch guard or an altered registry. The existing journal fixture's
source checks are updated without deleting or renaming any of its twenty-one tests.

Nothing has executed. The fixture is listed in the consolidated isolated-test
inventory, still subject to the clean source freeze, independently approved
coverage/dependencies/controller and one preparation/sequential no-build phase.
Authored checks are not a launched-service, concurrency, crash or durability
result. A real end-to-end witness run is still required.

These are logical signed-quota holds, not allocated filesystem blocks or a
guarantee against ENOSPC, device failure, unsafe storage, administrative changes
or process failure. They do not ensure that a terminal request is authorized,
arrives before expiry, has usable generation credentials, or is eventually
delivered. They do not reserve additional multi-record recovery work that a
future protocol may introduce. The current seven-phase protocol has one terminal
per reservation; an initialization decision protocol must declare and reserve
its own complete materialization/recovery lifecycle separately.

The startup minimum sequence/digest is still only a floor, not an independently
maintained latest head. Independent witness provisioning, pending-generation
handover, initialization COMMIT_DECIDED/APPLIED services, writer fencing and
atomic database materialization remain unfinished.
