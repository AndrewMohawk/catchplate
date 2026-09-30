# Native finalization: actual drain and complete final accounting

This source-only slice selects nativeCanaryDurableDelivery/v3. Its independently
signed policyCanaryFinalizationPolicy authorizes a distinct native role-4 purpose,
full statement33 signature and NSM challenge domain. Old delivery v1/v2, Fleet
envelopes and heartbeat-v1 observation-window expiry remain unchanged.

The actual worker owns idle cadence and finalization. Binding the real serving
Arc wakes that worker; its retained installed-generation/trusted-clock owner
arms admission before requests can enter. The first actual arm time is retained:
late installation cannot claim coverage before it. At the original observation
window end, the same admission mutex closes irreversibly. Live admission guards
and last-Arc request lifecycles form the census. Dropped, failed, unavailable or
unresolved work is retained and blocks a seal; neither an empty queue nor a
dispatch terminal proves response completion.
An actual covered request refused while the pre-end admission serializer is
busy poisons the coverage owner instead of disappearing from a successful seal.

A dispatched lifecycle must hold the genuine terminal, request comparison and
response comparison originals. In particular, unavailable reqwest response
capture does not become an exact response. The genuine native raw capture
consumer is a separate connected prerequisite owned by the transport lane.
No missing custody CloseIngress RPC, RangeClosure receipt or Fleet signature is
invented here.

After actual drain the immutable census is signed with the SAME final complete
ledger snapshot and a new heartbeat-v2 observation. Its authority is bounded by
the original assignment sealDeadline, assignment/load expiry, measured native
lifetime and current finalization permission. Each distinct idle/final
observation fixes one processing deadline before signing/contact. An unresolved
prepare, claim, intake, heartbeat or cumulative original is never retried,
replaced or given a fresh deadline.

The existing durable prepare, authenticated original read, irreversible claim,
single intake contact and authenticated consumed completion are used twice:
first for the exact heartbeat, then its exact cumulative-v2 carrier. Native
compaction intervals remain original-window observations and stop when admission
closes. Final accounting still includes ALL retained signed originals, including
the uncompacted tail; the census is not mislabeled as a spool-compaction receipt.
Empty prefixes and unchanged-prefix idle observations are explicit v2 cases, not
a weakening of cumulative-v1. Empty Merkle roots use the existing Rust domain.

The kernel rechecks exact protected assignment/load/publication, all original
signatures, complete predecessor roots/counters, latest consumed heartbeat,
cumulative continuity, and exact completed lifecycle associations. It refuses
later native observations after a consumed final seal. The source-fixed
validate_readiness_checkpoint(state, record) returns only the actual six retained
scope/accounting/seal objects after exact latest-consumed verification. The
independent verifier AND planner must additionally re-admit every referenced
finalization original under their current signed configuration.

After definite final cumulative consumption the native driver makes one call to
the paired readiness owner's submit(state, final_checkpoint_original, deadline),
with that unchanged deadline. Local finalization is marked sealed before the
call; missing fleet evidence is not a retry or readiness success. Detailed
route/operation/authority/expansion/response/latency facts and full fleet readiness
are separate genuine producers/consumers, not derivable from the old event hashes.
This slice does not publish a ready flag, activate policy or claim client delivery.

Temporary capacities are unchanged: 64 retained signed event originals,
512 KiB original history, 768 KiB cumulative record, 32 heartbeat/cumulative
sequence ceilings and the existing 32-row protected batch population plus
whole-operation proof/work/HTTP bounds. Heartbeat and cumulative deliveries each
consume journal capacity, as do request observations: these are conservative
pilot limits, not production throughput claims. Overflow fails before the
applicable effect and leaves prior uncertainty closed. Scaling, migration and
retirement of protected history remain required work.

Prerequisite: exact A12+B24 union33 from OkoJay at .317, subsequently landed
unchanged in .318. Root/B own explicit outer v21 selection and the separate
readiness module. No builds, tests, parsers, runtime, provider calls, cloud
provisioning or acceptance evidence were performed for this slice.
