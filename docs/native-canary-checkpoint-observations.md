# Native compaction checkpoint observations

Source-only implementation, not build/runtime or canary acceptance. This slice
starts from the exact frozen HELD40 integration plus A10 response observation
prerequisite. It does not add an outer startup profile or change old evidence
schemas, authority grants or legacy checkpoint/readiness admission.

## Actual producer and bounded selection

The live shadow worker calls AccountingLedger.compact_one_requested. Its
completed CompactSpool custody operation returns a VerifiedSpoolCompactionReceipt
under the independently assigned custody-spool-compaction key. The ledger checks
the exact retained predecessor chain, ordered range root, old head and retained
successor before applying that receipt. Only this successful local application
constructs AppliedSpoolCheckpoint. It retains the original signed receipt and
the exact ordered-range object calculated from the real receipt index before
removing its prefix; no decoded DTO can construct that applied owner.

The explicit measured-canary-delivery selection binds the SAME serving Arc to
the ledger. For this selection only, compaction has a fixed eight-event prefix
and 16-event trigger. Old profiles keep their 2,048-event prefix and 3,072-event
trigger. This is a concrete reachability decision: the old trigger cannot be
reached before the native intake's fixed complete-journal capacity fills.
No global row, proof, transport, queue or memory ceiling is increased. The
existing 16 MiB compaction reservation remains responsible for transient
originals; the exported canonical record is additionally capped at 32 KiB.
Production journal scaling and capacity lifecycle remain required work.

The concrete first-opening join also admits its existing canonical predecessor
ordinal zero as specified by the old schema; resulting event and ingress
ordinals remain strictly positive and exact predecessor+1. Previously the
receiver incorrectly applied the positive epoch validator to that predecessor.

## Real one-shot delivery

Before the custody compaction, the actual serving owner fixes one processing
deadline clipped by its original native lifetime and actual retained assignment,
load and generation observation expiry. The same generation is pinned before
the operation; neither a later publication nor processing delay renews it.
A successful original is
re-admitted against the SAME retained current generation, assignment, key trust,
native custody configuration and publication. Receipt time, interval and all
signed bytes remain unchanged. A retired or changed generation refuses; no
historical owner is reconstructed.

CheckpointAttempt consumes that actual applied original once through the
existing durable prepare, authenticated read, irreversible claim, one intake
and known-consumed completion chain. There is no retry or checkpoint resend,
new deadline, second request ID after uncertainty, or plain inspection elevated
into contact authority. Failure after compaction leaves its real result intact,
marks the selected runtime hard-unready, and prevents later compaction attempts
from bypassing the unresolved sender head. Earlier opening/terminal/request/
response observations keep their own original deadlines.

## Closed intake and proof limit

nativeCustodyCheckpointObservation/v1 is a separate record11 carried as one
checkpoint event in the unchanged native batch. It contains provenance, the
original compaction receipt19, exact ordered range6 with eight reference10
entries, and the actual signing public key. The receiver:

- Rechecks the protected assignment, load and publication/current revocations.
- Recomputes the exact range and new-spool roots, predecessor chain, count and
  existing assignment-bound spool-compaction signature. It never uses a
  FleetShadow signature alias or caller-provided success flag.
- Joins every covered already-intaken runtime receipt to its exact protected
  original and requires at least one such association. Omitted event types
  remain signed commitments, not fabricated runtime observations.
- Requires the first interval to extend the genuine protected load's exact
  authoritative ledger ordinal/head, then contiguous successors and no
  duplicate, skipped or overlapping interval, using authenticated complete
  prior-batch roots. It does not assume a zero baseline or invent prehistory.
  A fresh request ID cannot evade this check.
- Atomically retains original/result and source audit with the exact delivery
  consumption through the existing controlled writer.

The result9 coverage is only contiguous-spool-interval. Persistence and retrieval
digests remain original custody commitments, not independently manufactured
physical-storage proof. The original event ordinals are NOT ingress sequence
numbers. An interval may include only part of a request and excludes later,
uncompacted records. No complete ingress range, delivered client response,
entire fleet, sealed observation window or readiness claim follows from it.

## Remaining readiness join

The existing PolicyShadowCheckpointPayload/UnsignedCheckpointPayloadBuilder
describes a much broader cumulative checkpoint, but the runtime has no actual
producer that constructs, authorizes and seals that complete evidence from all
required observations/heartbeats/window closure. This slice does not populate
legacy checkpoint heads or make an interval pass that consumer. Genuine complete
coverage and final readiness/compiler/activation evidence, initial fleet and
role inventory producers, production capacity/migration and runtime acceptance
remain required successors. No readiness/completed Setup credit is claimed.
