# Bounded finalization completion history

`CustodyJournal.load_registration_finalization_completion_history` reads the
fixed historical chain needed by finalization completion replay. It accepts
only the finalization locator and keyword-only `maximum_original_bytes`,
`work`, and `current`. The client calls it directly on the original work
allowance, not inside a stable callback that forbids metered work.

The ordinary return tuple is `(preparation, reservation, finalization_outcomes,
registration_outcomes)`. `preparation` preserves the existing
`(finalization_record, evidence_digest, (evidence_record, signer_record))`
shape; reservation can be absent. These are opaque retained originals, not
an authenticated target, fresh authorization, store-existence proof or retry
permission. Genuine historical signature and completion replay still follow.

## Before the first body read

Under one journal-ready scope, source-fixed association indexes identify at
most fifteen distinct files: two associations, three prepared records, one
finalization reservation, four finalization outcomes and five evidence
outcomes. There is no scan, caller-supplied file list or prefix load. The
original source, families, three distinct locators, marker exclusions and
outcome prerequisites must agree before this inventory is usable.

Every selected path is stat-checked against its retained device, inode,
ownership, mode, link count, exact size and timestamps. Prepared byte counts
must match their indexed sizes; all other files retain their actual codec's
per-profile maximum. The aggregate check uses actual sizes, not fifteen
maximum-sized allocations:

`3 * sum(selected encoded byte counts) + 16 KiB <= maximum_original_bytes`

The caller supplies a positive remaining capacity no larger than 64 MiB after
reserving already-held originals and later replay/canonicalization headroom.
The journal does not divide that supplied cap again. Three encoded-byte
footprints conservatively account for fixed-size read buffers, bounded chunks,
immutable frames and the retained byte slices produced by these fixed binary
codecs. The additional 16 KiB reserves bounded header and locator text
bookkeeping. This is explicit representation accounting, **not a process-heap
bound**, allocator/RSS measurement or runtime evidence.

Actual read/decode/hash byte work, one EOF probe per file, fixed inventory work
and each content hash are precharged on the supplied ledger before body one.
Capacity or precharged-work refusal does not poison unchanged journal data.

## One read and unchanged evidence semantics

Each selected body is read and decoded once. The fixed reader opens with
`O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, checks the actual descriptor against the
preflight identity, uses a fixed-size buffer and bounded chunks, probes EOF and
rechecks descriptor identity. Normal close is followed by a fresh path identity
check. The original current guard brackets selected native operations and
decoding; descriptor cleanup still runs when a guard fails.

The original codecs and exact association/source/family/content-digest checks
remain in force. Reconciliation still requires its retained original uncertain
completion and cannot replace it. Missing optional records remain missing, not
proof of nonexecution. Every selected path and directory identity is checked
again before return. Mutation, corruption or a failed read poisons the journal;
no partially admitted tuple is returned. The guard must not recursively load
or publish records in this journal.

The four existing independent loaders are unchanged for other callers. The
new combined path avoids their repeated association/prepared reads and moves
this selected historical chain's aggregate refusal before any body allocation.
It creates no authority, work/window renewal, resource provisioning, recovery
worker staging, token exchange or browser cookie. Production acceptance and
runtime validation remain separate.
