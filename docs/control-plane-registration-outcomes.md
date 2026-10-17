# Local registration outcomes and one SQL-dispatch claim

This source-only extension retains exact response originals beneath an existing
complete signer/grant preparation. It adds one irreversible **local dispatch
claim**, not remote SQL permission or a new public route. The current source is
unbuilt and unexecuted; no production acceptance gate is closed.

## Original scope and APIs

The actual [custody journal](../catchplate/control_plane_custody_journal.py) and
[custody client](../catchplate/control_plane_custody_client.py) expose:

| Method | Local effect/result |
| --- | --- |
| `append_registration_reservation(local_digest, originals)` | Retain raw3 reserve request/snapshot/ack; return its local content digest. |
| `claim_registration_sql_attempt(local_digest)` | Publish and fsync an irreversible claim before any caller-owned send; return `None`. Every repeat fails. |
| `append_registration_sql_outcome(local_digest, originals)` | Retain the first exact raw4 SQL response; return its local content digest. |
| `append_registration_completion_outcome(local_digest, originals)` | Retain the first exact raw4 completion response; return its local content digest. |
| `load_registration_outcomes(local_digest)` | Return bounded opaque original records and IDs, never verification or permission. |

Every method requires the actual final preparation association and its exact
retained grant/signer pair, not a caller-supplied successful object. The claim
also requires retained reservation originals. SQL and completion outcomes
require that claim. A completion outcome may exist without a SQL response:
dispatch uncertainty must not be replaced with a fabricated response.

`RegistrationOutcomes` is frozen ordinary local data containing `source_revision`,
`local_digest`, and optional `reservation`, `sql_attempt`, `sql_outcome` and
`completion_outcome` records. Each record contains `source_revision`,
`local_digest`, `kind`, exact `originals` and its content `digest`; a claim has
empty originals. Their representations omit original contents. Loading rereads
the association, both preparation records and each present outcome. The source
token is the preparation's original token, not a claim that the current source
can replay that historical revision.

The grant ID is only a local locator. The caller must genuinely authenticate
each original response under independently admitted keys, scope, checkpoints,
purpose and original deadlines before using it. This module authenticates no
signature, committed state, current head, completion or credential finalization.

## Fixed records and durability

The [record codec](../catchplate/control_plane_registration_outcome_records.py)
uses distinct magic `SWCPO001` and content-identity domain
`catchplate.controlPlaneRegistrationOutcomeRecord/v1`. Frames contain a fixed
kind byte, bounded source token, raw preparation digest, fixed-count lengths and
exact original bodies with no trailing bytes. It reuses the actual reservation,
SQL and completion transport carrier/length checks; it performs no JSON or
cryptographic response verification.

- Reservation: exactly raw3, with the existing 256 KiB request, 16 KiB snapshot
  and 16 KiB receipt ceilings.
- SQL: exactly raw4, with existing state/ID/marker carrier bounds, including
  `observed-commit` and `uncertain`; marker at most 4096 bytes.
- Completion: exactly raw4, preserving existing `acknowledged` or `uncertain`
  carriers, request at most 256 KiB and receipt at most 16 KiB.
- SQL claim: zero bodies. All records retain at most 256 source-token bytes;
  the largest header is 331 bytes.

Fixed names are `reservation-`, `sql-claimed-`, `sql-outcome-` and
`completion-outcome-`, each followed only by the grant ID's canonical 64 hex
digits. Existing `SWCPR001`, `SWCPG001`, signer and preparation-association
formats are unchanged. No arbitrary filenames or paths are accepted.

The existing private directory owner, PID binding, singleton flock, readiness
lock, immutable regular-file checks, atomic publication/readback and fsync
machinery are reused. Recovery includes these files in its bounded scan and
byte quota, joins their source and exact preparation prerequisites, and rejects
unknown, temporary, altered or orphan files. The scan ceiling is six times the
prepared-record limit, covering the grant, its association and four fixed
records. Legacy attempt/observation byte reservations remain protected. These
new records do not change `JournalEntry`, inventory projections, legacy
attempt/observation flags or the permitted forwarding/reconciliation families.
Older readers reject the new files; there is no silent downgrade or cleanup.

Only byte-identical append repeats are idempotent. Changed originals never
replace a published record. The SQL claim is not idempotently reissued: once
published it is never removed, released or reused. Partial or uncertain
publication poisons the live journal and preserves every published original;
it never grants permission to resend. Quota exhaustion can prevent retaining a
response after remote activity, and therefore cannot establish nonexecution.
Filesystem durability still depends on correct fsync behavior. Local storage
does not resist malicious-root rollback or replace an independent checkpoint.

## Deliberate recovery limit

Completion retention is the immutable **first response**, not a latest-result
slot. If it contains uncertainty, a later independently admitted recovery may
obtain genuine acknowledged originals, but this API cannot overwrite the first
response or manufacture an upgrade. A separate bounded reconciliation and
original-association design is still needed. Neither missing responses nor a
historical acknowledgment establishes action-time currentness or allows SQL
retry. Public orchestration, independently admitted recovery, finalization and
production deployment remain separate work.

Planned frozen verification covers exact carrier/cap rejection, incomplete or
cross-source associations, missing reservation, repeated claims across restart,
readback/fsync failures, quota reservations, orphan/temporary recovery files,
changed first responses and unchanged legacy projections/forwarding. No such
tests or runtime checks have run for this source batch.
