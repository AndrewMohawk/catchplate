# One-record private release outcome store

`authority_oidc_session_activation_release_outcome_store.ReleaseOutcomeStore`
retains one exact token-free [outcome record](oidc-session-activation-release-outcome.md)
in a dedicated directory for one delivery slot. It uses actual
`CurrentRootJournal` and `WitnessJournalIO` mechanics, not the encrypted consume
plan journal. No AES/history/signing key, plaintext token, SQL table or directory
creation is involved. This is source-only, unbuilt, unexecuted and unprovisioned.

The constructor requires `directory_fd`, original `authorization_bytes`, the
actual `root_public_key`, independently supplied closed `expected_scope`, and
the existing `live_window`, positive `transport_deadline_ns` and cumulative
`work`. Genuine [root storage authorization](oidc-session-activation-release-outcome-authorization.md)
and current scope admission precede protected directory I/O. The process must
be UID/GID 65502 in all real/effective/saved identities, without supplemental
groups, in the fixed token-release mode.

The root scope binds configuration/database/generation/runtime, receiver,
delivery, release-custody digest, exact directory device/inode/UID/GID and an
independent checkpoint: `0/null` or `1/outcomeDigest`. Recovery never infers
genesis from absence. The directory is private mode `0700`; a separate no-follow
open takes an exclusive singleton lease. The underlying physical record limit
is two because its existing constructor requires that minimum; this protocol
rejects every sequence above one and permits only zero or one codec-bounded
64 KiB record. Unknown entries, temporary names, wrong metadata or extra slots
fail closed.

Cold recovery calls the actual journal's `recover(..., work=work)` on the
original allowance. Native reading charges its stat-validated size before
allocation; the semantic codec reducer legitimately charges that same work and
is not enclosed in a metrics-constant callback. All reads close normally and
the actual file/directory fsync barriers finish before the independently
authorized record count and domain outcome digest are compared. The raw file
SHA and a successful scan are not substitutes for that checkpoint.

`_snapshot_configuration()` returns one immutable sealed `_Configuration` with
`source_revision`, `authorization_bytes`, actual `root_public_key`,
`root_spki_digest`, canonical `scope_bytes` and `binding_bytes`,
`authorization_digest`, and `directory_binding`. Caller-owned mutable graphs
are not retained. Exact class, PID, lock, configuration identity and journal
identity are checked; actual journal inventory/file continuity is checked on
protected operations. Root integration can retain the configuration object's
identity through its own admission/retention suffix.

`retain_on_work(record_bytes=..., root_public_key=..., expected_binding=...,
live_window=..., transport_deadline_ns=..., work=...)` returns only the domain
outcome digest. The independent seven-field binding is configuration/database/
generation/runtime/receiver/delivery/release-custody identity. Each call joins
the supplied actual root SPKI to the held root, genuinely reauthenticates the
original storage grant and held scope, compares the independent binding with
the grant and record, and preserves sticky original processing clocks.
The live owner keeps its constructor's exact cumulative work object and
original three-sample clock bracket. Subsequent calls can only narrow the
previous window and deadline; they cannot restart either allowance. A fresh
independently authorized lifetime requires a separate cold construction.

The first record is published without replacement, made mode `0400`, fsynced,
and read back as exact bytes after normal close. Exact repeats return the first
identity after real readback; changed bytes conflict and poison/close the
handle. The initial checkpoint governs cold admission only: a successful own
append advances held state without treating the initial `0/null` as a current
checkpoint. A later cold authorization must independently pin the actual
one-record outcome. Renewing a storage grant does not alter the outcome's
identity: storage-authorization digests deliberately are not record fields,
avoiding a checkpoint/record circular hash.

Ambiguous I/O or a failed protected suffix poisons and closes the actual
journal; a visible publication is never removed, overwritten or retried.
Resource acquisition is held before callback suffix checks so constructor
failure can close it. `close()` closes only the independently opened journal
description, never the borrowed FD or retained bytes. Native append work is
precharged; no helper resets the cumulative budget.

This store does not authenticate a committed-release proof itself: the actual
release custodian must do so in the same invocation before retaining its
derived record. The returned digest is storage data, not release authority or
proof of plaintext egress. There is no read/recovery-authorization API, token
opening, automatic retry, rollback witness, service provisioning or production
verification here. Guarded opening and explicitly authorized uncertain-outcome
recovery remain separate gates.
