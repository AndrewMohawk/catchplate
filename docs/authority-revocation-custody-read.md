# Read-only custody originals

This source path retrieves existing originals through verifier → planner →
writer. It is unbuilt and unexecuted. A successful raw read is not authenticated
recovery, current execution authority or a completed end-to-end workflow.

## Fixed locator and read path

The caller independently supplies `execution_envelope_id` and
`planner_transaction_id`, each an exact lowercase `sha256:` identifier. These
IDs locate rows; they do not authorize custody, enroll keys or establish an
independent expectation merely because a server repeats them.

Configured private clients use the existing measured role, active-launch,
generation and peer topology. The planner forwards the
same two locators to the writer. No verifier persistence directory, new DSN,
signer, public request dispatcher or alternative registry admission is added.

The writer uses its configured database/TLS identity in one actual
`SERIALIZABLE READ ONLY DEFERRABLE` transaction. PostgreSQL 16, current/session
role, TLS identity, non-elevation and the unchanged writer privilege inventory
are admitted before fixed SELECTs. The store owns bounded rows, checks the
request's parent/execution links and original planned timestamp, joins the
retained plan and ACK, and validates original-byte codecs, digests and counts.
It does not treat mutable execution status as custody evidence.

The returned tuple contains exactly six originals, in order: intent, relay,
signed plan, evaluation context, historical expectations and writer ACK. Only
owned immutable bytes survive normal cursor, transaction and connection exits.
The planner and verifier return those bytes without re-signing or constructing
a replacement response. Reads neither insert nor repair custody records.

## Bounded framing

`serverware.policyAuthorityRevocationCustodyReadTransfer/v1` uses request magic
`SWCR\0\0\0\1`, two big-endian 64-bit lengths fixed at 71, and the two ASCII
IDs. Response magic `SWRC\0\0\0\1` precedes six such lengths and the raw tuple.
Response body caps are respectively 4 MiB, 4 MiB, 64 MiB, 512 KiB, 64 MiB and
16 KiB; each body is at least two bytes and the aggregate is at most 64 MiB.
All lengths are admitted before body allocation.

Clients check their actual pinned peer before sending, half-close requests and
require response EOF. Servers check peers before reading the prefix and require
request EOF before application work. Existing bounded I/O retains one absolute
deadline and first-error cleanup. There is no JSON success/error union,
automatic retry, signing or proof verdict in the transport.

## Authority and evidence boundaries

Only the currently understood source format and exact row contracts are read.
Current connection/configuration admission does not authorize historical keys,
generation, policy or signatures found in stored bytes. Independent crypto,
historical-policy validation and genuine plan replay remain separate obligations;
the raw tuple is not a successful-proof token or a rollback witness.
Original expiry and currently enabled mutation operations neither gate this
raw read nor authenticate its result.

Missing, incomplete or conflicting custody remains unresolved. An error or lost
response does not prove absence, rollback, or permission to regenerate controls.
Positive database custody can recover committed originals, but cannot recover
pre-delivery originals that were never committed to that database.

Durable pre-delivery retention, public orchestration, historical recovery
authority, uncertainty reconciliation and terminal execution remain pending.
Actual service/registry startup gates and the absence of verifier persistence
are unchanged. Broad behavioral coverage and consolidated frozen-build
verification are deferred; no test, parser, interpreter, SQL or runtime
verification has run for this source implementation.
