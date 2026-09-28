# Durable consume originals

Source integrated, unbuilt and unexecuted. These dedicated local records retain
only token-free claims and exact consume planning, authorization, grant,
reservation, unsigned SQL and completion-response originals. They are not
permission, signed-plan admission, private replay, committed SQL or authenticated
completion evidence, token release, a public route or a retry mechanism.

## Closed inventory and association

One separate logical consume claim has at most nine physical files:

| Fixed kind | Exact retained content | Ordering |
| --- | --- | --- |
| `claimed` | Current source revision, retained finalization `localDigest`, actual activation caller-authorization digest | Durably published before the first prepare request |
| `prepared` | raw6: `prepared`, canonical consume request, canonical scope, signed consume plan, plan digest, journal digest; or `uncertain` and five empty frames | Retained before interpreting the response; genuine plan admission must also finish before export |
| `exported` | raw7: `exported`, the same request/scope/plan, encrypted execution bundle, plan digest, journal digest; or `uncertain` and six empty frames | Only after the retained `prepared` response; retained before interpreting or returning the export |
| `authorized` | raw1: original signed consume caller authorization | Only after a successful `exported` predecessor and actual same-call signing; durably retained before return |
| `grant` | raw1: original signed consume grant | After `authorized`; retained before independent control interpretation and reservation |
| `reserved` | raw3: signed consume reserve request, computation snapshot, state ACK | After `grant`; retained before interpretation and the one-use SQL claim |
| `sql-claimed` | raw0 | After `reserved`; durable before the sole SQL request, never idempotent permission to resend |
| `sql-outcome` | raw4: actual unsigned `observed-commit` or `uncertain` response, bounded IDs/marker | After `sql-claimed`; retained before status, ID or marker interpretation; not a commit proof |
| `completion-outcome` | raw4: `acknowledged`, completion-request digest, signed completion request, state ACK; or `uncertain` and three empty frames | After `sql-outcome`; retained before status, ID or signature interpretation; not an admission or retry token |

The fixed slot identity frames both the finalization locator and the genuine
activation authorization identity under
`serverware.controlPlaneOidcSessionActivationConsumeSlot/v1`. A separate
finalization-target index rejects a second claim even if the authorization
changes. The caller derives that authorization digest from its actual signed
original, not a selected future plan. Neither source revision, clock nor token
changes create another permitted preparation.

The journal requires the same live owner that created the activation dispatch
claim and its complete retained stage prefix through `completion-outcome`.
That metadata requirement does not authenticate an acknowledgment: the actual
still-active caller must separately verify completion, admit the fresh
root-signed planner/history originals, and bind the exact target and old-token
possession before claiming and sending. No recovered context resumes this
operation. The journal does not repeat private replay or reread large activation
originals inside an uncharged callback.

The binary codec has exact magic `SWCOC001`, fixed kind/count, bounded ASCII
source revision, two raw SHA-256 identities, fixed length vector, exact immutable
bodies and exact EOF. Each kind uses a separate content-identity domain. It uses
the actual consume-planner raw6/raw7 response bounds; a verify-retained raw6 is
not a prepared response. Appended profile index 3 bounds raw1 to the actual
consume caller's `MAX_AUTHORIZATION_BYTES` (64 KiB), with a two-byte minimum.
Earlier profile indices, domains and byte encodings are unchanged. The new
profile stores only the signed source-control original, not separate request,
expectations or private inputs. Its shape/content digest does not authenticate
the signature, permit another signing attempt or confer grant authority.
Profiles 4–7 append grant, reserved, SQL claim and SQL outcome. Their fixed
raw1/raw3/raw0/raw4 counts use the actual dedicated consume authorizer,
reservation and SQL response grammars and aggregate limits. The raw0 claim has
no selectable payload. Earlier profile bytes remain unchanged; no generic
grant, reservation or SQL family is widened.
Profile 8 appends the actual consume-completion raw4 response grammar. An
acknowledged response has a 71-byte canonical completion-request digest, a
signed completion original of 2 bytes to 256 KiB and a state ACK of 2 bytes to
16 KiB; uncertainty has three empty bodies. The ID is not a pending or packet digest. Maximum response
bodies total 278,611 bytes; maximum framed retention is 278,974 bytes, including
the bounded source revision and four lengths. The actual transport validators
admit shape only, never the original signatures or remote currentness.
New publication requires the current source cohort;
decode accepts historical source metadata only as ordinary data. There is no
generic prepared/forwarding-family extension.

No old/new token, assertion, permission original, cookie, private key, decrypted
bundle or prepare request is retained. The export's encrypted execution bundle
is an original ciphertext, not plaintext or authority.

## Exact APIs and metering

`ControlPlaneCustodyClient` and `CustodyJournal` expose these keyword-only APIs:

- `claim_oidc_session_activation_consume_planning(finalization_digest=..., activation_authorization_digest=..., source_revision=...) -> slot_digest`
- `append_oidc_session_activation_consume_prepared(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `append_oidc_session_activation_consume_exported(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `append_oidc_session_activation_consume_authorized(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `append_oidc_session_activation_consume_grant(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `append_oidc_session_activation_consume_reservation(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `claim_oidc_session_activation_consume_sql_attempt(finalization_digest=..., activation_authorization_digest=...) -> None`
- `append_oidc_session_activation_consume_sql_outcome(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `append_oidc_session_activation_consume_completion_outcome(finalization_digest=..., activation_authorization_digest=..., originals=...) -> record_digest`
- `load_oidc_session_activation_consume_records(finalization_digest=..., activation_authorization_digest=...) -> ConsumeRecords`

`ConsumeRecords(claim, prepared, exported, authorized=None, grant=None,
reservation=None, sql_attempt=None, sql_outcome=None, completion_outcome=None)`
is ordinary retained data, with optional stage records. Each `ConsumeRecord` contains source revision,
finalization and authorization digests, slot digest, kind, original tuple and
content digest. None is a successful-admission carrier.

Before the stable native custody callback, the genuine caller precharges
`control_plane_oidc_session_activation_consume_records.MAX_CLAIM_IO_BYTES`
for the planning claim, or `_append_io_bytes(kind, originals)` for each fixed
stage: `prepared`, `exported`, `authorized`, `grant`, `reserved`, `sql-claimed`,
`sql-outcome` or `completion-outcome`. SQL claim passes the exact empty tuple
`()` to the meter.
`MAX_AUTHORIZED_BYTES`, `MAX_GRANT_BYTES`, `MAX_RESERVATION_BYTES`,
`MAX_SQL_CLAIM_BYTES`, `MAX_SQL_OUTCOME_BYTES` and
`MAX_COMPLETION_OUTCOME_BYTES` expose their framed bounds;
`MAX_LOAD_IO_BYTES` includes the complete optional suffix. Old prefixes load
with absent suffix fields set to `None` and gain no publication, signing or
SQL permission. The exact work ledger and actual current guard remain around
each callback. The charge includes the fixed activation-claim read, the consume
claim read where needed, and bounded publication/readback or existing-slot
comparison. The append helper uses actual body sizes plus maximum framing, not
an unbounded old record. Prior large records receive immutable identity checks
without silently rereading their bodies. A separately authorized future
read-only history caller precharges `MAX_LOAD_IO_BYTES`; load never opens a
clock, creates a work allowance or restores continuation authority.

## Durability, quota and terminal uncertainty

The existing no-replace publication, file and directory synchronization, normal
close, exact readback and immutable identity checks apply to all nine files.
An identical response append is only first-exact local retention, never
permission to repeat a network request. A different original poisons the owner.
An uncertain prepared response cannot acquire an export sibling, and an
uncertain export cannot acquire an authorization sibling. A failed guard cannot
be restored by retaining a response. A claim is never repeatable, including
after restart or with another authorization.
The fixed SQL claim is independently non-repeatable even within the same live
owner; it is durably published before network I/O. An identical old SQL claim,
missing outcome or unsigned uncertainty cannot authorize another SQL request.
An exact SQL outcome may be retained once after the actual call; storage does
not authenticate its commit marker or prove nonexecution.
The completion sibling requires the exact SQL-outcome prefix but neither SQL
status grants authority. It can retain the actual completion response after
either bounded SQL status; storage does not authorize that network call or
turn unsigned uncertainty into a commit. Completion uncertainty is retained
unchanged, never rewritten as success or used to permit a resend.

Recovery validates the fixed prefix, claim/source/target association and
original response shapes, but deliberately does not restore the volatile
same-owner continuation set. Historical originals can only be read. Missing
responses, successful decode and exact old bytes cannot authorize prepare,
export, repeat signing, SQL, completion, automatic recovery or a resend. Every
dispatch-suffix stage requires this live owner's original activation and consume claims,
their exact current-source prefix and successful exported predecessor.

Every consume claim counts as one additional logical record alongside legacy
prepared records, release claims and activation claims, at every capacity gate
and during recovery. The activation claim still has at most seven files; the
separate consume claim now has nine, including the required SQL claim and
completion response. Live physical accounting is therefore exactly
`7 * maximum_records + 2 * admitted_consume_claim_count`: only that separately
counted namespace contributes two extra possible files. This does not widen
other codecs or give every old record nine slots. Unordered recovery first
limits scanning to the worst-case `9 * maximum_records`, then enforces the
tighter consume-specific ceiling and complete fixed prefix before admission.
The 4,096 logical-record limit, byte quota and 8 GiB maximum are unchanged.
Legacy marker byte reservations remain subtracted before new publication.
Capacity failure may leave a terminal partial prefix; no later storage or
effect is silently promised, and no record is removed to enable a retry.

Local durability does not establish current remote state, off-host rollback
resistance, consume execution, browser delivery or production readiness.
