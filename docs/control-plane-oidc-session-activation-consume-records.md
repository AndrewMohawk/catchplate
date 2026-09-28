# Durable consume-planning originals

Source integrated, unbuilt and unexecuted. These dedicated local records retain
only a token-free planning claim and the exact consume planner responses. They
are not permission, signed-plan admission, private replay, SQL/commit evidence,
token release, a public route or a retry mechanism.

## Closed inventory and association

One separate logical consume-planning claim has at most three physical files:

| Fixed kind | Exact retained content | Ordering |
| --- | --- | --- |
| `claimed` | Current source revision, retained finalization `localDigest`, actual activation caller-authorization digest | Durably published before the first prepare request |
| `prepared` | raw6: `prepared`, canonical consume request, canonical scope, signed consume plan, plan digest, journal digest; or `uncertain` and five empty frames | Retained before interpreting the response; genuine plan admission must also finish before export |
| `exported` | raw7: `exported`, the same request/scope/plan, encrypted execution bundle, plan digest, journal digest; or `uncertain` and six empty frames | Only after the retained `prepared` response; retained before interpreting or returning the export |

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
not a prepared response. New publication requires the current source cohort;
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
- `load_oidc_session_activation_consume_records(finalization_digest=..., activation_authorization_digest=...) -> ConsumeRecords`

`ConsumeRecords(claim, prepared, exported)` is ordinary retained data, with
optional response records. Each `ConsumeRecord` contains source revision,
finalization and authorization digests, slot digest, kind, original tuple and
content digest. None is a successful-admission carrier.

Before the stable native custody callback, the genuine caller precharges
`control_plane_oidc_session_activation_consume_records.MAX_CLAIM_IO_BYTES`
for the claim, or `_append_io_bytes("prepared"/"exported", originals)` for
the response. The exact work ledger and actual current guard remain around
each callback. The charge includes the fixed activation-claim read, the consume
claim read where needed, and bounded publication/readback or existing-slot
comparison. The append helper uses actual body sizes plus maximum framing, not
an unbounded old record. Prior large records receive immutable identity checks
without silently rereading their bodies. A separately authorized future
read-only history caller precharges `MAX_LOAD_IO_BYTES`; load never opens a
clock, creates a work allowance or restores continuation authority.

## Durability, quota and terminal uncertainty

The existing no-replace publication, file and directory synchronization, normal
close, exact readback and immutable identity checks apply to all three files.
An identical response append is only first-exact local retention, never
permission to repeat a network request. A different original poisons the owner.
An uncertain prepared response cannot acquire an export sibling; the caller
also treats every uncertain response or failed guard as terminal. A claim is
never repeatable, including after restart or with another authorization.

Recovery validates the fixed prefix, claim/source/target association and
original response shapes, but deliberately does not restore the volatile
same-owner continuation set. Historical originals can only be read. Missing
responses, successful decode and exact old bytes cannot authorize prepare,
export, automatic recovery or a resend.

Every consume claim counts as one additional logical record alongside legacy
prepared records, release claims and activation claims, at every capacity gate
and during recovery. Its three files do not become an eighth activation file.
The activation logical claim still has at most seven files; this distinct
logical claim has at most three. Therefore the existing
`7 * maximum_records` physical ceiling remains sufficient without increasing
the 4,096 logical-record limit, byte quota or 8 GiB maximum. Legacy marker byte
reservations are unchanged and still subtracted before new publication.
Capacity failure may leave a terminal partial prefix; no later storage or
effect is silently promised, and no record is removed to enable a retry.

Local durability does not establish current remote state, off-host rollback
resistance, consume execution, browser delivery or production readiness.
