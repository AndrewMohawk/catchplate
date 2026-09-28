# Durable activation originals

Source-only, unbuilt and unexecuted. This is local retention for the private
activation coordinator, not a public route, replay verifier, completion proof
or token/cookie transition.

The existing [dispatch claim](control-plane-oidc-session-activation-dispatch-attempt.md)
irrevocably selects the exact retained finalization `localDigest` before the
planner socket. It also fixes the permission-request binding, authorization
enrollment and source revision. The new codec and custody facade preserve this
target beneath five closed, ordered, first-exact stage slots:

| Kind | Exact originals | Must precede / follow |
| --- | --- | --- |
| `prepared` | raw5: caller authorization, signed plan, encrypted bundle, canonical expectations, complete before-vector | After genuine live permission/planning/original authorization; before grant request |
| `grant` | raw1: original signed grant | After actual caller-side grant control admission; before reserve request |
| `reserved` | raw3: signed reserve request, canonical computation snapshot, state ACK | After actual original control admission; before SQL claim |
| `sql-claimed` | raw0 | Durable before the sole SQL request; never idempotent permission to resend |
| `sql-outcome` | raw4: actual unsigned SQL response | Retained before interpreting the response; not a verified commit |

The codec uses the actual activation authorizer, reservation and SQL framing
bounds, the original complete-vector limit, and a 64 MiB aggregate prepared
body bound. Its closed binary frame includes the source revision, finalization
locator, kind, fixed count and lengths, exact original bodies and exact EOF.
Each kind has a separate content-identity domain. New publication requires the
current source revision; decoding preserves an old source as ordinary data.
No permission assertion, pending cookie, old/new token, signing key or decrypted
bundle is retained. Shape checks cannot authenticate the supplied originals;
the actual same-call coordinator owns permission, independent expectations,
signature/control verification and the current processing guard.

## Fixed APIs and metering

`ControlPlaneCustodyClient` and `CustodyJournal` expose:

- `append_oidc_session_activation_preparation(finalization_digest, originals)`
- `append_oidc_session_activation_grant(finalization_digest, originals)`
- `append_oidc_session_activation_reservation(finalization_digest, originals)`
- `claim_oidc_session_activation_sql_attempt(finalization_digest)`
- `append_oidc_session_activation_sql_outcome(finalization_digest, originals)`
- `load_oidc_session_activation_records(finalization_digest)`

Append returns only a local content digest; claim returns `None`. Load returns
ordinary `ActivationRecords(source_revision, finalization_digest, prepared,
grant, reservation, sql_attempt, sql_outcome)`. Each optional `ActivationRecord`
contains its original bytes and local digest, not a successful-admission DTO.
No loader sends, resumes a workflow or authenticates a current remote state.

Before each stable native custody callback, the caller charges
`control_plane_oidc_session_activation_records._append_io_bytes(kind, originals)`
on the same actual work ledger and runs its actual current guard before and
after. The helper reserves three actual-body-sized frames with the maximum
source header plus the fixed original-claim read. It performs no hashing or
I/O. Existing-slot comparison cannot read a larger record than this charged
carrier. Prior slots receive immutable file-identity checks; their large bodies
are not silently reread on every append. A future independently authorized
read-only recovery caller precharges `MAX_LOAD_IO_BYTES` before loading the
bounded prefix. None of these helpers opens a clock or work allowance.

## Durability, capacity and uncertainty

Publication uses the existing no-replace write, file sync, directory sync,
normal close and exact readback. An identical ordinary stage is first-exact;
different bytes poison the owner. Every stage requires its preceding fixed
prefix and unchanged claim source. SQL claim is always non-repeatable, even
within the same owner. I/O or readback uncertainty poisons the journal; records
are never removed to permit another attempt.

Only a dispatch claim successfully created by this live journal owner permits
stage publication. Recovery restores originals for reads but deliberately does
not restore that volatile continuation allowance. Thus a recovered claim or
missing SQL outcome cannot authorize resuming dispatch or making a new SQL
claim. A future recovery action needs its own independently authorized design;
this library supplies no automatic retry or reissuance.

One activation logical claim owns exactly six possible physical files: its
claim plus these five stage slots. This is below the existing seven-file
allowance per logical record. The unchanged logical limit counts each
activation claim alongside prepared records and release claims; old families
already use at most seven files each. No new namespace creates another logical
slot or bypasses the unchanged `7 * maximum_records`, quota, 4,096-record or
8 GiB ceilings. Legacy marker byte reservations remain intact. Capacity failure
can leave a terminal partial prefix; it never grants a retry. No space is
silently promised for later observations.

These are dedicated nonforwardable namespaces, not additions to generic
prepared/forwarding dispatch. Local content identity and filesystem sync are
not permission, private replay, remote commit, off-host anti-rollback,
recipient acknowledgment or runtime/production acceptance.
