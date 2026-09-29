# Committed policy file materialization

This source connects the actual controlled activation finalization to a separate,
fixed-path file materializer. Finalization already commits the active tuple and
candidate artifact; it does not retain the exact signed PolicyBundle file bytes.
The caller must supply those independently signed JSON originals. The new owner
authenticates them with the current policy signing trust, matches their policy
tuple and canonical bundle digest to the current protected artifact, and retains
the distinct SHA-256 of the exact supplied bytes. No policy is signed, activated,
or advanced by this route. The disabled legacy policy publisher stays disabled.

This is source-only integration, not a tested or provisioned service. It does not
establish a pilot, off-host rollback resistance, a migration, or broad O05 closure.

## Fresh public authority

All routes use the configured `POLICY_BUNDLE_PATH`; no request supplies a path.
`GET /api/policy/file-publication` is authenticated, data-only inspection. POST
routes require a current OIDC `policy_publisher`, CSRF and genuine cold control
plane custody. Requester and distinct approver each need currently admitted
hardware/YubiKey WebAuthn with user presence and verification, regardless of
optional ordinary MFA settings. Missing physical trust or controlled services
refuses; there is no runtime-DML fallback.

`POST /api/policy/file-publication/materialize` is exactly publicationId (32 lower
hex), policyOriginalBase64url, artifactEnvelopeSha256, expectedFileSha256, reason
and mfa. Expected file hash and reason are required but nullable. The decoded
original is at most 16 MiB, canonical unpadded base64url; the original JSON bytes
are retained, not reconstructed. Expected file hash refers to complete old file
bytes, or null for actual absence. The server genuinely verifies the supplied
bundle and derives the materialization binding:

`kind`, `publicationId`, `reason`, `policyOriginalSha256`, `policyId`, `sequence`,
`rollbackEpoch`, `policyHash`, `policyBundleSha256`, `artifactEnvelopeSha256`,
`expectedFileSha256`, with kind `materialize`.

`POST /api/policy/file-publication/resolve` is exactly publicationId,
intentSha256, outcome, reason and mfa. Its binding substitutes kind `resolve`
for mfa. Outcomes are `finalize-installed` and `abandon-uninstalled` only.
Bindings use sorted compact `ensure_ascii=True` JSON without LF, at most 8192
bytes. A binding hash is not verification or effect permission.

For either action, use the dedicated
`POST /api/policy/file-publication/webauthn/options` with apiVersion
`serverware.policyFileApprovalOptions/v1`, action `policy.file.materialize` or
`policy.file.resolve`, resourceId `active-policy-file`, payloadDigest, full
request binding and optional approvalId. The actual actor and row select
request, decide or consume. The response is the existing publicKey five-field
shape plus seven-field serverware metadata with this distinct profile/operation.
Generic mutation options explicitly refuse these actions.

MFA is `{publicationProfile: "serverware.policyFileApprovalOptions/v1", assertion}`;
the continuing requester also supplies approvalId. Initial submission creates a
real pending approval and returns the existing exact 428 continuation. The
distinct publisher uses `/api/control-plane/approvals/{id}/approve`, `note: null`
and fresh purpose MFA. After approval the requester obtains new consume options
and explicitly resubmits the exact materialization or resolution, not the old
assertion. No automatic retry is supplied. The admin-token profile is unchanged
and cannot authorize this purpose.

The controlled `policy-file-approval.request/decide/consume` operations use the
same seven closed argument names as the existing publication machinery, but
separate action, resource, `policy_publisher` role and provenance. Each genuinely
verifies raw assertion originals against current proved physical trust. The
eight-field `.settle` operation is audit-only over the exact consumed request and
local completion digest. It is not independent evidence of filesystem completion
and cannot perform another effect. See the
[wire schema](../schemas/control-plane-policy-file-publication.v1.schema.json).

## Actual current-authority serialization

The materializer uses a **separate** private PostgreSQL connection with the fixed
role `serverware_policy_file_materializer`. Its protected UTF-8 DSN file and
independent exact byte hash are configured by
`SERVERWARE_POLICY_FILE_MATERIALIZER_DSN_PATH` and
`SERVERWARE_POLICY_FILE_MATERIALIZER_DSN_SHA256`. It cannot use an elevated app
runtime role. No DSN or policy original is returned by these APIs.

The existing offline metadata bootstrap source installs
`serverware_metadata.serverware_policy_file_current_lock(text,text)`, a fixed
SECURITY DEFINER procedure owned by the existing metadata authority owner. The
role has schema USAGE and this function only: no table/sequence DML, schema
creation, TEMP, inherited membership or generic SQL selector. Runtime admission
checks effective privileges, function metadata, exact source body and owner.
Provisioning this separate role/connection and the updated authority source
contract remains an external deployment prerequisite; no grants were executed
while authoring this change.

The function takes the actual controlled-writer fence row in shared mode,
then the twelve fixed authenticated-table roots in the same C-collation order as
the writer, then fixed table SHARE locks. This conflicts with the real writer's
exclusive fence, not an invented advisory lock. It returns only the actual
current active high-water/publication/activation-finalization chain with complete
audit inclusion and its exact activation-attempt candidate artifact. Supplied
digests are equality expectations, never table/path/historical-row selectors.
The retained same-connection owner compares backend/transaction identity and all
originals through closing readback; lock, statement and idle waits narrow its
original allowance. The current profile supports committed activation artifacts,
not genesis or old-source/migration adapters.

## Protected one-shot transition

The operation owns the real request, actor, physical credential policy, wall and
monotonic clock, fixed parent, journal, old/new originals and staged inode. Its
30-second allowance opens on entry to the concrete publication owner, after HTTP
body decoding; this is not a pre-body time/resource claim. Challenge and approval
expiry only narrow it. The journal is the fixed sibling
`.serverware-policy-file-publications`, protected 0700 on the same device. Files
are exclusive, nofollow, single-link 0600. Actual parent EX|NB precedes journal
EX|NB, excluding a cooperating live publisher. Named and held identities and
exact original bytes are rechecked, including original inode custody across
rename; the expected ctime change is recorded as the actual final identity.

The ordered effect is:

1. Retain `.old` when present, immutable `.new`, sole `.stage` inode and `.intent`.
2. Durably publish `.claimed` with the exact intended consume request and audit
   association, then obtain one definite controlled consume result.
3. Open the separate authority connection, acquire actual writer-conflicting
   locks, and revalidate current tuple, artifact, signing trust and held files.
4. Perform the sole stage-to-fixed-target rename. Flush held file originals,
   both directories and exact `.complete` readback while authority locks remain.
5. Release the authority transaction before audit-only controlled settlement;
   durably append `.settled` and only then return the six-field success result.

The journal has at most 16 attempts and 160 retained files across ten suffixes:
old, new, stage, intent, claimed, complete, settled, resolution-claimed,
resolution-complete, resolution-settled. Each original is at most 16 MiB and each
canonical record at most 16 KiB. Intents anchor the exact predecessor terminal
digest and actual old identity. Histories are never pruned or rewritten. No
claim is proof of definite approval commit; a thrown/uncertain consume never
enters the rename path. The original allowance includes verification and scans;
these bounds are not a claim that every maximal input completes within it.

## Explicit interrupted outcome

A fresh resolution can only finalize an already-installed exact new original
(same staged inode and bytes, no stage name left) or abandon an intact not-installed
attempt with its exact unchanged old inode/bytes or absence and intact stage.
It requires the same current signed bundle/committed artifact and fresh separate
approval. A superseded policy, malformed/orphan history, identity mismatch, or any
existing resolution claim refuses. Resolution never renames, regenerates, deletes,
restores, or returns policy bytes. It adds only resolution-claimed,
resolution-complete and resolution-settled records after the same definite
consume/authority/readback sequence. Interrupted resolution is not replayable.

Only a settled original completion or settled resolution is a terminal anchor
for a later independent publication. The active PolicyBundle loader checks the
journal before loading and again against its actual file identity before returning
either cached or new snapshots. Unresolved, malformed, locked, or mismatching
state fails closed. An abandoned old file still must pass the normal current
high-water check; abandoning does not reactivate its retired policy. Exact current
originals must then be independently materialized under a new approved attempt.

The result/inspection does not prove consumer reload, distributed convergence,
external audit delivery or persistent service availability. Missing separately
provisioned authority, physical trust or exact policy originals is not repaired by
this path. Full activation recovery, multi-host coordination, coherent off-host
rollback protection and unrelated filesystem publishers remain separate work.
