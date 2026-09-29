# Finalized-genesis policy file publication

This additive source path publishes the first protected policy file. It does not
create authority, sign policy, run activation or infer genesis from missing files.
No runtime, role provisioning, hardware ceremony or interruption testing was run
for this source-only slice. O05 is not complete.

## Positive authority

The existing genesis producer must already have independently verified its signed
`serverware.policyAuthorityGenesis/v1` preparation, included its real transition
in the audit ledger, and finalized its committed publication/high-water tuple.
The new read-lock function positively joins:

1. Current high-water and committed publication with the same complete tuple.
2. Exact genesis preparation/finalization, the same high-water digest, and a
   finalization time within the original preparation validity.
3. Genesis signature evidence and installed trusted-key revision, with exact
   domain, signature, envelope, payload and record binding.
4. The genesis transition and signed audit-inclusion receipt, with its own
   signature evidence and independently installed key revision.

These are historical authenticated facts, not renewed effect permission. Fresh
publication approval supplies current permission. Superseded high-water,
unfinished genesis, or missing/divergent positive records refuse the effect.
Caller-supplied success metadata and local absence cannot substitute.

## Reachable cold maintenance, not a normal-startup exception

Normal production startup still requires an active signed policy file. First
publication instead uses the explicit root entrypoint argument
`control-plane --policy-file-genesis-maintenance`. Its source-fixed successor is
`serverware.control_plane_policy_genesis_runner`; no incoming request or plain
environment boolean can enter it. Both the normal runner and ordinary app lifespan
reject a maintenance custody profile. The restricted runner never calls the
ordinary application lifespan or starts runtime, provider, release, CA publisher
or reconciliation workers.

The offline producer
`control_plane_policy_genesis_bootstrap.sign_configuration(configuration,
maintenance, runtime_root_private_key=...)` takes the existing v1 custody base
and an explicit ten-field maintenance object. It creates
`serverware.controlPlaneCustodyStartup/v3`, exact twelve fields, under the separate
`serverware/control-plane-policy-genesis-maintenance/v1` plus NUL domain.
The existing admitted root-owned sealed configuration FD is reused; no new
signing key, browser-selected root or secret descriptor is introduced. The
original signature covers the actual runtime configuration digest, source,
journal FD/identity/limits, exact genesis tuple/digests and protected DSN SHA.
The actual custody runtime-root key verifies it after permanent privilege drop.
Old v1/v2 bytes and cold selections remain unchanged and cannot enter this runner.

The signed interval is at most fifteen minutes, further clipped to the original
custody attestation interval. Its initial wall/monotonic deadline never renews.
Sealed configuration original/identity, actual custody/enrollment owners, and
independent RBAC witness startup are retained. Production auth/TLS/hardware/
two-person configuration checks are preserved. Before listening, a distinct
at-most-30-second read observes the positive current genesis chain under the
fixed read lock, then releases that connection; it is not a reservation or
permission for a later effect. Each file operation still has its fresh original
owner, authorization and fenced current-chain check.
Publication approval/options/decision/consume/settlement transports and the
filesystem owner are explicitly clipped to that same original maintenance
deadline, not merely sampled before and after a longer exchange.

The outer ASGI gate denies every route not in this source-fixed list before
ordinary handlers run:

- GET auth status, OIDC start/callback and CSRF; POST logout and existing-session
  WebAuthn options/verify.
- The fixed session activation/permission/confirmation and existing activation
  recovery/completion/release/delivery/consume paths. These retain their own
  genuine authentication owners; no new credential enrollment or generic
  control-plane execution endpoint is exposed.
- GET approvals, filtered to this exact genesis binding or its retained
  resolution intent; POST only a matching existing approval's `approve` route.
  Other actions and generic denial/mutation paths are refused.
- GET policy-file inspection; POST dedicated policy-file options,
  `genesis-materialize`, and `resolve`. An activation-materialize binding is
  refused. Resolution checks the actual retained intent, not a copied verdict.

There is no broad portal/business route, health-as-readiness claim, websocket,
fallback signed policy or automatic promotion. Operators use pre-enrolled genuine
hardware credentials and the existing authenticated HTTP ceremonies. After
durable settle, stop maintenance and perform a fresh normal startup, which checks
the actual installed policy and its journal. Original expiry leaves the listener
closed to operations; it never creates a fresh allowance. Explicit failure or
shutdown closes retained owners in reverse order and cannot reinitialize them.

The materializer verifies actual signed PolicyBundle bytes with current signing
trust and matches their compiled policy hash/tuple to the positive chain. Fresh
approval also binds the exact file SHA and canonical bundle SHA. Genesis has no
activation candidate artifact and does not impersonate one; the existing
activation-only role and function stay unchanged.

## Actual HTTP and approval path

`POST /api/policy/file-publication/genesis-materialize` requires exactly seven
fields: `publicationId`, `policyOriginalBase64url`, `genesisPreparationDigest`,
`genesisFinalizationDigest`, `expectedFileSha256` (explicit null), `reason`
(required nullable), and `mfa`. The whole HTTP body is bounded at 24MiB; the
unpadded canonical base64url original decodes to at most 16MiB. The source derives the twelve-field `genesis-materialize`
binding in `schemas/control-plane-policy-file-genesis.v1.schema.json`.

Use `/api/policy/file-publication/webauthn/options` with
`serverware.policyFileApprovalOptions/v1`, distinct action
`policy.file.genesis.materialize`, resource `active-policy-file`, complete binding
and its canonical digest. Current authenticated OIDC `policy_publisher` and CSRF
are required. Requester and a different publisher perform fresh hardware/YubiKey
UP+UV ceremonies; then the requester explicitly submits the same approved material
with a new consume assertion. Generic mutation options refuse this purpose.
Optional MFA for other actions is unchanged. The actual existing controlled
request/decide/consume/settle kernels retain the new action and original binding.
There is no assertion reuse, approval substitution or automatic request retry.

## Separate connection and writer fence

The fixed role `serverware_policy_file_genesis_materializer` has only schema USAGE
and `serverware_policy_file_genesis_lock(text,text)`. Offline protected-store
bootstrap admits no relation/sequence rights, inheritance, DML, CREATE, TEMPORARY,
generic SQL or activation access for it. Operators must provision this separate
role/connection; HTTP does not. The protected UTF-8 DSN file is selected by
`SERVERWARE_POLICY_FILE_GENESIS_DSN_PATH` and
`SERVERWARE_POLICY_FILE_GENESIS_DSN_SHA256`.

The owner retains actual named/held DSN identities and bytes, environment pins,
effective privileges and exact function metadata/source. The function takes the
real controlled-writer fence FOR SHARE, eight authenticated table roots in C
order, then fixed table SHARE locks. It retains the same connection and
backend/transaction identity through closing file readback. No advisory-lock or
caller-selected relation substitution is supported. Waits narrow the original
at-most-30-second HTTP owner deadline.

SQL chain originals are bounded at 16MiB and the canonical owner snapshot at
32MiB. Each genesis/inclusion envelope and payload original is at most 1MiB with
an independently checked SHA. Immutable originals remain in protected authority
storage; local intent pins their preparation/finalization digests and actual
signed bundle original. No expired historical record authorizes an effect alone.

## One attempt and truthful interruption

The configured target must be absent and the locked local publication journal
must have no attempts/predecessor terminal. Those are extra conditions only.
The owner may stage bounded originals and consume fresh approval before checking
the positive current genesis chain; a failure then remains unresolved and never
renames the target. A failed lookup is not genesis authorization or new-attempt
permission.

The real existing publisher retains the staged inode, immutable intent/originals,
durable one-shot claim, definite controlled consumption, sole rename, file and
both-directory fsyncs, completion readback, unlock and audit-only settlement.
Genesis may only be the root journal entry. Subsequent policy changes still need
the independent activation path and exact predecessor chain.

`GET /api/policy/file-publication` is authenticated read-only inspection. A retained
interrupted genesis intent uses separately approved `/resolve`; its original
binding selects the genesis owner, never a caller switch. The same current
finalized genesis and exact file/stage identities remain mandatory. Only
`finalize-installed` or `abandon-uninstalled` is admitted. Neither repeats rename,
deletes, restores, reconstructs or restages. Any local history, including an
abandoned first attempt, refuses a new genesis attempt. Missing acknowledgement
remains uncertain; missing/malformed local records do not prove noncommit.

Superseded-history resolution, migration, malformed/orphan repair, journal
archival, off-host rollback, distributed reload convergence and availability are
separate work. Clearing a journal or choosing another ID is not recovery
authorization. The full O05 acceptance scope remains open.
