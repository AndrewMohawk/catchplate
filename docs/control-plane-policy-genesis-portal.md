# Dedicated genesis-maintenance portal

This is source-integrated operator UI, not a tested pilot or production claim.
It is served at `/` only by the genuine `MaintenanceApplication` admitted through
the root-signed custody-startup/v3 `finalized-genesis-file-maintenance-v1` profile.
It is never the normal dashboard with disabled business buttons. The outer gate
continues to deny every unrelated route before the broad application's handlers
and suppresses its normal lifespan/workers. The normal runner does not acquire
maintenance authority or promote a settled maintenance process into service.

The page's additions are the two fixed POST routes
`/api/policy/genesis-maintenance/context` and `/review`. They authenticate the
actual OIDC policy publisher and cookie CSRF before accepting an upload. The
original cold owner, current authenticated ceremony owner and original clipped
maintenance window are retained and rechecked. No incoming endpoint, trust root,
key, DSN, target path or success flag selects authority. Context projects only
the signed six-field genesis target, original expiry and a bounded, scoped
approval queue. It does not refresh the startup's positive finalized-genesis
read or reserve the current tuple against future writers.

## Operator flow

1. Start the explicit cold maintenance command with independently provisioned
   roots, delivery, finalized genesis and separate read-lock role as described
   in [the genesis guide](control-plane-policy-file-genesis.md). Use genuinely
   enrolled OIDC participants with the current `policy_publisher` role. The page
   offers existing-passkey session binding once, plus read-only session status;
   it does not add enrollment, lost-key recovery or a fallback identity. A lost
   session-binding result is not resent. Use a separately usable session if
   current authenticated status cannot be established.
2. Read the original cold target and choose the exact signed policy file. Review
   verifies the actual signature/schema/compiled policy identity with the same
   admitted trust as publication, matches the cold genesis tuple, and returns
   the exact canonical binding and original-file SHA. The page displays the
   complete original text and exact canonical target/reason/action. Both actors
   explicitly confirm review; that checkbox is usability, never server authority.
3. The requester explicitly obtains fresh purpose-specific options, performs a
   hardware UP+UV ceremony, and sends the existing genesis-materialize endpoint
   **without** an approval ID once. Its exact 428 approval-required response is a
   pending approval, not a filesystem outcome. Copy the approval ID or recover
   it from the scoped queue with the actual requester/target/payload digest.
4. A different authenticated operator selects the same signed file and exact
   approval ID. The server reads the actual retained purpose-specific original;
   the page shows its requester and binding. New `policy-file-approval.decide`
   options and a fresh hardware assertion go to the existing approval route,
   with null note. No generic approval, copied assertion or approval-by-self is
   substituted. The backend independently enforces current roles and difference.
5. The requester explicitly reviews the actual approved row, rechecks the same
   original binding and different approver, then obtains NEW consume options and
   a NEW assertion. The existing materialization owner still performs the real
   durable claim, definite approval consumption, finalized-genesis current lock,
   one rename, exact readback, durability and separate audit settlement. Preview,
   HTML, a hash or a returned approval DTO cannot manufacture that owner.

There is no automatic action chain. Browser options, WebAuthn, body reads and
each handoff share one 30-second local operation allowance, clipped further by
the actual server's original maintenance authority. Review has its own bounded
read-only allowance and cannot renew writer authority. A signature verification
running in a worker thread is checked after return; the timeout is not a claim
of hard preemption. All real effect owners and their deadlines remain unchanged.

## Interruption and exact resolution

Before a handoff the page retains a bounded nonsecret tab-local hint and reads it
back. It never persists policy bytes, assertions, cookies, tokens, keys or DSNs.
Changing a file, reason, selected outcome or approval does not clear a sent
action's lock. Page reload retains these locks. Storage failure blocks effects.
These are user-interface protections, not global concurrency authority: the
protected backend journals and one-use approvals remain the cross-tab/process
authority. Clearing browser storage cannot grant a backend retry.

A lost approval response is inspected through the actual scoped queue and exact
approval review. Queue truncation, missing entries or malformed data never prove
noncommit; an exact known ID can be reviewed even if outside the latest 64 rows.
A lost materialization/decision/resolve response never enables resubmission.
Use the unchanged protected file/journal inspection endpoint; retain the exact
publication ID and intent SHA. A missing association is UNKNOWN. Inspection
cannot unlock a sent action, delete an intent or restore a predecessor.

To resolve, explicitly choose `finalize-installed` or `abandon-uninstalled` for
that retained intent and provide the same signed file. Read-only review derives
the actual underlying material from protected history and verifies the original
against it. The resolution has its own fresh requester, distinct approver and
consume ceremonies using the unchanged backend resolution endpoint. It does
not repeat rename/staging, and definite installed/uninstalled admission remains
the actual resolver's responsibility, not a radio button or browser observation.

Only an exact successful effect result or settled matching terminal inspection
produces the prominent RESTART REQUIRED message. `abandon-uninstalled` does not
provision a usable file or authorize another genesis attempt. On materialization
success, stop maintenance and perform a fresh normal startup; no automatic
promotion, fallback policy, CA/trust rewrite or restart request exists here.
If maintenance authority expires first, its gate refuses further requests;
observations are never accepted as replacement authority.

## Closed boundaries and limits

- Context request<=1KiB; review request<=24MiB/4096 chunks and exact decoded
  original 1..16MiB; returned portal observations<=128KiB. Browser response reads
  are bounded 256KiB/1024 chunks. Server duplicate JSON keys are refused.
- Canonical binding strings<=8192 ASCII bytes preserve original i64 sequence
  values without JavaScript number round trips. Options embed these exact bytes;
  materialization sends the original uploaded bytes, never a reserialized file.
- Tab hints<=32 entries/64KiB. Whole signed files stay only in page memory and
  text nodes; the page uses a fixed-script SHA CSP, no external scripts, no
  `innerHTML` with returned/user data, no framing and no arbitrary network URLs.
- Existing first-publication semantics, separate role/function/writer fence,
  original cold startup versions and effect HTTP/approval contracts are unchanged.
  The [portal schema](../schemas/policy-genesis-maintenance-portal.v1.schema.json)
  describes only read-only inputs/observations, not a permission object.

Superseded-history migration, malformed/orphan repair, archival, multi-host
rollback/reload convergence and availability remain separate work. Neither this
portal nor the held backend proves runtime behavior or closes all O05 scope.
