# Durable public WebAuthn revocation

This source path connects the public passkey-revocation route to the actual
protected successor issuer, executor, committed-state readers and terminal
delivery owner. It is not a diagnostic or a replacement SQL implementation.
It has not been built, executed, provisioned or tested by this source change.
Other revocation purposes, including provider OAuth cleanup and trust-wide
revocation, remain separate. This is not a claim that all O03 work or production
acceptance is complete.

The current portal still emits legacy revocation and approval bodies. Its typed
self/admin target review, explicit MFA/approval ceremonies and retained recovery
UI are not connected yet. A completely lost execution response also needs an
authenticated read-only options-to-attempt lookup before a browser can discover
the genuine retained recovery locator. The server endpoints below do not close
those operator-flow gaps or authorize automatic retry.

## Explicit admission and unchanged old profiles

The new measured authorization is
`serverware.publicWebAuthnRevocationAuthorization/v1`. It carries the actual
authenticated actor, independently enrolled current mutation policy, exact
payload commitment, optional real assertion, and optional separately approved
row original. Its plan, planner response, signed plan and snapshot use explicit
v5 domains; its complete proof bundle/read-write transition and retained-plan
header use distinct v2 profiles. Existing v4 assertion-only evidence, bytes,
SQL sidecar and mandatory-assertion guards are not reinterpreted. Public v5 uses
the existing `SuccessorExecutionIssuer`, `SuccessorExecutionExecutor`,
`SuccessorExecutionRecoveryReader`, `CurrentRootCommitReader` and
`CurrentRootCompletionDelivery` path, not the v4 sidecar.

The HTTP request owner retains the actual FastAPI request/scope/headers and
bounded original body, current configured authentication/CSRF and policy,
same-process/thread custody and cold key owners, original enrollment bytes and
one absolute processing deadline. It rechecks actual current requester roles
until its single execution handoff. Existing static/bearer/OIDC authentication
modes are preserved. Admins may revoke another operator's credential; an
eligible non-admin requester may revoke only their own. OIDC roles are also
rechecked from authenticated current prestate in the kernel.

MFA is required exactly when configured and independently enrolled. Disabled
MFA is explicit null, not a fabricated assertion. Enabled MFA verifies the
actual browser response against the issued challenge, selected credential,
RP/origin, configured authenticator policy, current trust and counter. Two-person
approval is similarly conditional. A required approver must be a current admin
different from the requester. No browser supplies trust roots, keys, endpoints,
SQL roles or DSNs. Root enrollment and configured mutation policy must match.

Approval creation and decision have four explicit source operations:
`public-revocation-approval.request-identity`, `.request-asserted`,
`.decide-identity`, and `.decide-asserted`. The cold caller enrollment lists all
four; current policy selects the permitted pair. Only an actual verifier owner
holding and rechecking the original caller signature can enter their existing
protected v3 writer path. The generic operation API cannot supply that owner.
These operations do not revoke a passkey. Final v5 revocation proves the actual
approved row, policy, requester, distinct approver and nullable/real evidence
provenance, and consumes it atomically with the cascade.

## Cold operator inputs

Cold selection is additive, never inferred from an HTTP body:

- `signedControlPlaneEnrollmentBootstrap/v23` adds the required
  `publicWebAuthnRevocation` field (explicit null disables it). A nonnull scope
  pins three original independently signed enrollments and the source-fixed
  current-root endpoint. The dedicated actual caller private key is FD 208,
  separate from every authority role key.
- `signedCurrentRootStateBootstrap/v10` admits the fixed actual verifier head,
  issuer reserve, and executor completion/original-lookup peers: UIDs/GIDs
  65520, 65521 and 65522. Existing state profiles remain unchanged.
- Each actual measured verifier/issuer/executor explicitly selects the
  `--public-webauthn-revocation` cold entrypoint flag and its additional rooted
  credential `serverware-authority-{role}-public-revocation`. The entrypoint
  retains its sealed original at FD 212; an ambient environment flag cannot
  select it. The stage-zero credential manifest must explicitly include that
  original. Old launch credential sets remain unchanged when not selected.
- `authority_public_revocation_terminal_bootstrap.produce_on_work` signs a
  separate root-approved terminal original, not a bootstrap generated from
  observed local state. `authority_public_revocation_caller_authorization`'s
  enrollment producer likewise requires independent root inputs. The scope
  joins the current-root computation key to the actual measured verifier key,
  completion key to actual executor response key, and grant-authorizer key to
  actual issuer response key. Existing measured configuration requires the
  verifier's response/signing SPKI identities to be equal.
- Terminal SQL access uses dedicated existing least-privilege successor
  issue/execute/recover/commit roles, each with its own root-pinned TLS originals.
  It never reuses the old authority service's differently privileged DSN.
  TLS files are fixed below `/run/serverware/public-revocation-tls/`:
  `ca.pem`, and `issue`, `execute`, `recover`, `commit` `.crt`/`.key` pairs as
  required by that role. The verifier adds no SQL credential. Endpoint, DNS/IP,
  role, TLS identity and query/structure manifests are independently admitted.
- Executor journals are preprovisioned service-owned 0700 directories at
  `/var/lib/serverware/authority-public-revocation/attempts` and `completion`.
  Protected ancestors, exact named/held device and inode, independent original
  sequence/head checkpoints, and capacity are retained. Startup does not create,
  repair or enroll a journal from its own observed head. No record is deleted.

The actual configuration must enable the four new approval operations on the
existing planner/issuer/writer path. Deployment must independently provision
the signed root closure, keys, descriptors, TLS/database roles, protected
directories and current checkpoints; this source does not generate local
self-authority. A new root-approved cold admission after expiry is distinct
from automatically renewing an outstanding effect. Source/generation migration
and unresolved historical checkpoint repair are not implicit recovery rights.

## Public route sequence

All requests are POSTs, use the actual current authenticated session/token and
applicable CSRF protection, and reject query strings. See the paired
[closed HTTP schemas](../schemas/public-webauthn-revocation-http.v1.schema.json).
Required nullable fields must be present.

1. If two-person approval is configured, request approval options at
   `/api/control-plane/mutations/webauthn/options` using
   `publicWebAuthnRevocationApprovalOptionsRequest/v1`, action
   `webauthn.credential.revoke`, resourceId, reason, null approvalId and either
   the current caller's credentialRecordId or null when MFA is disabled. Submit
   its actual retained localDigest and real assertion/null with
   `publicWebAuthnRevocationApprovalSubmitRequest/v1` to
   `/api/webauthn/credentials/{id}/revocation/approval/request`.
2. A different admin obtains the same approval-options profile with the genuine
   approvalId and their own credential/null, then submits that options identity
   to `/api/control-plane/approvals/{approvalId}/approve`. The operation proves
   the current pending row and cannot approve an inferred or supplied receipt.
3. Call `/api/webauthn/credentials/{id}/revocation/options` with
   `publicWebAuthnRevocationOptionsRequest/v1`, reason, actual approved approvalId
   or null, and credentialRecordId or null. The server retains the exact target,
   semantic request, policy, approval original, and actual challenge. Cascade
   row IDs here are only bounded selection hints; later authenticated complete
   predicates prove there are no omitted live rows.
4. Submit `publicWebAuthnRevocationExecuteRequest/v1` to the existing
   `/api/webauthn/credentials/{id}/revoke` with the returned localDigest, unchanged
   reason and actual MFA response/null. The local attempt is durably burned
   before its first authority contact. Explicit cold selection refuses old
   request profiles rather than falling back to legacy mutation.
5. On interruption or an unknown result, use
   `/api/webauthn/credentials/{id}/revocation/recover` with
   `publicWebAuthnRevocationRecoveryRequest/v1` and the retained **attempt**
   localDigest, not its earlier options identity. This authenticates the current
   requester or an admin. If the revoked credential also ended the requester's
   session, use a separate still-valid authorized session/admin; the old session
   is not reactivated. An unknown response never requests automatic resubmission.

Approval TTL is separately configured (bounded to one hour). Each options,
approval submission, decision and final execution has its own freshly admitted
request, but an individual operation never renews its original <=30-second
window. Challenge/approval/cold expiry can only shorten that window. After the
single final handoff, response publication retains the admitted original even
if this cascade revoked its own session; that continuation can only complete
the same result, not grant another effect.

## Durable effects and truthful recovery

Preparation retains the original caller enrollment/authentication and exact
request, complete root vector, fresh signed current-root head, full plan and
historical context. Current-root pending work refuses a competing revocation.
Independent grant admission and original plan replay precede reservation.
The exact computed reserve request/snapshot is retained before reserve contact;
the protected signed reserve acknowledgement is retained separately. Actual
packet locators are reproduced and retained **before** issuer/executor contact.
The executor's own durable attempt precedes its SQL transaction.

The atomic successor mutation includes the actual credential revocation,
complete live bound-session/grant/approval cascade and registration-challenge
invalidation, optional real assertion counter/challenge CAS, required approval
consumption, audit and authenticated root transitions. No partial row list or
caller count establishes completion. A direct SQL acknowledgement is not the
public terminal result: separate restricted committed-state readback and
authenticated original completion delivery must establish it.

Custody uses distinct `SWCPV001` records with length vectors checked before body
slicing. HTTP admission is 64 KiB (not a promise to preempt FastAPI's earlier
body allocation); caller authorization/recovery originals are 64 KiB, caller
enrollment 16 KiB, preparation history 16 KiB, terminal bootstrap 512 KiB.
Frames/stage originals have a combined 64 MiB ceiling plus bounded headers,
with fixed per-component caps; journals keep their existing record/capacity
limits (terminal journals at most 4096 records). One cumulative validation
meter is retained in each actual operation; helpers do not reset it. A work,
clock, capacity or ownership failure refuses, and does not infer no effect.

`committed-observed` requires original-byte successor packet/plan replay,
actual restricted committed state, and signed completion/receipt association.
Recovery uses a separately signed **read** purpose and current read allowance;
it cannot reserve, issue or execute again. Missing pre-contact acknowledgements,
incomplete original associations, malformed history, expiry and lookup failures
remain unresolved. A locally unattempted observation is not proof of remote
absence. No recovery path replays a stored SQL attempt.

Approval-only lookup uses its actual retained options/request to identify the
row and can report `approval-row-observed`, `outcome-unknown` or
`locally-unattempted`. It explicitly reports `committedObserved: false` and
`revocationExecuted: false`; it neither reconstructs a missing approval-writer
acknowledgement nor treats a current row as permission. Final v5 execution
independently authenticates and consumes that real row. Read-only inspection
does not reset attempts, repair journals or authorize another effect.

The [aggregate schema](../schemas/public-webauthn-revocation-authorization.v1.schema.json),
[independent caller enrollment](../schemas/public-webauthn-revocation-caller-enrollment.v1.schema.json)
and [cold scope/terminal schema](../schemas/public-webauthn-revocation-cold.v1.schema.json)
describe wire shapes, not authority. Browser UX, deployment provisioning,
failure-injection/runtime acceptance and any separately authorized history
migration/repair remain distinct from this source connection.
