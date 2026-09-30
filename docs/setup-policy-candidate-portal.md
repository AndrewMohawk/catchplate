# Protected Setup association and separately approved policy publication

The owner-facing panel connects the actual activated Setup revision 3 to a
completed protected native generation through `setup.policy.bind-candidate`.
The association alone does not load policy, authorize a proxy, finish a canary or complete Setup. The separate publication controls below invoke the real existing materializer and a control-plane-only installed observation; neither is native gate readiness.
Source is unbuilt and unexecuted; no browser/provider/runtime acceptance is
claimed. The independent authority/kernel continuation is integrated in the
same batch, without widening the old OAuth four-event mutation contract.

The four existing association POST routes live under `/api/setup/policy-candidate`:

- `/draft` takes `apiVersion`, `sessionId`, `expectedRevision: 3` and
  `generationRequestId`; it reads actual Setup and completed generation claim
  rows and returns exact `argumentsOriginal` plus the reviewed assignment.
- `/options` admits the same canonical original string and creates a genuine
  purpose-bound hardware WebAuthn challenge.
- `/bind` accepts those unchanged bytes and a dedicated `setupPolicyProfile`
  assertion, dispatches once, then reads back the exact protected result and
  `continuationOriginal`. The continuation is revision 0; Setup stays revision 3.
- `/lookup` takes only the fixed request label and session ID. It returns a
  read-only continuation original or null, always `okForAction: false` and
  `automaticRetryAllowed: false`. Missing association after a lost response is
  unknown, never proof that a dispatch can be repeated.

Every association route requires a genuine current OIDC cookie, exact Origin and CSRF,
literal `credential_owner`, and the actual Setup owner. An administrator
override, bearer token, publisher role or assignee alone is insufficient.
The owner retains the actual request/scope/process/thread, cold custody owner
and same signed configuration snapshot. Original Setup and generation rows,
credential policy and physical authenticator trust are rechecked through the
one operation. The original argument deadline is at most 30 seconds and is
clipped to the unchanged Setup expiry; subsequent browser/options/bind requests
cannot renew it. Only the protected writer mutates continuation state. Challenge
creation uses its existing controlled authority operation, never direct DML.

The protected kernel separately requires the actual old activation event,
completed linked audit outbox, active version-1 credential/open currentness,
and genuine current candidate/native-publication originals. Waiting for audit
or missing prerequisites remains a refusal; these routes do not call a legacy
transition to manufacture success. Draft SQL reads are reviewed observations,
not substitutes for those authenticated atomic checks. A stored continuation is
never converted into a loaded-policy or proxy-ready permission.

The page preserves nanosecond-bearing argument bytes as a string and uses the
existing exact-integer codec for display/validation, never Number round-tripping.
It retains the draft only in memory, requires explicit review and a fresh
passkey, and sets a session-storage marker containing only nonsecret actor,
session and generation recovery IDs before the irreversible handoff. Assertions
and authorization originals are never stored. The marker is only a local
anti-repeat aid, not server authority or a durable completion receipt. Lost
responses lead to the separate read-only lookup; no automatic retry is offered.

Closed HTTP shapes are in `setup-policy-candidate-http.v1.schema.json`.
The independently signed authority configuration must explicitly admit
`setupPolicyContinuationPolicy`: its closed authority-policy shape binds the
control-plane configuration, hardware credential policy, maximum operation
duration and original argument bound. Both verifier and planner re-admit it.
One immutable `setup_policy_continuations` row per Setup session is inserted
atomically with actual assertion consumption and audit. The six complete
generation/trust populations are reconstructed against authenticated before
roots; existing 32-row population limits and global proof limits are unchanged.
No runtime DML, historical claim-window renewal, mutable policy-file proof or
automatic successor replacement is introduced. Existing databases require
explicit schema/root migration; this source change performs no migration.

Canonical arguments are <=2 MiB; escaping is included in the complete
4 MiB+32 KiB request bound. Continuation originals are <=2,170,880 bytes and
complete responses are <=5 MiB. A larger original is refused, not truncated.
The exact bind response is the controlled writer's six fields, including the
continuation original, with no added readiness claim.

## Actual publication continuation

Two additive owner-bound POST routes use the exact three fields `{apiVersion: "serverware.setupPolicyMaterializationRequest/v1", sessionId, expectedRevision: 3}` (raw request <=4096 bytes). They reconstruct the actual protected candidate-bound continuation0 and completed generation; they do not run the expired original bind request again. Old Setup revision3 and the four association routes remain unchanged.

- `/materialize-draft` additionally requires the literal `policy_publisher` role. It verifies the actual signed candidate and current committed artifact/high-water, rechecks the real publication journal and existing target-file digest, and returns exact6: `apiVersion`, `okForAction:false`, `automaticRetryAllowed:false`, `continuationOriginal`, `requestOriginal`, `bindingOriginal`. It generates one actual publication ID and `reason:null`; the exact body contains the signed candidate bytes, artifact pin and nonnull existing-file pin. Missing file, incomplete journal, full journal, stale/uncommitted candidate or association refuses. No genesis/repair fallback or file effect is performed by drafting.
- `/installed` returns exact5: `apiVersion:serverware.setupPolicyInstalledObservation/v1`, `okForAction:false`, `automaticRetryAllowed:false`, `nativeGateVerified:false`, `observationOriginal`. The real retained `LoadedPublication` reader joins the locked materializer journal, exact file/stat originals, signed policy, actual process-global control-plane loader, reviewed assignment, consumed approval and completed settlement audit. It is not a supplied loader flag or a path-only existence check.

The portal deliberately keeps the two role permissions separate: the Setup owner needs both `credential_owner` and `policy_publisher` to obtain a publication draft; the policy-file request/consume controls also require that same owner and both roles. A different literal `policy_publisher` may import the same data-only draft and approve without becoming the Setup owner. No admin-token fallback or credential-owner-as-publisher alias is allowed. Imported JSON is review data, never signature or authorization proof.

The materialization ceremony uses the existing endpoints and exact purpose:

1. Review the draft's exact signed policy bytes and materialize binding. Request fresh `/api/policy/file-publication/webauthn/options` for `policy-file-approval.request`, then call the actual `/materialize` endpoint once. The expected first response is HTTP428 `control_plane_approval_required` with the exact pending approval/action/resource/payload digest; this is not materialization success.
2. Share the unchanged data-only draft and approval ID with a different publisher. That operator imports/reviews them, retrieves the actual authenticated approval listing, and must find one exact ID whose `request` canonicalizes byte-for-byte to `bindingOriginal`, matching the stored payload digest, requester, pending status and expiry. The existing listing returns parsed `request`, not `request_json`; the exact-integer codec preserves its integers, while real effect owners still verify the stored original. A fresh `policy-file-approval.decide` assertion goes to the real `/api/control-plane/approvals/{id}/approve` route.
3. The original requester imports/reviews the SAME draft and approval ID, observes an approved row with a different `approved_by`, and obtains a NEW `policy-file-approval.consume` assertion. Only this explicitly selected `/materialize` call supplies `mfa.approvalId`. The materializer itself rechecks current authority, definite commits and all actual filesystem owners; browser review never substitutes for those checks.

Each phase retains the actual actor/cookie scope, field selection and original browser operation bound across awaits. i64 policy sequence/rollback and nested nanoseconds use the existing exact-integer/canonical OAuth helpers, not Number parsing. Policy-file body/binding bytes are admitted against the exact returned originals; the policy bytes are independently hashed for review. A lost options/assertion or failed prerequisite sends no materialize/approve effect; a sent effect is never automatically repeated. Approval rows are re-read immediately before effect dispatch. The bounded latest100 approval list is navigation, not complete absence proof: an unavailable exact row refuses the ceremony.

Before EACH request/decide/consume dispatch, session storage must successfully retain a nonsecret unresolved marker with phase, publication ID, payload digest, approval ID (nullable), actor ID and status. No assertion, draft, policy original or authorization original enters storage. Request marker scope blocks replacing an uncertain publication with a newly generated ID; later-phase markers block repeating the same publication/approval. Observed responses only annotate the marker; journal/installed observations never clear it. This browser anti-repeat aid is not durable server authority or a completion receipt, and cannot replace server-side one-shot/journal guards across browsers. Data-only draft transfer is explicit and manual; local originals remain in page memory/text controls only.

The separate journal button performs only the existing read-only bounded publication observation, with no resolve/retry action. The installed button is always labeled **CONTROL-PLANE loader only**, `nativeGateVerified:false`. Its original has scope `control-plane-loaded-policy-only` and retains exact file identity9, reviewed assignment6, journal/approval/audit originals and observation time. Setup still stays revision3. Native gate immutable policy/startup enrollment and actual native loaded evidence are separate, unfinished acceptance joins; installed observation is not proxy-ready, action permission, canary completion or full Setup completion.

New original bounds: continuation <=2170880 ASCII bytes, materialize requestOriginal <=1400000, bindingOriginal <=8192, signed candidate decoded <=1048576, installed observationOriginal <=131072. Whole escaped responses remain <=5242880; aggregate overflow refuses. Existing policy-file HTTP schemas define the unchanged WebAuthn/materialize/result envelopes; the Setup HTTP schema adds only the exact draft and observation contracts. No builds, parsers, browser tests, runtime requests or provider contacts were executed for this source slice.
