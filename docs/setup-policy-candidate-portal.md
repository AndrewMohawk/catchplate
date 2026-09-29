# Protected Setup candidate association

The owner-facing panel connects the actual activated Setup revision 3 to a
completed protected native generation through `setup.policy.bind-candidate`.
It does not load policy, authorize a proxy, finish a canary or complete Setup.
Source is unbuilt and unexecuted; no browser/provider/runtime acceptance is
claimed. The independent authority/kernel continuation is integrated in the
same batch, without widening the old OAuth four-event mutation contract.

Four fixed POST routes live under `/api/setup/policy-candidate`:

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

Every route requires a genuine current OIDC cookie, exact Origin and CSRF,
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
