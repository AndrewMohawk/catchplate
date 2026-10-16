# Credential-first operator workspace

## Current ordinary-product status — October 15

The user accepts a trusted server administrator for the present product. Optional
host-trusted approve/deny and finite managed workload renewal are implemented
and deployed; native/TEE enforcement is a separate future assurance target, not
a prerequisite for either. Earlier statements below about missing ordinary
approvals or renewal are superseded by the current records:
[host review](project-completion.md#host-trusted-approvals--connected-acceptance-passed),
[managed renewal](project-completion.md#finite-workload-token-renewal--deployed),
and the [current deployment](project-completion.md#current-live-deployment).

The same instance now offers [12 additional common-app providers and 15 scoped
operations](common-apps.md), with Requests and official AI SDK examples. These
are specific supported jobs, not blanket service access or universal SDK
compatibility. Provider keys, real Google/X consent, real jobs and receiver
delivery still need their own acceptance. Local stdio MCP is implemented using
downloaded private client configurations; focused protocol/adapter checks and
the actual MCP → proxy → synthetic-provider allow/deny smoke passed. Hosted MCP
delivery is future work, with no endpoint deployed
or expanded authentication surface. The [ordinary delivery queue](project-completion.md#remaining-ordinary-product-work--october-15)
distinguishes missing implementation from private operator inputs and future
hardware assurance. Historical examples and evidence remain below.

## Product decisions from the original examples

The primary question is **let this app use this account or key for these
actions**. A credential form should not ask the operator to design an API
firewall. Keep the independent resources below, but compose them in one guided
journey rather than making the user visit three management pages.

The two first-class journeys are:

- **Use an API key:** save or reuse a key, select the app and destination,
  choose automatic insertion or an exact dummy authentication value to replace,
  then copy client configuration. No response-field list should be mandatory.
- **Use a connected account:** choose Google, consent to a supported permission
  preset, select the app, then use its normal API client. Refresh is Serverware's
  responsibility. The account owner should not manage refresh tokens, expiry
  arithmetic or token endpoints.

Provider application setup is an administrator task performed once per
deployment. Account consent is a separate task for each account owner. An app's
Serverware identity, provider authentication and an optional dummy value are
three different things; the UI must not call all three a "credential".

Default to **no optional content filtering** for new rules, with the supported
formats stated plainly. Destination and operation permissions, app identity,
secret-disclosure protection and transport bounds still apply. Existing rules
must not be broadened. An unsupported request/response format is a compatibility
gap, not an optional restriction that can be hidden in Advanced.

Response fields, mail age, quotas, schedules and approval are optional
restrictions on use, not properties required to save a credential. When chosen,
they remain real enforcement obligations. For example, disabling field
projection cannot disable the response evidence needed to enforce mail age.

Prioritize complete ordinary-client authentication replacement and unattended
Google mail before expanding the generic editor. Then present the original
examples as understandable operation bundles: read mail, post to X, publish a
specific npm package, or approve a particular ECR image. A single exact endpoint
is not a complete provider workflow.

Keep routine screens concise. Show the effective permission summary and relevant
compatibility limits before saving; keep raw IDs, policy hashes and detailed
diagnostics available through details, not as the main explanation. The new
guided UI is an incremental implementation, not the final provider-preset UI.

### Interface contract

Use **Credentials**, **Clients**, and **Permissions** as the resource navigation.
Credentials are provider accounts and keys (including GitHub App installations);
clients are the scripts, agents and CI jobs using Serverware. The underlying
application IDs and security ownership do not change with the UI labels.

Lead with the **Set up access** action, not a duplicate navigation section, then
present one sentence: "Inbox worker may read mail using Andrew's Google account"
or "Billing worker may use Billing key at
this API; replace this exact dummy header." **Credentials → Add credential**
uses the same provider editor in save-only mode and stops without creating a
client, proxy token or permission. **Use with a client** on a saved credential
starts setup with that exact credential, without requesting its secret again.
Saving an account/key remains an independent action. Separate resource
ownership in the backend must not become separate mandatory setup exercises.

Account cards should lead with the account name, meaningful permission names,
affected apps and observed attention state. The Google account card now shows
the account, **Read Gmail**, and assigned app names, with raw scope URLs, preset
identifiers, exact IDs and former assignments in one **Details** disclosure.
This is presentation, not a live health check or reconnect workflow.
Keep material limitations and blocking conditions visible,
but use concise states such as "Not tested yet", "Setup required", "Temporary
failure" or "Reconnect required" only when their evidence supports them.

Use the original examples to define complete permissions, not default restrictions:
read mail; post to X; publish a selected npm package; publish an approved ECR
image. Mail age, daily quota, publishing hours and human approval are deliberate
additions. An exact endpoint editor is an advanced option, not the normal way to
describe a service. The existing example files are demonstrations, not safe
defaults to copy wholesale.

Keep **Proxy setup** and its CA download first-class, alongside **Credentials**,
**Clients**, **Permissions**, and **Audit log**. Provider application
configuration belongs in administrator settings. Approvals use their own
**Pending actions** workflow. Ordinary host review is now available when the
matching runtime is enabled; never offer an inert option or represent it as
the separate future hardware-backed workflow.

Retained connection checks must not look like configured provider accounts.
Overview counts and next-step guidance exclude resources used only with the
exact local diagnostic endpoint. Credentials, Clients and Permissions retain
them in collapsed **Connection-check resources** sections; revoked records have
their own history section. Grouping never changes authorization or deletes data.
Names alone never classify a resource, and a credential/client shared with any
non-diagnostic permission remains in the ordinary list. Unassigned and ambiguous
resources also remain ordinary.

Guided setup excludes those saved diagnostic credentials and clients by default.
An explicit **Include saved connection-check resources** option restores them.
Choosing **Use with a client** on a diagnostic credential is already explicit
intent and includes those choices. Previously selected resources remain selected;
refreshing or changing a display filter must not silently choose another key or
client. Manual setup asks for an explicit approved destination instead of
preselecting the local diagnostic upstream.

The [proxy destination workflow](operator-proxy-destinations.md) keeps operator
configuration separate from application permissions: review a proposed list,
prepare it, then activate it through an exact controlled cold restart without
discarding saved resources. Preparation is not activation or provider readiness.

Acceptance is two ordinary jobs, including their subsequent use: authentication
replacement with zero response-configuration interactions, and an inbox worker
that lists, paginates, reads messages and continues after provider-token expiry.
Neither a short form nor a successful isolated endpoint substitutes for those
jobs. Do not promise arbitrary passthrough while the implementation supports
only bounded JSON and selected statuses.

### Observed activity is not account health

Account and key cards should answer what the proxy has actually recorded, while
keeping their saved permissions separate from runtime observations. The additive
`observed_activity` catalog field reports a bounded recent audit window: matched
successful response records for saved credentials and refresh success/failure
records for Google accounts. Reading it must neither decrypt a credential nor
contact a provider, trigger refresh, change a generation or publish a policy.

The ordinary card shows one concise summary. Details identify the recorded
events and incomplete coverage. Missing, malformed or unavailable evidence is
not proof of health or disuse and must not disable otherwise valid catalog
management. Quarantined or revoked credentials remain unusable regardless of
historical successes. A recorded proxy response is not proof that the client
received it or completed its job; audit timestamps are storage/receiver times,
and this projection does not independently verify the audit chain.

Refresh failure alone does not establish that consent was revoked. The generic
refresh error must direct the operator to account status and audit information,
not unconditionally instruct reconnection. A safe reconnect workflow, real
Google acceptance and app-identity renewal remain separate requirements; this
read-only display does not implement them.

### Guided setup consistency, 2026-10-09

The working source now reuses the compact Google account card inside Connect,
including its optional Details disclosure. Ordinary selection/review labels
omit UUIDs; duplicate names receive the shortest distinguishing ID suffix.
Literal names imitating generated labels or create/grant actions remain visibly
distinct, with a full-ID prefix only for exceptional collisions. Exact option
values and account/app/rule relationships, stale-state guards and token custody
are unchanged. Details stays open across refresh only for the same account.

The existing Google browser suite's `--setup-only` selection passed one pure
group and five rendered groups: compact summary/details and client setup,
duplicate-name exact selection through reorder, and three selected-account
quarantine controls. Desktop/mobile screenshots were inspected, without
horizontal overflow. Both syntax checks passed, inputs remained unchanged, and
the bounded browser scope exited zero with no remaining cgroup processes.
The unchanged guided-connection suite also passed all 24 rendered groups on
the same frozen production UI, including inline API-key/app/rule creation,
saved-resource reuse, token handling and uncertain-mutation guards. Its evidence
is `connect-regression.vt9d2W/browser.log`; that scope also exited zero with
unchanged sources. No provider or live API requests, consent, token refresh or
generated client commands ran in those fixtures. The change was absent from the
then-deployed `d2f645f6` snapshot; it was included in the retained `e19f8b5a`
deployment alongside the subsequently tested activity display. See
[current activity and live verification](operator-account-activity-verification.md).

Evidence: `google-connect.FN6xrL/browser.log`; screenshots:
`serverware-operator-artifacts/google-browser-synthetic-epbCb7` beneath projects.
Connect SHA-256:
`a306c455c554a31ae7d2415133e7b2ae575193ea07fefdf9ecd4a57aaef21fe5`;
test SHA-256:
`a648108951f8155e1f155d2b8e0be5905d4ef5f801e8bda2b0f6cb2026af9167`.

### Compact account-card verification, 2026-10-09

The focused `scripts/test_operator_google_browser.cjs --cards-only` check passed
one pure group and three rendered groups: active account, quarantined account,
and unknown-preset refusal. Details opens and closes, preserves exact assignment
IDs, and stays optional. Static-key actions remain unchanged. Desktop and mobile
screenshots were inspected. After correcting only screenshot scroll positioning,
the same focused checks passed again with unchanged production UI code.

The resource-script SHA-256 at that earlier checkpoint was
`08338a6e1652e9077ca389619a3d82aec909fd4504f3ad435c4e2a9e748d3446`.
Evidence is `google-cards.P18BigAf/browser.log`; screenshots are in
`serverware-operator-artifacts/google-browser-synthetic-lQbkfL` under the projects
directory. Inputs were unchanged during each run; both bounded browser scopes
terminated and their empty scratch directories were removed. These intercepted
fixtures make no provider, proxy or live application requests. They do not
establish consent, refresh, deployment, or production acceptance.

## Normal use, not just first-run configuration

The everyday account card should answer: **which account, which apps use it,
and does it need attention?** Present permissions as understandable names;
raw scope URLs, client IDs, generation numbers and signing details belong in
expandable diagnostics. A saved-account record alone cannot establish healthy
refresh. Show known outcomes such as last successful use, a temporary failure,
or provider-required reconnection only when backed by actual observations.

The basic authentication replacement screen should ask only which app and
destination may use the selected credential, whether to insert authentication
or replace an exact dummy value, and where the provider expects it. Default
new rules to no optional content filtering. Choosing response fields or body
restrictions is a separate, deliberate action, not a prerequisite to storing
a key. Copying a normal client's configuration should be the final step, not
an invitation to understand internal policy JSON.

Changing an app's permission, rotating its Serverware token, replacing a static
provider key, reconnecting an OAuth account and disconnecting that account are
distinct actions. Show affected apps before shared-account changes. Restarting
the console must not require reconnecting accounts or repeating setup; a changed
provider secret or CA trust root needs its own explicit workflow.

The [static key replacement workflow](operator-key-replacement.md) now preserves
the saved credential and all assigned apps/rules while changing its encrypted
value. It requires no new response configuration. This is separate from
replacing a dummy authentication value in an app's outbound requests, and from
reconnecting an OAuth account; deployment and proxy verification are recorded
in that workflow's verification section.

The [active Google account reauthorization workflow](operator-google-reauthorization.md)
renews consent for the same account without rebuilding its applications or
permissions. It preserves the original account binding and application tokens;
it neither broadens Google scopes nor restores disconnected or quarantined
accounts. Its focused synthetic verification is separate from real-provider
and deployed acceptance. Account owners do not configure refresh-token fields.

Delivery priority is two complete vertical journeys: ordinary-client auth
replacement with supported request/response formats, and connect-once Google
mail with automatic refresh. Then expose the Gmail/X/npm/ECR operation bundles
and optional restrictions. A larger generic editor, more field names, or more
disabled buttons is not a substitute for these working journeys.

## The minimum form and the optional policy

The normal form should produce a sentence the operator can understand before
it produces a policy document: **Allow this app to use this account at this
service.** Authentication placement is part of that setup; restricting the
content of an API conversation is a separate choice.

| Question | Normal setup | Optional restriction |
| --- | --- | --- |
| What authenticates upstream? | A saved key or a connected account | None; do not attach response rules to the secret itself. |
| Who may use it? | A selected application | Approval, schedule or usage quota. |
| Where and for what? | A destination and an operation or supported operation bundle | Narrower paths, packages, repositories or request values. |
| What should be replaced? | Insert authentication, or replace one exact dummy header value | Advanced supported credential placement, not arbitrary byte replacement. |
| What comes back? | The provider response in the explicitly supported formats | Selected fields, age limits or other deliberate response policies. |

For example, a basic rule should read "Invoice worker may call this billing
API using Billing key; replace `Authorization: Bearer DEMO`; no optional
content filtering." The Google equivalent is "Inbox worker may read mail
using Andrew's connected Google account." Neither needs a response-field
editor. Adding "only messages from the last 30 days" introduces an actual
response-policy obligation, not merely a convenient query parameter.

Google is an account connection, not the name of a single Gmail endpoint.
The first supported preset may be Gmail read-only, but the UI must name that
permission explicitly rather than imply it covers Calendar or every Google
API. Adding provider permissions requires deliberate consent; choosing another
application must not silently expand the account grant. Administrator OAuth
application configuration belongs in Settings, with a clear missing-setup
explanation when unavailable, not extra token-endpoint fields in each account
form.

Unattended use has two lifecycles: provider access-token refresh and the app's
own Serverware identity. A long-running job needs a supported way to renew or
rotate the latter before its finite expiry; automatic Google refresh alone is
not indefinite job access. Manually managed client tokens retain an explicit
30-day default and a 90-day maximum, with manual rotation. The earlier backlog
for managed renewal is now implemented: explicit Ed25519 enrollment grants
1–90 days of renewal authority and 1–24 hour tokens, clipped to the enrollment
deadline. Existing clients remain manual until deliberately enrolled. Show the
selected lifecycle in setup; never silently renew tokens or remove their expiry.
See the [deployed renewal contract](operator-workload-renewal.md) and
[connected helper evidence](project-completion.md#default-managed-helper-https--isolated-connected-acceptance).

Normal clients also need their request bodies, provider errors and supported
response statuses to behave normally. "No optional content filtering" must
therefore be implemented in the request and response paths, not achieved by
hiding required field declarations. Unsupported formats must be explained
before saving. The additive [ordinary-client compatibility contract](ordinary-client-compatibility.md)
implements unchanged JSON request bytes plus an explicit JSON-or-empty-204
response mode in source. The operator UI exposes these choices only when
advertised, without requiring either field list; real client and deployment
acceptance remain separate gates.
Ordinary query ordering, form, binary and streaming support remain separate
work. Existing rules must not acquire these permissions through a default change.

## Requirement and scope

The operator's October 8 feedback is the design input: connect an account such
as Google for unattended application use, or specify credential replacement
without having to author a response-field projection. The product remains a
credential-control proxy, not a mechanism for distributing provider tokens.

The original combined demo form stored a credential, created a 24-hour client
identity, and granted one projected-JSON route together. Those are distinct
resources. Simplifying labels without separating their lifecycles would not
meet the requirement.

This workspace uses the ordinary host-trusted profile. Its application checks
still require authentication, client isolation, secret protection and retained
data integrity. It does not establish native commissioning, independent custody
or hostile-root resistance; those are future assurance targets, not prerequisites
for ordinary approval. Provider ownership and actual job acceptance remain
distinct from implementation. This requirements document and source tests alone
do not establish deployment; use the linked release records.

## Resource model

- **Credentials:** a named encrypted credential or verified OAuth
  account. Saving a static credential requires its name, authentication type,
  value, and applicable header name, not an endpoint or response schema. The
  existing encrypted credential database remains the only secret store.
- **Clients (application identities):** the identity used by one client or job to authenticate to
  Serverware. Creation and rotation return a client token once; only its verifier
  is persisted. Lifetime is explicit and finite. Provider-token refresh and
  client-token rotation are independent operations.
- **Access rules:** references to an application and credential, the approved
  destination and operations, and any optional additional restrictions. No rule
  means no access. Merely saving a credential or application grants nothing.
- **Proxy setup:** endpoint, client-scoped CA trust, and actual supported client
  instructions. The console and forward-proxy addresses remain distinct.
- **Audit:** explain configuration changes and request decisions without exposing
  provider secrets, client tokens, or OAuth token responses.

One credential may serve several rules and applications. Removing an
application's access cannot delete that shared credential. Removing a credential
with active assignments requires an explicit affected-application workflow; it
must not silently cascade from an ordinary application action. Local removal
is not provider-side revocation or forensic erasure of historical database pages.

## User journeys and acceptance

The default journey is **Set up access: choose a credential, choose a client,
review permissions, copy the client setup**. Separate resources must not become
disconnected administrative chores. The overview should show the next unfinished step and
each resource should link to its assignments. Advanced controls belong behind
an explicit restriction choice, with a plain-language summary of what will be
allowed before publication.

The primary action is **Set up access**, with inline choices to reuse or
create a credential and client identity. **Add credential** is a save-only entry
to the same editor, not a competing setup form or an implicit grant. The separate
resource pages are management views, not three mandatory stops in onboarding.
Present provider operations in the operator's language; do not expose a policy compiler
form as the default journey.

Choose the connection method first: **Connect Google**, **Use an API key**, or
**Use a saved connection**. Show only the relevant form. Opening Google setup
must not leave a second API-key form and another Connect Google button competing
on the same screen. Credential-only consent must stop at the saved account;
only an explicit use action continues into client access with that exact account
selected. Explain account permissions once; keep exceptional recovery controls
contextual. This layout does not establish provider consent, refresh health or
deployed acceptance by itself.

A new basic authentication-replacement journey must require **zero response
configuration interactions**. Select the advertised supported no-filter contract
automatically, with a short visible compatibility summary. Compatibility-version
names are not user choices, even inside Advanced: expose only meaningful content
restrictions, while retaining existing saved and drafted contracts exactly.
Generate an optional permission name from the selected operation. Opening or
closing **Add restrictions** must not itself change a permission. If an older
backend supports only field projection, show that limitation and the required
fields explicitly rather than inventing a no-filter capability.

| Step | Required in the normal journey | Only when applicable |
| --- | --- | --- |
| Connect or save | Named API credential, or provider consent and verified account | Custom header name; administrator OAuth application setup is separate |
| Choose the app | Existing application or a new scoped client identity with a visible finite lifetime | Custom token lifetime and rotation; never provider-token copying |
| Allow its use | Credential/account, approved destination and operation | Exact public placeholder when the client requires dummy authentication |
| Add restrictions | None beyond the selected operation's necessary scope and protocol limits | Response fields, age, quota, schedule or human approval, each an explicit choice |
| Review and use | Effective permission summary, actual activation status, proxy endpoint and client-scoped CA | A complete sample request when the user supplies its body/query values |

"No content filtering" is not "no authentication or destination restriction."
Conversely, a transport limitation is not an optional policy preference: show it
before saving, and do not suggest hiding an unsupported request format makes it
work. New rules can explicitly preserve supported JSON content without field
declarations. Choosing optional field restrictions retains the legacy contract,
including no body when that list is empty. Saved rules are never broadened by
the new form defaults.

The two basic onboarding paths are:

1. **API key or token:** name and store the secret with its supported provider
   authentication placement. The current connection owns that placement:
   Bearer Authorization or a custom header. When granting access, choose the app,
   destination and either automatic insertion or replacement of one exact
   nonsecret placeholder in that configured header. The rule does not choose a
   different injection location or perform arbitrary body/query/byte substitution.
   Additional placements need an explicit supported contract, not a misleading
   form option.
   The workload's Serverware identity is separate from the placeholder and must
   never be forwarded to the provider.
2. **Connect Google:** administrator setup supplies the OAuth application once;
   the account owner consents to the chosen permissions. Applications use the
   connected account without receiving its provider tokens. The normal flow
   refreshes access automatically; provider-required reauthorization is a
   distinct, exceptional action, not a daily setup step.

For a basic replacement rule, **do not filter response content** is a legitimate
explicit choice, not an empty or wildcard field projection. The interface must
state supported formats and remaining transport/disclosure limits. If a selected
preset requires response-side evidence, such as Gmail message age, that check
cannot silently disappear when content filtering is disabled.

### Concrete acceptance boundaries still to finish

These are journey acceptance criteria. Some are now implemented and deployed;
their linked current records distinguish that evidence from remaining real-use
acceptance. Historical source-only descriptions do not reopen completed ordinary
work. None of these criteria may silently broaden existing saved rules.

- **Name the job and client.** Each supported preset must name its client and
  configuration, operation sequence and completion condition. For example,
  polling Gmail lists through pagination and reading returned messages across
  token expiry is a specific job; "Google works" is not. Attachments, history,
  stock SDK support and Serverware running the job are separate promises, not
  implications of a Read Gmail label. The client remains responsible for the
  job unless an executor is explicitly implemented.
- **No response configuration means useful responses.** The default must retain
  supported provider content, error status/body and the bounded metadata needed
  by the named client, including retry or pagination semantics, without a
  user-authored schema. Disclosure and protocol checks remain mandatory. Current
  JSON limits and discarded response headers are compatibility gaps where they
  prevent that job; the label must not imply arbitrary transparent passthrough.
- **Distinguish dispatch outcomes.** A denial before upstream dispatch is not
  the same as a lost or rejected response after a write may have completed.
  Client errors and redacted audit correlation must distinguish those outcomes;
  a generic "blocked" result must not imply safe resubmission. Preserve supported
  provider idempotency semantics and never automatically replay an uncertain
  payment, publication or other write merely because response validation failed.
- **Make account selection explicit.** Current same-app overlapping route
  matching cannot choose between two Google accounts for the same operation.
  Until a deliberate selector or reviewed switching workflow exists, bind that
  app/operation to one exact account and explain conflicts. Account creation
  order is never a selector; switching must show affected permissions rather
  than silently replacing the account or inheriting another account's access.

| Journey | Evidence required |
| --- | --- |
| Save a static credential | Browser-to-API persistence succeeds without route or response fields; no signed access policy changes and no provider request is made. |
| Share a credential | Two independently authenticated applications can use their own permitted rules referencing the same encrypted credential. |
| Remove one application's access | After the new policy is actually loaded, the revoked client cannot dispatch, including with a previously warmed credential cache; the other application still works. |
| Rotate a client token | The new token is disclosed once, the old verifier is replaced in the signed policy, and old-token rejection is verified after activation. No provider refresh or reconnection occurs. |
| Restart or migrate | Existing credential ciphertext, IDs, token verifiers/expiry, nonce history, policy bytes/hash/sequence and high-water state are preserved; a restart neither renews tokens nor grants new access. |
| Replace a saved provider secret | Preserve the shared credential's assignments and application identities; make the version change and affected applications explicit. Verify new issuance and subsequent proxy use of the new generation without implying instant remote invalidation or provider revocation. The catalog/UI implementation, private two-application lease-expiry proof and retained-state rollout are recorded in the [key replacement workflow](operator-key-replacement.md). The deployed long-name review/Cancel flow now passes at 320/390/1280 pixels; no live key was changed during that read-only browser check. |
| Connect Google | Real consent identifies the account and granted permissions; a proxy request obtains only an injected access token, with no provider token handed to the application. |
| Run Google unattended | A request after access-token expiry completes through actual refresh, generation reconciliation and durable storage; concurrent callers do not race token rotation. Provider-required reauthorization is distinct from transient failure. |
| Replace a configured value | A normal client with the configured placeholder succeeds; unrelated, ambiguous or mismatching input does not select or reveal a credential. Existing insertion-only rules retain their behavior. |
| Apply no response content filter | Supported responses retain their logical content without a user-written field allowlist; protocol, size, timeout, target, safe-header and disclosure controls still apply. Unsupported formats are explicit, not silently transformed or advertised as supported. |
| Complete a provider workflow | One understandable preset covers the necessary bounded operation bundle, such as Gmail list, pagination and message reads, or npm prerequisite reads plus publish. Prove the ordinary client can complete the operation, not just one hand-crafted endpoint call. |
| Approve a requested action | Ordinary host-trusted review is implemented and deployed: an actual request creates a pending action; approve, deny, expiry and one-use consumption have visible outcomes and explicit identical-request retry. Connected synthetic acceptance passed. Real-provider use and improved human-readable review remain separate; review currently contains metadata/body hash, not body contents. Native/TEE authority is future work. |

Google OAuth application configuration belongs to administrator setup. An
account owner still performs initial consent. The interface should show the
verified account, permissions, refresh/reconnection state and affected
applications, not access or refresh tokens. An OAuth source implementation is
not evidence of a working deployed provider integration.
The [Google integration plan](operator-google-integration-plan.md) records the
remaining catalog, consent and unattended-refresh work, including why a generic
generation-conflict response is not permission to retry credential issuance.

## Compatibility and migration

Import existing combined connection metadata transactionally into separate
catalog records. Preserve the existing encrypted credential rows and each
connection's application identity, token verifier, expiration and rule identity.
Migration does not sign, advance or replace the committed policy. Mark the
catalog schema version only after the complete import validates.

Catalog mutation uses revision compare-and-swap, and access-changing mutation
also binds the expected committed policy hash. Data, policy publication and
redacted audit changes commit together. A database commit followed by a failed
policy-file write is pending publication, not an invented rollback or active
policy. Actual loaded-policy observation determines enforcement.

Once the catalog is active, legacy combined creation/revocation must refuse
instead of reinterpreting a shared resource as a disposable one-to-one
connection. Preserve historical receipts. Do not reset history, reuse retained
identifiers, silently renew a client token, or automatically retry an uncertain
mutation. Status remains available for reconciliation.

## Incremental delivery is not completion

The workspace now offers an explicit bounded whole-JSON response choice as
well as selected-field projection. New UI rules prefer the whole-JSON choice
when advertised; the API's omitted mode still requires the historical
projection. Existing saved policies are not broadened. Text, binary, compression
and streaming compatibility remain separate requirements, not capabilities of
the JSON-only choice.

The advertised modes describe this source version, not dynamic negotiation
with an arbitrary running proxy. Deployment must pin a compatible control plane
and gate supporting `bufferedPassthrough`, and establish private actual-proxy
acceptance before rollout. An old gate must reject an unsupported policy; never
silently substitute another response mode. Saved state is not active until the
backend reports active publication and the loaded hash matches the saved hash.

Per-rule header replacement is implemented and has actual proxy acceptance;
the [public allow/revoke boundary](operator-public-proxy-verification.md) is also
recorded. Google's managed account and Gmail SDK profiles are implemented with
isolated consent/refresh and job evidence. The real-provider consent/refresh
journey is still open: do not present inactive OAuth controls, a health check,
fixture-only browser success or a JSON-only response mode as its completion.

Client placeholder matching belongs to an access rule, not the reusable secret.
Two applications sharing a credential may use different dummy values, or one
may need insertion without any dummy header. The provider header target still
comes from the credential's injection contract. The placeholder is public client
configuration, never a provider secret or an application authentication token.
The [replacement guide](exact-header-replacement.md) describes that client
journey and its exact supported header contract.

## What the original examples imply

| Example | What the operator should configure | What must remain enforced |
| --- | --- | --- |
| Gmail recent mail | Connect Google; choose read-only mail and an optional age limit. | Verified account and scopes; message routes and response-side age evidence, not only a rewritten query. |
| X daily posting | Connect the X account; allow posting with a daily quota. | Shared provider-account quota across applications; changing a client identity cannot reset it. |
| npm publishing | Store the publishing credential; choose package and allowed hours. | Typed publish operations, exact package and schedule; a time window permits requests rather than scheduling a job. |
| ECR image publication | Select account, region and repository; require approval for the exact image. | The deployed ordinary path binds whole-image review to exact repository/tag, staged content and its upload/manifest workflow, not transient SigV4 headers. Stock Boto3 through the proxy passed connected synthetic acceptance; real AWS publication remains open. Native custody is a separate future requirement. |
| Ordinary API client | Store the key; select destination and credential placement. | Application identity, explicit destination/operation permission and exact replacement semantics; no compulsory content projection. |

These are user-facing presets over the existing policy mechanisms, not reasons
to expose their entire schema during credential creation. Use the specific
operation bundles rather than treating the generic rule editor as a substitute.
The earlier ECR storage/signing-only gap is closed by the deployed publication
workflow, including explicit terminal artifact cleanup and separate action/audit
notifications; see the [current completion record](project-completion.md#p1--complete-the-explicitly-requested-features).
Selecting a restriction still requires its actual request and response
enforcement, and choosing an unfiltered mode must not silently discard it.

Optional Gmail age restrictions remain an ordinary-product implementation gap.
The current Read Gmail catalog bundle accepts only unrestricted age; its UI and
runtime do not enforce a last-N-days limit. Keep the optional recent-mail
requirement open, alongside the implemented unrestricted inbox job. A search
query alone is not an age policy, and existing unrestricted grants must not be
silently narrowed when an additive restricted mode is introduced.

The Google delivery boundary is a **usable inbox job**, not merely a successful
consent callback. Generic catalog rules still bind one literal path; the new
explicit Read Gmail bundle covers bounded list, pagination and returned-ID
message reads with its own ordinary query contract. Its isolated Requests job
passed before and after actual synthetic-token expiry without new consent or
exposing provider tokens. The actual official Go Gmail SDK example subsequently
passed that local workflow over an HTTPS proxy using Basic CONNECT and separate
trust roots, with wrong-trust, unassigned-app and revocation controls. See
[the exact verification boundary](operator-gmail-job-verification.md).
That Go checkpoint is historical. Later Node/Python/upgraded-Go synthetic jobs
passed across expiry and refresh, and their configuration handoff is deployed;
see the [current Gmail row](project-completion.md#p1--complete-the-explicitly-requested-features).
Real Google consent and the actual deployed inbox job remain open.
Mail-age restrictions remain optional, with their independent response checks
when selected. Attachments, history and other operations must be named explicitly
rather than silently included in a vague "Google access" grant.

Do not copy the illustrative npm policy as a publish-only default. The README's
daily publishing window differs from the weekday JSON example, which also
requires approval and lists unpublish, dist-tag, token and metadata writes.
A publish preset must permit only its reviewed publish workflow and necessary
prerequisite reads. Schedules and approval are separate choices; neither broader
write permissions nor weekdays-only behavior may be inferred from the example's
name. ECR additionally needs its actual authentication and multi-request image
publication protocol; a generic JSON route and static header insertion do not
implement that integration.

The downloadable npm project's earlier isolated metadata/publishing workflow
passed through the real proxy: default read-only metadata, scoped/unscoped manifest
reads and publications, six request denials, eight unassigned/revoked CONNECT
denials, trust failures and local publication guards. Its 21-case acceptance
joins stored tarball bytes and the persisted audit chain; it does not imply
public npm access, installation, CI execution or live-demo acceptance. See
[the exact npm example evidence](operator-npm-example-acceptance.md).

The subsequent, separate [npm installation acceptance](operator-npm-install.md)
passed stock installation, cold `ci`, transitive dependency bytes and default
advisory requests across 25 commands. Its paired app/proxy is deployed; a live
LAN proxy smoke passed separately. Neither result establishes public-Internet
CONNECT, real npm credentials or a real registry publication. The guided publish
preset also offers optional daily UTC hours; no time window is added by default.

Judge the simplified demo by two complete jobs: a normal client replaces its
configured dummy authentication with **zero response-configuration interactions**,
and a background mail worker uses a connected account across token expiry.
Browser setup, saved configuration, loaded permissions, actual API results and
redacted audit outcomes must agree. Source tests, a saved-account card, or one
successful handcrafted request are useful evidence but not either full job.

The broader [policy examples](../policies/credential-limits.examples.json) also
use Basic, query-token and cookie authentication, and form bodies for Stripe and
Twilio. Those are conditional provider/client requirements, not more mandatory
fields on every saved key. A simple header-replacement implementation must not
be advertised as supporting those other placements or formats. Likewise, an
optional usage limit needs an understandable unit, reset window and sharing
scope: request count, payment amount and reserved requested output tokens are
different limits. A requested-token allowance is not measured token usage or
provider billing. Show these details only when that restriction is selected.

The approval journey is a first-class workflow, not a checkbox on a credential.
The original ECR example assumed a configured hardware ceremony; that remains
a future protected-assurance design, not the October 15 ordinary requirement.
The deployed host-trusted workflow provides Pending actions, explicit exact-
request review, approve/deny/expiry and visible consumption. It requires no
per-action hardware ceremony. Review currently shows metadata and a body hash,
not the request-body contents; improve action/client/account descriptions without
claiming a richer review than is available.

A rejected, expired or uncertain action must not silently resubmit. The original
request stops with HTTP 428; after approval the client must explicitly retry the
identical request once before expiry. The UI must not promise transparent
continuation. Host-review action alerts contain no provider secret and are
separate from audit delivery. Real receiver delivery and actual provider approval
use remain unverified. ECR's separate whole-image review and multi-request
publication protocol are now deployed, with connected synthetic Boto3/proxy
acceptance; [real AWS publication](operator-ecr-publication.md) still requires
its own explicitly authorized job and is not established by those checks.

Account connectivity/refresh health, application-token validity and actual rule
activation must be three separately visible states. A healthy Google grant does
not renew an expired Serverware application token. A temporary refresh failure
must not be labeled lost consent without provider evidence. Existing Google
disconnect/reconnect and native ownership boundaries remain explicit; do not
work around them with a pasted refresh token or a hidden legacy fallback.
In particular, do not direct an existing account owner to repeat initial consent
as a repair action: current duplicate-grant handling can quarantine the shared
grant family and revoke affected rules. Reconnect must preserve and deliberately
reconcile the existing account identity and assignments through its own supported
workflow. Account-level repair must show which applications it affects.

## Ordinary-client compatibility boundaries and remaining gaps

The current source is not yet a general "just replace authentication" proxy.
Removing mandatory response projection solves only one part of that journey:

- Standard Basic proxy login is now an explicit signed choice for catalog
  applications, retaining scoped token hash/expiry checks and legacy Bearer
  behavior. The [Requests/curl verification and rollout record](operator-basic-rollout.md)
  distinguishes isolated HTTPS acceptance from the bounded live smoke. The
  official Go Gmail example also now has isolated Basic/HTTPS acceptance;
  the older Requests Gmail job alone used a custom Bearer adapter. This does
  not implement provider Basic injection, renew expired application tokens or
  establish arbitrary SDK support. Client trust configuration and workload
  credential separation remain part of each named client's acceptance.
- Legacy rules can interpret an empty request-field list as forbidding a body.
  New supported rules explicitly preserve bounded strict JSON without field
  declarations; the deployed UI selects the advertised contract automatically.
  Private ordinary-client acceptance verifies exact bytes, while the separate
  live smoke verifies injection and audit. Neither establishes form/binary/stream
  compatibility. Existing restricted rules retain their saved contract.
- Query names default to none, and forwarded client headers default to
  `accept` and `user-agent`. An example-request importer could suggest those
  names locally for explicit approval; it must not silently broaden access.
- Generated cURL remains a connection template, without body or query values.
  A complete example would need supplied sample input and must not execute
  automatically.
- Ordinary provider response headers need an explicit compatibility contract,
  separate from which headers are forwarded to the client. The isolated normal
  Google run returned upstream HTTP 200 but the signed response envelope blocked
  its headers even with `unfiltered_json` selected. Basic setup must not require
  operators to reverse-engineer provider metadata. Fix the supported simple mode
  with bounded admission/forwarding and regression coverage, without weakening
  existing signed rules or removing fixture metadata to hide the gap. V2 now
  repairs admission by safely discarding unselected metadata, with isolated and
  live evidence; forwarding remains the separate requirement below. See
  [the retained failure](operator-google-backend-verification.md#corrected-joined-run-response-header-blocker).
- Accepting and discarding response metadata is not transparent client behavior.
  Current catalog profiles forward no selected response headers. A usable
  provider workflow may need `Retry-After`, `ETag`, `Location` or pagination
  headers; add the appropriate bounded forwarding contract and client checks.
  Do not require operators to discover missing retry or pagination semantics
  by reverse-engineering a response-field editor.
- Whole-JSON responses retain status-code, body-presence, size and safe-header
  restrictions. Legacy whole-JSON envelopes do not support `204 No Content`;
  the deployed additive contract admits it through an explicit paired mode,
  covered by private acceptance rather than the live echo smoke. Text, binary
  and streaming remain open compatibility work. Generic queries still require
  canonical ordering; the Gmail bundle has its separate ordered query contract. Ordinary-client
  compatibility needs explicit implementation and proof, not a claim that
  "no response filter" removes these protocol restrictions.

Destination and operation permissions remain necessary even in the simple
journey. Optional content restrictions and provider-specific presets should be
separate choices, with a short effective-permission summary before publication.

The current UI clarity slice shows the same five essential restrictions in the
draft and saved rule: destination/methods, body, query, headers and response.
Bodyless POST defaults and the JSON/empty-response limit remain visible; detailed
compatibility limits are expandable. Client setup leads with the existing
client's settings and explicitly labels cURL as an incomplete connection
template. This is presentation support, not new protocol compatibility or the
complete inline onboarding/provider-preset journey described above.
