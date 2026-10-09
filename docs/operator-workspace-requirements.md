# Credential-first operator workspace

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
not indefinite job access. The current development token has an explicit
30-day default and a 90-day maximum, with manual rotation. Show that limit in
client setup and treat managed workload-identity renewal as separate unfinished
work, not an excuse to silently renew tokens or remove their expiry.

Normal clients also need their request bodies, provider errors and supported
response statuses to behave normally. "No optional content filtering" must
therefore be implemented in the request and response paths, not achieved by
hiding required field declarations. Unsupported formats must be explained
before saving. The additive [ordinary-client compatibility contract](ordinary-client-compatibility.md)
implements unchanged JSON request bytes plus an explicit JSON-or-empty-204
response mode in source; verification and UI exposure remain separate gates.
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

This workspace changes the development profile only. It does not satisfy or
remove native commissioning, independent custody, production approval, provider
ownership, public routing, or production acceptance requirements. No deployment
is established by this document or by source tests.

## Resource model

- **Credentials and accounts:** a named encrypted credential or verified OAuth
  account. Saving a static credential requires its name, authentication type,
  value, and applicable header name, not an endpoint or response schema. The
  existing encrypted credential database remains the only secret store.
- **Applications:** the identity used by one client or job to authenticate to
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

The default journey is **connect an account, choose an application, allow its
use, copy the client setup**. Separate resources must not become disconnected
administrative chores. The overview should show the next unfinished step and
each resource should link to its assignments. Advanced controls belong behind
an explicit restriction choice, with a plain-language summary of what will be
allowed before publication.

The primary action should be **Connect an app**, with inline choices to reuse or
create its account/credential and application identity. The separate resource
pages are management views, not three mandatory stops in onboarding. Present
provider operations in the operator's language; do not expose a policy compiler
form as the default journey.

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
work. The current editor still requires request-field declarations for JSON
bodies; removing that requirement needs implementation, not different wording.

The two basic onboarding paths are:

1. **API key or password:** name the credential and store its value. When granting
   access, choose the destination and credential placement. A replacement rule
   identifies one specific header and an exact nonsecret placeholder; it is not
   a global search-and-replace over arbitrary request bytes. The workload's
   Serverware identity is separate from that placeholder and must never be
   forwarded to the provider.
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

| Journey | Evidence required |
| --- | --- |
| Save a static credential | Browser-to-API persistence succeeds without route or response fields; no signed access policy changes and no provider request is made. |
| Share a credential | Two independently authenticated applications can use their own permitted rules referencing the same encrypted credential. |
| Remove one application's access | After the new policy is actually loaded, the revoked client cannot dispatch, including with a previously warmed credential cache; the other application still works. |
| Rotate a client token | The new token is disclosed once, the old verifier is replaced in the signed policy, and old-token rejection is verified after activation. No provider refresh or reconnection occurs. |
| Restart or migrate | Existing credential ciphertext, IDs, token verifiers/expiry, nonce history, policy bytes/hash/sequence and high-water state are preserved; a restart neither renews tokens nor grants new access. |
| Replace a saved provider secret | Preserve the shared credential's assignments and application identities; make the version change and affected applications explicit. Prove old cached material cannot be used after activation. This is distinct from rotating an application's client token and remains unimplemented in the catalog. |
| Connect Google | Real consent identifies the account and granted permissions; a proxy request obtains only an injected access token, with no provider token handed to the application. |
| Run Google unattended | A request after access-token expiry completes through actual refresh, generation reconciliation and durable storage; concurrent callers do not race token rotation. Provider-required reauthorization is distinct from transient failure. |
| Replace a configured value | A normal client with the configured placeholder succeeds; unrelated, ambiguous or mismatching input does not select or reveal a credential. Existing insertion-only rules retain their behavior. |
| Apply no response content filter | Supported responses retain their logical content without a user-written field allowlist; protocol, size, timeout, target, safe-header and disclosure controls still apply. Unsupported formats are explicit, not silently transformed or advertised as supported. |
| Complete a provider workflow | One understandable preset covers the necessary bounded operation bundle, such as Gmail list, pagination and message reads, or npm prerequisite reads plus publish. Prove the ordinary client can complete the operation, not just one hand-crafted endpoint call. |
| Approve a requested action | A real attempted operation creates a pending review showing the exact action, expiry and affected account; approve, deny and timeout produce visible outcomes. Fresh one-use approval admits only the bound action, and the client has a supported continuation or explicit retry path. This workspace integration remains open. |

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

Per-rule header replacement is implemented in the catalog, UI and Rust source;
actual proxy acceptance remains separate. Google profile integration and the
real-provider consent/refresh journey are still open requirements. Do not
present inactive OAuth controls, a health check, fixture-only browser success
or a JSON-only response mode as completion of those journeys.

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
| ECR image publication | Select account, region and repository; require approval for the exact image. | Request-bound, one-use human approval before credential use. Publication is not enclave deployment or attestation. |
| Ordinary API client | Store the key; select destination and credential placement. | Application identity, explicit destination/operation permission and exact replacement semantics; no compulsory content projection. |

These are user-facing presets over the existing policy mechanisms, not reasons
to expose their entire schema during credential creation. The current generic
rule editor cannot express all of them; the README explicitly keeps ECR-specific
integration open. Selecting a restriction still requires its actual request and
response enforcement, and choosing an unfiltered mode must not silently discard
it.

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
Request-triggered approval, as in the ECR example, requires a pending-actions view, an exact-action review,
the configured hardware ceremony, and a visible terminal result. A rejected,
expired or uncertain action must not silently resubmit. Whether a client waits
or deliberately retries depends on the implemented provider protocol; the UI
must not promise transparent continuation where only an explicit retry exists.
An approval notification contains no provider secret. Current operator catalog
routes and navigation do not provide this workflow.

Account connectivity/refresh health, application-token validity and actual rule
activation must be three separately visible states. A healthy Google grant does
not renew an expired Serverware application token. A temporary refresh failure
must not be labeled lost consent without provider evidence. Existing Google
disconnect/reconnect and native ownership boundaries remain explicit; do not
work around them with a pasted refresh token or a hidden legacy fallback.

## Remaining ordinary-client usability gaps

The current source is not yet a general "just replace authentication" proxy.
Removing mandatory response projection solves only one part of that journey:

- In the existing UI and legacy rules, an empty request-field list forbids a
  body. The additive source mode preserves bounded strict JSON without field
  declarations; it must pass backend verification and have accurate mode-aware
  UI summaries before being exposed. Collapsing the form alone is not support.
- Query names default to none, and forwarded client headers default to
  `accept` and `user-agent`. An example-request importer could suggest those
  names locally for explicit approval; it must not silently broaden access.
- Generated cURL remains a connection template, without body or query values.
  A complete example would need supplied sample input and must not execute
  automatically.
- Whole-JSON responses retain status-code, body-presence, size and safe-header
  restrictions. The existing UI and legacy whole-JSON envelope do not support
  `204 No Content`; the additive source contract admits it only through an
  explicit paired mode. Text, binary and streaming remain open compatibility work. The current
  CONNECT parser also requires canonical query ordering. Ordinary-client
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
