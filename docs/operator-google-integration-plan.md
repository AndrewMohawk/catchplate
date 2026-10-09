> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Google account integration into the operator workspace

## Status and objective

Current joined checkpoint, 2026-10-09: the isolated **Read Gmail** job passed
list/pagination/message reads before and after actual synthetic-token expiry:
eight proxy requests, one automatic refresh and eight matching audit attempts.
The same account and application continued without reconnection. This used
Requests with a CONNECT Bearer adapter, not a stock Google SDK or real Google.
See the [ordinary-client Gmail job record](operator-gmail-job-verification.md).

The earlier fresh isolated V2 run passed
consent/callback/account storage, access-denial controls, two normal Rust proxy
requests and automatic refresh across actual synthetic-token expiry. The
response-header blocker is repaired for this supported JSON contract. Google
remains disabled in the live demo: this is synthetic provider/backend evidence,
not real Google consent, a joined browser journey or deployment. See the
[current acceptance result](operator-google-backend-verification.md#v2-joined-synthetic-refresh-passed).
Earlier failures and the open provider/browser/lifecycle requirements remain
recorded below; they are not erased by this focused success.

The consent UI is now wired in source: the catalog advertises only a validated
Google profile, the owner explicitly continues to Google, and callback return
selects an account only after joining the actor's saved intent to a fresh active
catalog record. Backend callback/discovery checks and intercepted browser checks
pass separately; they do not establish a joined real-provider browser journey.
The exclusive connection-method layout is now deployed with the ordinary
synthetic demo; this does not enable Google. An additive **Read Gmail** bundle
is now implemented in the working source, covering list, pagination and
individual message reads without endpoint or response-field setup. Its separate
verification status is below. See [consent UI verification](operator-google-backend-verification.md#consent-discovery-and-return-ui-checks).

### Read Gmail source checkpoint, 2026-10-09 UTC

The new closed `gmail_read_v1` catalog bundle uses the `gmail.read.v1` adapter,
whole required JSON responses, and explicit `orderedFormV1` query handling.
It does not include mail-age enforcement, sending, mutations, attachments,
history, threads, Calendar, arbitrary response formats or general SDK support.
Existing exact rules and retained pre-query bundle rows keep their original
contracts. Malformed or unavailable capabilities do not silently fall back.

Independent source review covered catalog, Python, Rust and UI changes. The
browser checks passed one pure group and 17 rendered groups across two runs:
the initial run passed nine rendered groups, then a Playwright FIELDSET matcher
assertion failed. A test-only correction checks the native fieldset property
and disabled child controls; the eight remaining groups passed. Production UI
files were unchanged between those runs. Screenshots were inspected at desktop
and mobile sizes. The fixture intercepts backend traffic: no real consent,
proxy requests or generated client commands ran.

The paired source snapshot is Git tree
`3ee51abcab363e22fc3fa989eb2f599cab310d08`, with 4,730 files. Its archive SHA-256 is
`762db37ee4bb4bef5347f711e0b0c58c85ed6e73564f33707c88b696d8460b11`.
Evidence is retained in `gmail-bundle-ui.McjCz3rt` and
`gmail-final.1heE61Lq` under the operator workspace evidence directory.
On the final snapshot, all 32 selected Python groups passed in 75.161 seconds:
12 query-parser, nine integration, seven catalog and four existing controls.
They ran without networking, with read-only source/root, one CPU, 1 GiB RAM,
no additional swap, 96 PIDs and a 900-second deadline. Source and archive were
unchanged; the container exited normally without OOM. The result receipt
`gmail-final.1heE61Lq/python.test-result.json` has SHA-256
`36027fdc74b6858f840036d2a6eb2d98db6a7c328c4c02d220596a208dd5b678`.
Earlier Gmail batches retain their failures: JSON MIME admission, then a test
that incorrectly put overlapping old and new routes on the same app. Those
were corrected separately; this targeted run is not a full-suite pass.

The Gmail Rust changes now have compiled and focused-test evidence, followed
by an isolated ordinary-client list/paginate/read job across actual synthetic
token expiry. The [verification record](operator-gmail-job-verification.md)
distinguishes the historical harness results from the final production parser
correction and its six focused checks. This is not a full-suite or real-provider
acceptance result. A URL-library limitation refuses raw apostrophes
when parsing would rewrite their spelling; percent-encoded `%27` is the intended
supported spelling. Query helper tests alone do not establish wire acceptance.

This source checkpoint does not enable Google in the live demo or change native
pilot status. Account health, provider-aware reconnect/disconnect, managed app
identity renewal, and ordinary response-header semantics remain product work,
as documented in [the requirements](operator-workspace-requirements.md).

Originally designed against workspace commit `10879772`. The 2026-10-08 shared
working-tree checkpoint now contains cold profile, consent/catalog,
generation-reconciliation and local cleanup-fence source. It is **not releasable
or deployed**: backend and Rust acceptance remain incomplete. The first focused
cleanup batch passed one case and failed the next during Google rule schema
admission, before its cleanup assertions; 18 cases were unattempted. That
failure is retained separately from subsequent corrections. Individual source
checks or focused tests do not establish complete end-to-end acceptance.

The corrected clean `71aa1ec5` batch passed five focused cases, then failed cold
restart because the new cleanup trigger was attached to a v9 schema-pinned core
table but absent from its expected manifest. Sixteen selected cases were
unattempted in that batch. Do not bypass that guard or repair a retained/live
database in place.
See [backend verification](operator-google-backend-verification.md) for exact
historical failures and subsequent repair evidence.

The reviewed `51ee05e6` repair makes the operator-owned association the durable
source of cleanup ownership. It places no trigger on the v9 core table. The core source
is a checked mirror: changing it cannot turn owned work into legacy work. A
persistent side-table deletion guard admits only validated transactional
adoption or fenced cleanup completion. Missing or changed retained ownership
schema is refused, not recreated; only a genuinely new profile initializes it.
Eight selected checks passed on that repair before a test misclassified runtime
profile drift as cold unconfigured startup. The corrected `0bcfac30` batch then
passed the remaining 26 selected cases plus a new cold-start group. Production
Python inputs stayed identical between the two batches. These are 35 distinct
focused successes across two runs, not one full-suite pass. Twelve compiled
Rust reconciliation tests also passed separately against synthetic transport;
a current deployable gate and real consent/refresh acceptance remain open.

Read with `operator-workspace-requirements.md` and the OAuth onboarding section
of `goal.md`. R96 remains terminal: no restart, new enrollment, real provider
contact, configuration change or native authority is authorized by this plan.

The journey is connect Google once, choose an application, allow its operations,
then use the ordinary proxy client. Serverware refreshes access automatically.
Applications never receive provider tokens. Account consent, application-token
rotation and access-rule publication remain separate operations.

## Explicit development boundary

Add an opt-in `operator-google-v1` capability to the operator-development profile,
not a blanket removal of the `SERVERWARE_GOOGLE_*` prohibition. Admit only a
configured Google client, private client-secret file, exact HTTPS callback,
fixed provider endpoints, bounded permission presets and pinned API origins.
Persist the client/callback binding; reject silent application changes on restart.
Keep existing static workspaces and their policy bytes unchanged when disabled.

Preserve `oauth_application_owner` selection and `_require_application_lifecycle`
unchanged. A configured enrolled owner cannot fall back to development OAuth.
Native, broker, currentness, policy-aware and controlled release paths retain
their existing ownership, approval, lifetime and execution requirements.
Do not disable configured mutation MFA or two-person activation. Unsupported
protected combinations fail closed before provider contact, not by silently
switching to immediate development activation.

The current cold-profile source selects only the exact
`SERVERWARE_OPERATOR_GOOGLE_PROFILE=operator-google-v1` opt-in. Its initial
permission preset is `gmail_readonly`, with canonical scopes `email`,
`https://www.googleapis.com/auth/gmail.readonly`, and `openid`, and the API origin
`https://gmail.googleapis.com` must already be in the deployment allowlist.
The client ID, private secret file and exact HTTPS callback use the existing
Google configuration names. Only the operator start POST and exact Google
callback GET gain route exceptions; generic OAuth mutation namespaces remain
closed. The initial capability refuses configured mutation MFA/two-person
combinations it cannot fulfill. Supporting the protected journey remains a
requirement, not a permission to disable those controls.

## Implementation slices

1. **Cold profile admission:** `operator_demo.py`, `config.py`, and a focused
   `operator_catalog_oauth_profile.py`. Validate the complete capability and
   file/callback bindings before exposing consent. Admit exact required routes,
   not the entire legacy OAuth mutation namespace. Use existing configuration
   names for the client ID, secret file and redirect URI; no secret chat input.
2. **Consent intent:** add `operator_catalog_oauth.py` and bounded routes in
   `operator_catalog_api.py`. Retain metadata-only actor/provider/permission,
   reviewed catalog and state-digest bindings. No token, authorization code or
   PKCE verifier belongs in catalog metadata. Saving a connection grants no rule.
3. **Existing OAuth lifecycle:** connect existing `oauth.py` and `app.py` start,
   callback and activation paths to that intent. Reuse S256 PKCE, one-use state,
   browser-bound Secure/HttpOnly cookie, verified Google subject and granted
   scopes. Validate intent after state consumption but before exchange. Preserve
   retained issuance/cleanup work, duplicate-account checks and configured MFA.
   Harden state-file durability. The checkpoint includes a shared state-file
   fsync writer, also affecting legacy state persistence; crash/failure and
   regression evidence are still required, and its
   private-file PKCE verifier must not be described as encrypted storage.
4. **Atomic registration:** retain `db.credentials` as the only token store.
   `db.create_credential(..., _connection=conn)` permits active credential,
   catalog registration, intent completion, revision and audit to commit together.
   For protected pending activation, extract a transaction-owned primitive from
   existing DB activation without removing requester, approval, identity, expiry,
   collision or ownership checks. Join catalog registration to the same commit;
   do not insert an active credential through a generic substitute. Pending
   accounts remain unassignable and cancellation retains existing cleanup.
5. **Catalog and rules:** extend `operator_catalog_schema.py`, mutations and
   policy compilation with a managed-Google variant. Bind immutable verified
   subject, OAuth client ID and canonical scopes; derive current generation and
   expiry from the core credential. Compile `credentialType: oauth2`, exact route
   binding and `Authorization: Bearer` injection from `access_token` only. Reuse
   the Gmail read-only example; optional age restrictions retain the Gmail
   adapter's response evidence. Never accept pasted refresh-token JSON.
6. **Usable UI:** extend operator portal assets with Connect Google, verified
   account/permissions, pending approval and affected applications. Distinguish
   account health, client-token validity and loaded rule activation. Derive
   reauthorization-required from bounded provider evidence, not every 503 or
   timeout. Temporary and uncertain refresh outcomes must remain distinct.

## Cleanup fencing: source implementation, acceptance open

The required protocol below now has a source implementation in
`operator_google_cleanup.py`, `operator_google_cleanup_store.py` and the existing
OAuth/database owners. Do not deploy or enable real Google contact while its
acceptance remains open. At the preceding checkpoint, the duplicate-account
callback could poison the whole catalog: the existing
grant-family quarantine changes an already connected core credential to
`revocation_pending`, but its catalog credential and rules remain active.
`schema.validate_bindings` then rejected the core/catalog mismatch before catalog
reads and mutations, including operations on unrelated static credentials.
Keeping the existing grant-wide collision guard is mandatory; bypassing it is
not a repair.

A callback-only quarantine transaction also does not establish cleanup safety.
`db.claim_oauth_revocations` automatically promotes expired `held` work to
`pending` and the background reconciler can revoke it independently. The token
exchange/refresh retention-failure paths can invoke immediate revocation, and
other post-contact failures can mark work pending. Google grant-wide revocation
can therefore affect a previously connected account before its local access is
fenced, even when the callback itself skips generic cleanup.

The minimum required protocol is:

1. **Reserve immutable operator cleanup ownership before contact.** Both initial
   authorization-code exchange and managed-account refresh must reserve work
   under a server-owned, immutable canonical association and atomically retain a
   token-free association before any provider request. Bind the actual work ID,
   operation kind, admitted profile/client, consent intent or existing credential
   and generation, and verified account identity when available. Codes, tokens,
   PKCE verifiers and browser nonces do not belong in this association. Caller
   metadata cannot select the source or create the association. A missing,
   malformed or mismatched association on operator-tagged work fails closed;
   retained ownership also remains protective if the core tag changes or the
   core row disappears. Neither case converts the work into ordinary legacy
   cleanup. Disabling the opt-in cannot authorize a generic revocation fallback
   for the retained operator account store.
2. **Make cleanup eligibility durable, not a callback-local decision.** Generic
   held-work promotion, pending claims, background/restart reconciliation, and
   every immediate revocation fallback must refuse operator work without its
   matching committed cleanup fence. A timer extension, delayed callback or
   transient boolean is insufficient. Preserve ordinary/native cleanup owners;
   do not make this development capability an alternate enrolled revoker.
3. **Retain uncertain work without guessing the account.** Before verified
   identity is available, or when a fence cannot commit, retain available
   encrypted material and issuance-uncertainty evidence for bounded manual
   review. Do not automatically revoke a guessed family, retry the provider
   exchange, release retained work, or infer that no token was issued. If durable
   material retention itself failed, report that uncertainty rather than claim
   the token was retained or safely revoked. Bounds and exhausted-capacity
   refusal remain mandatory; unavailable cleanup authority does not justify
   unbounded work accumulation.
   A verified identity with **no retained local family** also stays deferred for
   manual review. An empty snapshot is not a durable ownership exclusion: a
   second consent could issue/adopt tokens between a cleanup permit check and
   provider revocation. The current source refuses empty-family fences and
   existing empty receipts rather than enabling that race. A future automatic
   cleanup design needs durable exchange/family lifecycle serialization; an
   adoption-time check alone does not close issuance-before-cleanup races.
4. **Fence known-family access in one publication transaction.** Use the existing
   operator order: process-local publication lock, shared-volume EX lock, then
   one SQLite transaction. A caller-owned form of the existing grant-family
   quarantine must retain its identity, generation, encryption, collision and
   audit effects without opening another connection or committing independently.
   In that same transaction, bind affected managed catalog credentials to the
   real quarantined core rows, revoke their active rules, publish the reduced
   signed policy, advance catalog revision, record the failed consent/operation
   disposition and audit, and durably authorize only the matching cleanup work.
   Preserve unrelated applications, static credentials and rules. A quarantined
   account is neither a deleted secret nor proof of completed provider revocation.
   Keep its retained core/catalog identity verifiable so the remaining workspace
   stays usable. Do not weaken active-credential validation globally.
5. **Separate committed and deferred outcomes explicitly.** Failure before a
   successful commit rolls back the whole fence and leaves cleanup ineligible,
   including after the old held-work timeout and a process restart. An uncertain
   commit outcome is not proof of rollback: reobserve the existing durable fence
   under its owner before deciding eligibility, without replaying provider work.
   A typed deferred result must not fall through the generic persistence-error
   handler that revokes rejected exchanges. Once committed, keep a typed
   committed receipt containing the exact fence/work/policy/revision bindings.
   Materialize the committed policy while still holding EX; a materialization or
   post-commit guard failure is pending publication, not rollback and not
   permission to run duplicate generic quarantine. Retain the database's
   authoritative fence for restart recovery. Neither a successful file write
   nor a receipt alone proves the gate loaded the reduced policy.
6. **Release publication/SQLite ownership before provider cleanup.** Only the
   existing provider-aware cleanup mechanism, after checking durable eligibility,
   may contact Google. Never perform provider I/O while holding EX or the
   registration/quarantine transaction. Preserve its bounded retry, uncertain
   outcome and retained-work semantics; do not replay consent, refresh, upstream
   application operations or controlled issuance claims as a cleanup shortcut.

These controls cover both initial exchange and refresh: identity/scope refusal,
duplicate-family collision, stale catalog review, registration/update failure,
retention failure, crash recovery and rejected refreshed material. Handling
only the explicit duplicate-collision exception leaves other cleanup sinks open.
The admitted operator profile is SQLite-only; the caller-owned helper
does not authorize changing PostgreSQL/native lock ordering or ownership.

Known-family fences retain quarantined core rows as the local exclusion against
new adoption; successful provider cleanup does not delete that exclusion or
claim external project-wide ownership. Publication failures retain a committed,
pending receipt. Public presentation keeps provider revocation `not_proven`.
The [presentation checkpoint](operator-google-presentation-verification.md)
does not substitute for backend or provider verification.

## Generation reconciliation: a separate correctness prerequisite

The baseline legacy lease path refreshes in `_credential_for_lease`, then checks
the resulting generation against the caller's earlier metadata pin. A changed
generation returns 409 before secret-envelope creation. The original Rust
`fetch_scoped_credential_lease_on_deadline` and
`ensure_scoped_credential_lease_on_deadline` behavior propagates that failure
rather than reconciling it. The checkpoint's new reconciliation source still
requires the full protocol and evidence below; direct refresh tests do not prove
unattended proxy use.
Do not move refresh into the authority-free `generationMetadata` read.

An ordinary or even signed **409 is not retry authority**. Current source:

- `data_plane_credential_leases` durably reserves the recipient nonce before
  refresh; the operator replay cache commits that reservation separately.
- `_claim_credential_lease_release_authorization` may also claim controlled
  issuance before refresh. Error handling audits and rethrows; it does not undo
  nonce reservation or a claim. Other 409 branches occur after encryption.
- The response signature binds method/path/query, status, response body and
  response nonce. It does not independently bind the complete lease request body.

A candidate reconciliation protocol is acceptable only with all these checks:

1. Emit a new closed, versioned **no-secret-envelope-issued-for-this-attempt**
   outcome only at the definite pre-encryption generation-conflict branch.
   Provider refresh may already have committed; this is not a claim that no
   provider request occurred or that no secret was handled internally.
2. Before emission, prove explicit development capability, unchanged active
   policy, exact Google binding, definite current committed generation, no
   controlled dispatch, no request/release authorization, and no issuance claim.
   Exclude native/enrolled/broker/currentness/policy-aware paths entirely.
3. Put the exact lease request-binding digest, policy hash, scope/principal/route/
   credential IDs, binary digest, recipient key/nonce binding and expected
   generation/metadata digest in the signed response body. Strictly verify this
   outcome against the original request and existing trusted response context;
   neither status text nor a client-supplied retry flag is sufficient.
4. Keep the original nonce spent. Never release, reset or prune replay state to
   facilitate retry. Obtain fresh metadata and fresh recipient material/nonces
   for subsequent lease requests. Replay-cache capacity failure remains a failure.
5. Invalidate only the matching stale cache entry without lowering generation
   floors or deleting a concurrently installed newer generation. Do not broadcast
   a request-bound outcome as permission for different single-flight waiters.
6. Permit at most one reconciliation before upstream dispatch. Establish a finite
   absolute operation deadline before the first acquisition; an absent deadline
   is not a valid bound. Preserve it through metadata reread, single-flight waits
   and reacquisition. Recheck policy/application authorization before sending.
7. Never replay an upstream API operation, a controlled claim or an ambiguous
   provider exchange. Missing/malformed signatures, mismatched bindings, timeout,
   interrupted response, post-encryption errors or a second conflict fail closed.

This protocol requires complete implementation and deterministic evidence;
neither the existing 409 branch nor in-progress helper code alone can safely
enable it. Keep native behavior unchanged.

## Disconnect and reconnect

Application/rule revocation removes only that application's access. A shared
Google credential must not enter the static credential-delete path. Explicit
disconnect first requires an affected-assignment workflow, then uses the
existing provider-aware pending/failed/retry lifecycle. This is distinct from
reauthorizing an active account: renewed consent for the same verified account,
client and permissions must preserve its application assignments, not require
disconnecting and rebuilding them. Google's grant-wide revocation prevents
treating a superseded token as independently revocable; it does not require
revocation before same-account reauthorization.

The current generic reconnect writer queues superseded-token revocation and
therefore correctly refuses Google. Do not remove that guard. The operator now
has a separate [same-account reauthorization workflow](operator-google-reauthorization.md),
preserving the original enrollment binding, advancing the credential generation
atomically, and keeping unadopted or uncertain candidate tokens in non-revoking
custody. Its source and focused verification status are recorded separately;
this does not establish deployed or real-provider acceptance. No provider
exchange may be replayed merely because its response or commit was lost.

An explicitly disconnected or quarantined account is a different recovery
case. Reauthorization must not bypass its retained cleanup exclusion, silently
restore revoked rules, or interpret provider revocation acceptance as proof
that revocation has fully propagated. Do not bypass duplicate-account guards;
prefer reuse of an already connected account. Local removal is not forensic
erasure or provider-side revocation. Disconnected-family succession remains
unfinished and is not implemented by active-account reauthorization.

### Definite refresh rejection and uncertain retirement

Active-account reauthorization first needs an accurate refresh outcome. The
operator previously classified every failure without attached token material
as uncertain issuance, including an explicit rejection from the token endpoint.
That can leave an otherwise unchanged account with an unresolved reservation
which cannot legitimately be interpreted as issued tokens or safely discarded.

The operator-only refresh path now distinguishes a bounded, duplicate-free
JSON rejection from an unknown response. Its closed error/status pairs follow
[RFC 6749 section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2): the six
standard token errors on HTTP 400, or `invalid_client` on HTTP 401. Wrong media,
unknown fields or errors, duplicate keys, contradictory token fields, HTTP 200
error objects, malformed responses and lost responses do not prove rejection.
Identifiable tokens in a parsed contradictory response still enter encrypted
custody before that response is refused; they are not silently discarded.

A fresh one-use rejection observation is bound to its exact work, profile and
OAuth client. It may retire only an unchanged, empty, in-flight refresh
reservation, with a redacted audit event in the same transaction. It changes no
credential generation, application, rule or policy and makes no revocation
request. Historical uncertainty, initial consent and material-bearing work
cannot enter this path. A lost local commit acknowledgement is a separate
uncertainty: only the exact audit event plus absence of both owned work rows
establishes retirement; missing work alone does not.

The provider rejection and local retirement results remain separate. Neither
authorizes an automatic exchange replay, proves account health, or implements
reauthorization. In particular, `invalid_client` calls for administrator
configuration review, not an unconditional request for the user to reconnect.
Google documents those distinct [error meanings](https://developers.google.com/identity/protocols/oauth2/web-server#errors).

#### Focused refresh rejection result, 2026-10-09

Frozen commit `2075558b3f8750ee52bfa6e90e445057493304ef` passed all eight
selected groups in one fail-fast run, with 16 sequential cold-process cases.
The unittest log records 214.017 seconds, with no failures, errors, skips or
retries. Coverage includes all supported rejection pairs, ambiguous empty
responses, custody of contradictory token-bearing errors, refusal for initial
or older work, current-generation binding, audit rollback, lost commit
acknowledgement, one-use observations, successful refresh and restart recovery.
Existing account permissions and policy bytes remain unchanged on definite
rejection. Historical uncertainty is not retroactively cleared.

The tests use real SQLite, encrypted storage, policy signing and production
refresh/retirement code, with synthetic provider transport. Size controls test
the classifier, not the underlying HTTP reader. This is not a full-suite,
browser, Rust proxy, active-account reauthorization, real-Google, native-pilot
or deployment result. The live demo was not changed.

Evidence: `google-refresh-rejection.RWm7Qeez` under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence`.
`test-result.json` SHA-256:
`f85fb1a54993036a5f3c3061960ec45292166b0b540b6279f941096e66c275d4`.
The frozen 4,765-file source manifest passed before/after checks and an
independent host check after process exit; its SHA-256 is
`61387aff80f816b95d7bf6ec3979f07b08905d1e50bdaa8719d0aa22af7164a9`.
The cached-image container ran with network disabled, read-only source/root,
UID 1000, one CPU, 1 GiB RAM, no additional swap and 96 PIDs. Its actual terminal
state was exit zero, PID zero and no OOM. Independent result review found no
contradiction. Only the exited container and 202 MiB task scratch were removed
after terminal, mount and visible-open-file checks. `cleanup-receipt.json`
records the visibility limit and verified removal; committed source and durable
evidence remain.

### Explicit disconnect backend, October 9 source work

The new backend slice separates an explicit administrator disconnect from
rejected-consent/refresh cleanup. Its source has passed independent review and
all 13 selected synthetic backend test groups. It is not deployed, browser-wired,
real-provider verified or a reconnect feature.

`POST /api/operator-demo/oauth/google/disconnect` requires the target account,
catalog revision and policy hash, the complete sorted set of affected active
rule IDs, and an explicit project-wide revocation acknowledgement. The server
recomputes impact; the submitted list cannot narrow the account's affected apps.
`GET /api/operator-demo/oauth/google/disconnect/{credential_id}` observes the
initiating administrator's retained operation without repeating the action.
A missing operation is not evidence that an uncertain mutation rolled back.

The transaction joins encrypted cleanup work, the local account fence,
revoked permissions, signed policy, audit and a durable public receipt. App
identities/tokens and historical rules remain; active rules are deliberately
revoked by the confirmed disconnect, not silently restored later. Provider I/O
occurs outside publication and database ownership. Provider acceptance must
commit with guarded work retirement; failed or uncertain outcomes remain
distinct from success. Deletion of temporary cleanup work alone proves nothing.

Worker selection and the final pre-contact permit both join the durable receipt
to the exact work, actor, profile, account family, original policy fence and
revoked assignments. Missing or corrupt ownership blocks provider contact while
retaining the encrypted work. Provider contact admits only pending/retry state;
guarded work retirement separately requires accepted state in the completion
transaction. Completion does not query management HTTP under the publication or
SQLite write lock. Its audit and reconciliation counter say provider accepted,
not revoked; the public `attempts` field counts failed/unconfirmed outcomes,
not all provider requests. Acceptance does not restore rules or enable reconnect.

Google documents account-grant revocation as affecting all clients and granted
scopes in the same project, with potentially delayed effect. A local account fence and an
administrator acknowledgement cannot establish control over external clients or
prove propagation. See [Google's revocation contract](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke).

This first backend version retains the family exclusion even after provider
acceptance and blocks new unknown-account consent while any disconnect remains.
Finalization, permission-preserving reconnection and its UI are still required;
"Connect Google" is not a workaround. Lifecycle storage is provisioned only for
fresh profiles. Older retained profiles remain unavailable for this new action,
without implicit schema reconstruction or backfilling live account state.

#### Focused backend result, 2026-10-09

Frozen commit `ba06b7363f649051a510ae382bfccc8884dccf0e` passed the nine new
disconnect groups and four existing controls in one fail-fast run. The unittest
log records 13/13 in 224.529 seconds, without failures, errors, skips or retries.
The new groups cover shared-account impact and unrelated-resource preservation;
exact review, authentication and input guards; signing/audit rollback; failed and
lost provider responses; durable acceptance across process restart; in-flight
consent/refresh refusal; committed publication failure; and missing/corrupted
ownership after a real worker claim, with zero subsequent provider contact.
Existing controls cover disabled Google capability, deferred empty-family
cleanup, failed callback cleanup and canonical successful consent.

The test uses real SQLite, policy signing, ASGI and the production cleanup
orchestrator, with synthetic provider transport. Completion is also checked for
absence of management HTTP beneath publication EX. This is focused backend
coverage, not a full-suite, browser, Rust enforcement, real-Google, propagation,
reconnect, native-pilot or deployment result. The live demo was not changed.

Evidence: `google-disconnect.5a3IHF03` under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence`.
`test-result.json` SHA-256:
`54ff59dd5d7f145064761e099fb15320aeedf011f0e319a2d1087e1ad9d4d65e`.
The exact 4,763-file source manifest, before/after manifests and frozen test IDs
agree; manifest SHA-256:
`b46065de97732fa5274e2ba2f6815a68facd9f6dc44d284c6f0fc26de37cb9b1`.
Independent result review found no contradiction. The cached-image container
ran with network disabled, read-only source/root, UID 1000, one CPU, 1 GiB RAM,
no additional swap and 96 PIDs; its terminal exit was zero with PID zero and no
OOM. Only its exited container and 105 MiB task scratch were removed after
terminal/mount/open-file checks. `cleanup-receipt.json` records the check's
visibility limit and verified removal, superseding the execution receipt's
earlier cleanup-pending field. Committed source and durable evidence remain.

## Verification and remaining user actions

Buildable without real consent: profile refusal tests; HTTPS provider-simulator
consent, browser/state, identity, duplicate-account, pending approval and rollback
tests; actual isolated Rust proxy use after token expiry; concurrent refresh and
generation-race controls; no-envelope proof and negative retry controls; shared
account revocation; restart recovery; and token non-disclosure in UI/logs/leases.
Assert the failed attempt's nonce stays reserved, a fresh nonce succeeds once,
controlled claims are never retried, and an ambiguous outcome sends no retry.

Cleanup-fence acceptance must additionally exercise the real background claimant
with aged held work, restart and missing-association controls; immediate
retention-failure paths; unknown identity; both initial and refresh operations;
and signing/catalog/audit/commit rollback. Before a committed fence, assert zero
provider revocation attempts and no cleanup eligibility. After a commit followed
by materialization failure, assert a retained committed/pending receipt, no
duplicate quarantine, no newly granted access, and recoverable publication.
After duplicate-family quarantine, assert the affected rules are absent from the
new signed policy while catalog reads and unrelated static/application changes
still work. Provider cleanup success/failure must not corrupt those bindings.

Real Google proof still requires administrator provisioning of the OAuth Web
application, enabled intended API, exact registered HTTPS callback and private
client-secret file; a choice of least permissions and authorized test account;
account-owner consent in Google; and separately authorized deployment/routing.
Then prove consent -> proxy request -> expired-token refresh with the real
account. No pasted refresh token or secret in chat is required. Source/simulator
success is not deployed provider integration or production/native acceptance.

The retained synthetic demo is not configurable into real Google merely by
adding environment variables. `operator_demo_store.initialize()` pins both
`allowed_upstreams` and `fixture_cidrs` to the data directory and explicitly
rejects a changed allowlist. Its control-plane container is also on the internal
synthetic network with no external DNS forwarding. Preserve its credentials,
application identities, policy and audit history. Real-provider rollout needs
either a separate reviewed deployment/data target or an explicit, reviewed
destination-migration workflow, plus bounded control-plane DNS/TLS egress and
the private Google secret mount. No retained database pin should be edited to
make an environment-only change appear valid.

The working source now provides an explicit
[reviewed first-Google setup transition](operator-google-setup.md), with an
[optional deployment layer](../docker/serverware-operator-demo/GOOGLE-SETUP.md).
Preparation leaves Google disabled; a controlled restart validates and applies
only the exact reviewed public configuration. These additions do not establish
a real-provider deployment or account consent. Their focused verification status
is recorded in the setup document.

For ordinary clients, distinguish the isolated HTTP-proxy CONNECT check from
the public HTTPS-proxy connection. Current workload identity uses proxy Bearer
authentication; standard Requests proxy-URL credentials generate Basic instead.
A supported Requests integration must keep proxy credentials out of upstream
headers. For the public HTTPS proxy it must also keep outer public/system trust
separate from inner Serverware CA trust. An HTTP-loopback fixture cannot prove
that second TLS layer, and a hand-crafted cURL success does not prove stock SDK
configuration. Managed app-identity renewal remains separate from Google refresh.
