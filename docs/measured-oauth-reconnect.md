# Controlled measured active-family reconnect

This source path replaces one existing OAuth credential with a freshly verified
same-account encrypted successor. It is not new-credential issuance, Setup,
provider revocation, retired-family succession or automatic credential recovery.
Source changes have not been built, tested or exercised against a provider.
Native helper/signing/browser startup is a separate required producer join.

## Independent permission and original windows

The cold control-plane profile is `serverware.oauthApplicationStartup/v4`.
It retains the actual existing enrollment/configuration/custody owners and
encrypted client material, plus separate sealed root/grant descriptors. The fixed
delivery paths are `/run/serverware/authority-trust/oauth-reconnect-root-public-key`
and `/run/serverware/authority-trust/oauth-reconnect-authorizations.json`.
The root must differ from enrollment and runtime configuration roots. The
authority independently checks its signed `oauthMeasuredReconnectPolicy`, enabled
operation inventory, enrollment signature and purpose-specific family signature.
Browser input cannot provide those roots, descriptor paths or authority URLs.
Old startup v1–v3 and old issuance/Setup signed bytes are not widened.

`serverware.oauthFamilyReconnectAuthorization/v1` has exactly25 fields. Its
independent signature commits the target ID/N, exact credential and generation
rows, actual enrollment/client/provider/subject/account, requester, desired
scopes, original metadata, entire affected local family and explicit external
family-replacement permission. It also commits distinct absolute contact,
retention, pending and final expiries. The interval is at most one hour; contact
is at most600s, additional retention at most600s and pending at most3600s after
contact. Native phases copy these expiries rather than generating new windows.
Every individual authority exchange is bounded by an original<=30s operation
deadline. A new browser action, consumed receipt or observed ciphertext grants
no renewal or retry.

Local complete inventory is not proof of global provider-family ownership.
The independent family grant explicitly covers external family replacement
effects. Existing account-family retirement and conservative provider-wide
retirement fences refuse this ordinary reconnect. No code clears those fences.

## Actual ordering

1. Current OIDC requester/CSRF, cold grant and enrollment produce a fresh actual
   hardware assertion for `oauth.reconnect.authorize`. The protected writer
   reserves one immutable authorization ID and retains exact signed grant,
   enrollment, requester policy and affected credential/head originals.
2. Only the returned definite signed result allows the same retained HTTP owner
   to coordinate real all-holder drains. All affected current roots must be open
   initially. Each actual registered holder must acknowledge drained sends and
   blocked version. Missing holders or an elapsed deadline are not drain proof.
3. `oauth.reconnect.fence` atomically consumes all admitted barriers and changes
   the target to `reconnect_pending`, other affected credentials to
   `reconnect_fenced`. It records the exact barrier vector and request digest.
   Its admission deadline is the authorization's original<=30s window. It never
   changes token bytes, contacts a provider or creates a new currentness epoch.
4. Only a definite fence response produces the native intent. The portal sends
   `base64url(canonical ASCII intent)` directly to the admitted distinct origin's
   `/oauth/begin#original=...`. No CP draft fragment or legacy human PREPARE
   conversion is used. The native owner must independently verify the actual
   signed fence frame, result, grant, enrollment and exact original rows before
   generating PKCE. Machine-only `oauth.measured-reconnect.prepare` then admits
   the separate native purpose proof and sealed private state.
5. The helper claims once before its single token POST, captures encrypted exact
   reply/issued material, verifies provider identity and stages a same-account
   candidate encrypted for the actual target ID/N+1. The CP never decrypts or
   re-encrypts tokens. PREPARE/CLAIM/CAPTURE/STAGE/RECOVER/CANCEL preserve their
   own signed labels/domains, independent role-4 assignment and original owner.
6. Candidate approval uses a fresh requester hardware ceremony, a distinct
   current credential owner with their own fresh hardware ceremony, and a new
   requester assertion at activation. The protected transaction compares the
   exact candidate, original target/head/fence and unused approval, writes N+1
   encrypted bytes, creates its new strict currentness root and consumes the
   approval. Other affected credentials remain fenced. Old encrypted originals
   and all transition/capture history remain retained; no automatic revocation
   work, token-validity assumption or currentness reopen is produced.

The actual controlled-writer response is a signed committed-state receipt under
the configured **trusted-host-local** consumption profile. The current authority
consumer explicitly refuses unsupported TEE/external-witness prerequisites.
That receipt must not be described as produced native TEE custody attestation.
The helper's genuine native role-4 proof and independently assigned family root
are separate checks; full production attestation acceptance remains open.

## Fixed originals and bounds

The schema is `schemas/oauth-measured-reconnect-authority.v1.schema.json`.
Native statement23 uses `serverware.nativeOAuthReconnectStatement/v1`, signing
purpose `nativeOAuthReconnectExchange.sign/v1`, statement-schema+NUL signature
preimage, and its own `serverware/native-oauth-reconnect-attestation/v1` NSM
domain. Native arguments12 add the raw signed authorization (base64url) to the
existing scalar field names; every phase request includes `fencedRowSha256`.
Assignment is nonnull even for PREPARE and is independently re-admitted.

The immutable authorization journal17 contains canonical raw grant/enrollment,
initial affected `{credentialOriginal,generationOriginal}` pairs in grant order,
authorize/fence argument originals and digests, barrier vector and original
times. Native custody20 retains preparation, claim, capture, recovery, candidate,
committed target and predecessor originals. The encrypted candidate is exact12.
The native business result is exact6 with `originals` exact FOUR:
`journalOriginal`, `exchangeOriginal`, `custodyOriginal`, `candidateOriginal`.
These are raw canonical ASCII strings, not base64. Before native PREPARE the
last three are null. Human activation results add actual approval/credential
projections without exporting ciphertext to the portal.

Grant<=64KiB, argument<=2MiB, each retained row<=4MiB, candidate<=512KiB,
machine request<=3MiB, signed authority response<=6MiB and outer response<=8MiB.
Every allocation/parse boundary retains its own fixed bound. Intent10<=8MiB
contains base64url actual signed fence request/response originals. They remain
outside the64KiB private state; private state is old21 scalar names plus separate
`reconnectBinding`7 and the new `nativeOAuthReconnectState/v1` label. No previous
purpose's sealed state or successful response is converted.

Helper cold configuration18 is the previous inventory/window/identity field
set plus `reconnectLimits` exact3: affected7, history64, max grant3600s. It has its
own `nativeOAuthReconnectExchangeConfiguration/v1` label. Outer native startup
and actual private helper construction are separately source-selected by their
owner; incoming browser fields cannot select a profile.

## Bounded complete acquisition

Admission supports at most7 affected lineages and64 retained reconnect journal
rows. AUTHORIZE separately proves the complete journal root before inserting a
new slot. FENCE proves full credentials65, pending65, Setup65 and the existing
fixed two-family-fence group with effective declared34. Each independent family
table still has its own limit33/read work/root proof and combined observed cap32;
neither root is omitted. Seven exact head/root/barrier triples add21. Exact
journal, current actor role, provider-scope fence and audit row add4: total254
declared rows, below the unchanged global256. All actual acquisition paths use
the existing fixed group metering before proof construction. No generic budget
subtraction or proof-cap increase is introduced.

PREPARE independently proves the existing complete exchange-reservation root
before its new row. Larger populations, sentinels, missing members, unknown
metadata or any inactive/previously fenced member refuse; no truncation or
absence inferred from a subset. Existing same-family pending material or an
active Setup referring to an affected credential also refuses. Stage/activation
consumers use their already authenticated complete credential root to refuse
competing same-family publication while the reconnect target is pending.

These are explicit implementation capacity limits, not permission to prune,
archive, migrate or reset history. Capacity/migration are separate required work.

## Operator flow and interruption

The portal's controlled reconnect panel lists only cold-admitted requester grants.
It reviews the exact affected family and original expiry, then uses fresh passkey
options and one irreversible authorize/drain/fence submission. Distinct approvers
inspect the exact authorization ID and staged account, request/decide/activate via
the dedicated endpoints. It never stores assertions or automatically resubmits.
An unknown response burns the browser's attempt latch; the protected ID/rows
still reject replay after reload.

`GET /api/oauth/reconnect/{authorizationId}` is authenticated read-only inspection.
Missing retained association reports **outcome unknown**, not completion or
safe replay. A partially drained or fenced operation cannot reconstruct a native
handoff from this observation. There is no continue-fence/reopen/reset endpoint.

`POST /api/data-plane/oauth-reconnect/original` acquires actual retained encrypted
originals for a separately cold-selected recovery target. Its exact6 response is
schema, `okForAction:false` and the four originals. Only a fresh independently
admitted RECOVER may process already captured material within the original
pending expiry; it cannot send a second token POST. Staged/committed recovery
returns observation only. Missing capture/acknowledgement never proves no effect.

Audit events stay real pending outbox work; a transition digest does not imply
completed external audit. Old provider tokens are not automatically revoked or
declared valid. Retired-family succession, disposition of non-target fenced
lineages, uncertain pre-capture cleanup, later Setup adoption/completion,
history-capacity migration and full production/runtime acceptance remain
explicitly required successors rather than claimed closure of O01/O03/O04.
