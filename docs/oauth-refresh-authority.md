# Automatic due-only refresh authority

This source slice implements `oauth.refresh.claim`, `oauth.refresh.retain` and
`oauth.refresh.commit`. It is unbuilt, unexecuted and unprovisioned. It does not
prove provider authorship, O02 measured exchange, cross-deployment coordination,
or immediate invalidation of a lease already held by a data plane.

## Explicit current permission

Automatic refresh is authorized only by the mandatory `oauthRefreshPolicy`
block in the actual independently signed measured authority configuration,
with schema `serverware.oauthRefreshAuthorityPolicy/v1` and the three separately
enabled fixed operations. The verifier and planner each admit that original
configuration, purpose and enrollment independently. No additional envelope
duplicates the configuration signature. The signed enrollment authenticates
the current application; an old activation/consent approval does not grant
refresh permission.

The policy has exactly eight fields: schema, enrollment root raw public key and
SPKI hash, control-plane configuration digest, deployment ID, `dueWithinSeconds`,
`operationMaxSeconds`, and `revocationCapacity`. The latter three are source
capped at 300, 30 and 64 respectively, each at least one. Every request's exact
three-field `limits` must equal the admitted signed policy; a caller cannot
increase these bounds. Enrollment key separation remains unchanged. The
identity root cannot become a cleanup-effect root.

Permission covers only an active, enrolled OAuth credential with the same
verified provider account, application association, client, scopes and current
credential/generation heads, when its actual committed access-token expiry is
within the signed due window. It does not cover reconnect, setup, a manual
early refresh, another provider/client, cleanup, retry or changing an existing
expected-version release authorization. Those are separate required workflows.

## Original-bound transaction

The shared module is `authority_oauth_refresh.py`. Raw authority inputs are
exactly `credential_id`, `enrollment_original`, and `request`; no actor ID,
caller trust root, provider-success flag or caller-selected table is accepted.
Claim/retain/commit requests have eleven/nine/nine fields respectively. Results
have six fields, with only commit adding the exact public credential projection.
The paired [schema](../schemas/oauth-refresh-authority.v1.schema.json) is a
closed data projection, never signature, custody or effect authority.

`oauth_refresh_reservations` is a protected, source-keyed relation. Its stable
UUID is derived from the actual credential ID and current version, never a new
timer, grant ID or random retry ID. It retains exact sixteen-field credential
and three-field generation originals, enrollment bytes, signed-policy limits,
claim request digest, held-owner nonce hash, contact commitment and original
absolute bounds. Every subsequent phase compares those original heads and
owner possession, and independently rechecks current policy/enrollment.

1. Claim authenticates complete refresh/work inventories by reconstructing
   their primary roots against the same transaction's before-roots. A database
   `COUNT(*)`, truncated provider list or claimed empty page is not a capacity
   proof. Claim refuses an existing slot or another uncommitted refresh for
   the credential, checks actual due/refresh-token expiry, and reserves all
   issued-material capacity plus an X superseded-material slot before contact.
   Reservation rows and audit are committed atomically. The credential remains
   `active`; the exact uncommitted refresh row is the explicit issuance fence.
2. The actual client retains its original cold application owner and HTTP
   opening. Only a definite signed claim result plus exact row readback permits
   its one token POST. The request commitment covers exact URL, method, encoded
   body hash and actual constructed headers. No claim replay, deadline reset,
   implicit token retry or old runtime-DML refresh is used.
3. Retain stores the actual bounded raw response and issued-token originals,
   encrypted under deterministic refresh artifact IDs and version-one AAD,
   before replacement normalization. Raw response fields are actual status,
   raw headers and body, not a manufactured success. An absent usable issued
   token is explicit paired null and cannot commit. The received-at epoch is
   fixed at the original response observation, not taken from a later commit.
4. Commit requires those retained originals and unchanged original heads.
   It atomically writes the new envelope under the existing credential ID and
   next version, updates the genuine generation head, consumes issued-work
   reservation, handles the separately reserved X retirement slot, completes
   the refresh row and appends audit. It is not sequential consume plus runtime
   DML. The retained raw/issued originals remain in the refresh record.

Immutable metadata is compared as canonical bytes, preserving scalar types.
Only refreshability, Bearer token type, unchanged sorted scope set and bounded
access/refresh-token expiries may change. Replacement expiries are constrained
by the retained response's received-at origin and existing maximum token
lifetime, never a fresh timer at commit. Original refresh expiry cannot be
silently discarded. Omitted provider fields retain their original semantics;
explicit malformed/null values are not treated as omitted.

The actual client decrypts and rechecks the old association, exact raw/issued
retention and replacement originals. The pure metadata writer does not decrypt
them or pretend encrypted bytes independently prove provider authorship.

## Retirement is not a generic cleanup grant

Issued work has source `enrolled-oauth-refresh-issued/v1`; X superseded work
has source `enrolled-oauth-refresh-superseded/v1`. Before retention their states
are `refresh_in_flight` and `refresh_superseded_reserved`. Issued retention
changes its work to `held` or `refresh_issued_unavailable`. Successful commit
consumes issued reservation while retaining its original in the refresh row.
For X, the client derives only OLD access/refresh token fields whose exact values
changed; an unchanged shared refresh token is not queued for retirement. An
empty X subset consumes the unused reservation; otherwise exact ciphertext is
retained as `held` work. Google never receives a superseded token-family
revocation operation.

These sources are deliberately incompatible with the exchange-only current
revocation grant. Their independently authorized cleanup/uncertain-outcome
successors remain required work. Retention alone does not authorize contact,
and a local HTTPS response is not an independently signed provider revocation
receipt. No unknown response path deletes tokens, runs inline cleanup or tries
the POST again.

## Lease and interruption boundaries

Due refresh is triggered only before returning `generationMetadata`, before a
new caller pins that generation. `dispatchSecret` is read/check/refuse only:
it must observe an unfenced, unchanged, non-due enrolled version and never
transparently renew an already pinned expected version. Control-plane cached
material is checked against current rows/heads and the refresh fence before
new lease publication.

These checks do not retract an earlier lease already held by the data plane.
An independent currentness mechanism at actual cached upstream-send admission
is still required; this source does not invent a SQL-only global fence,
retroactive undo, fake currentness proof or a database query in the Rust hot
path. The CP fence limits new observed issuance, not previously dispatched
effects. Any race-free distributed send boundary must be joined and validated
separately before claiming that stronger property.

Unknown claim/contact/retention/commit outcomes leave the original slot consumed.
There is no resume-from-JSON permit, lease renewal, automatic retry, deletion,
history rewrite or fake no-contact receipt. An actual timeout cannot prove that
the provider did not rotate a token. Original contact and retention bounds are
committed before contact, clipped by current enrollment and the genuine cold
operation/custody window. Expiry does not reopen a slot or discard its evidence.

The initial capacity contract is sixty-four rows per complete inventory and
the signed work capacity, not a hidden per-provider narrowing. Existing global
byte/work/deadline limits can refuse an inventory earlier. Each envelope is
bounded to 256 KiB, authority inputs to 1 MiB, credential originals to 512 KiB
and refresh rows to 2 MiB. Retained refresh history is not pruned here; larger
population acquisition and separately authorized archival/retirement remain
required follow-ons. Terminal i64 maximum generation can be stored, but another
increment is refused before contact.

No source-connected statement is production or pilot validation. Actual signed
policy/configuration, enrollment, roots/ACLs, cold custody, provider application
material and the independent authority services must be provisioned, and the
full selected flow must undergo separately authorized validation. Refresh
cleanup, cached-send currentness, reconnect, setup and cross-deployment ownership
remain explicit obligations rather than a permanently narrowed product.
