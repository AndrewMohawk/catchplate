# Enrolled OAuth refresh before generation admission

This source connects `control_plane_oauth_refresh.py` and
`oauth_refresh_material.py` to the actual credential-lease endpoint. It has not
been built, executed, provisioned, or exercised against a provider. It does not
establish measured provider-response authorship, cross-application coordination,
or a tested pilot.

An independently signed measured `oauthRefreshPolicy` must grant the fixed
`oauth.refresh.claim`, `oauth.refresh.retain`, and `oauth.refresh.commit`
operations. The current application enrollment authenticates the application;
it is not an automatic-refresh grant and is not substituted for that policy.
The client requests the source-selected limits of 60 seconds until access-token
expiry, a maximum 30-second operation, and 64 revocation-work slots. Every writer
transition independently checks equality with current signed policy. The actual
cold application owner retains the client/auth configuration, enrollment and
custody client. Missing or changed production ownership fails closed; the
explicit unconfigured development profile keeps its previous refresh behavior.

## Actual producer and consumer sequence

The authenticated `/api/data-plane/credential-leases` handler captures one
`LeaseOpening`, its actual request/payload, wall and monotonic clocks, and current
cold owner. Existing recipient, route and release-authority verification still
runs. The opening is only narrowed by the original application-owner interval
and any request-authority reservation expiry.

For `generationMetadata`, the client reads the exact protected credential and
generation-head originals. A due credential is refreshed before the endpoint
returns a version/metadata binding. For `dispatchSecret`, the enrolled path is
read/check-only: a due, changed, or fenced credential is refused. It never
refreshes transparently under an already pinned expected version or renews that
request's authority.

1. `oauth.refresh.claim` binds the original credential/version, generation head,
   independent enrollment, owner nonce commitment, fixed token-request digest,
   and absolute contact/retention deadlines. The stable slot depends on the
   credential ID and version, not a new random attempt. It reserves issued-work
   capacity and, for X, separate superseded-token capacity before contact.
2. Only the same retained owner, after the definite signed writer result and
   exact protected-row readback, may perform one token POST. Its source-owned
   attempted bit is set before contact. There is no retry loop, redirect/proxy
   fallback, or new allowance after an uncertain response.
3. `oauth.refresh.retain` stores the encrypted exact local HTTP observation
   (`status`, ordered raw headers and body bytes) and any bounded extracted
   issued tokens. The client decrypts the retained originals and compares them
   before interpreting the response as a credential replacement. A hash or
   ciphertext equality alone is not plaintext proof or provider attestation.
4. After definite retention, normalization preserves the same account,
   application and scope set. Omitted refresh token and refresh-token expiry
   preserve the original values; malformed explicit values do not authorize a
   replacement. Expiry arithmetic uses the retained receipt timestamp, not a
   fresh operation window. The replacement envelope uses the same credential
   ID with version N+1; response/issued/superseded artifacts have distinct
   deterministic IDs and version-one envelopes.
5. `oauth.refresh.commit` atomically replaces ciphertext/version and generation
   head, associates retention/retirement evidence and appends audit. The client
   checks the exact resulting row, decrypted replacement, head, and signed
   public projection. Local secret caches are invalidated after claim and after
   definite completion. No secret, raw reply, or private request is returned in
   a public refresh response or diagnostic log.

The raw reply is bounded to 96 KiB, its raw headers to 8 KiB, canonical material
to 190 KiB and each encrypted envelope to 256 KiB. Partial, oversized, malformed,
expired or uncertain outcomes remain consumed/fenced; bounded retention cannot
promise that every returned byte survives process death or expiry. No error path
invokes the legacy inline revoke/delete helpers.

## Fence and cleanup boundaries

The credential remains `active`; an uncommitted protected refresh row is the
irreversible fence. New enrolled lease openings and output checks query this
fence and recheck the exact current credential/head, including immediately before
response publication. An old committed slot is retained evidence; only a later
current version can receive its own independently due claim.

These checks are not a distributed atomic snapshot, a retroactive revocation of
already dispatched effects, or proof that previously retained data-plane leases
have been revoked. The Rust cached upstream-send path currently checks its local
lease/generation/policy state. A separate current-fence join at those consumers
remains required; Python response SELECTs are not that authority.

Refresh work is purpose-separated as `enrolled-oauth-refresh-issued/v1` and
`enrolled-oauth-refresh-superseded/v1`. Google never queues family-wide revocation
of an old grant as token retirement. X retains only old token fields whose bytes
changed; an unchanged refresh token is not selected for retirement. These work
labels do not silently enter the existing exchange-only cleanup authority.
Actual cleanup admission for the distinct refresh purposes remains a separate
consumer join. Reconnect and setup successors are also separate; this client
does not downgrade them into a new-credential flow or expand runtime SQL roles.
