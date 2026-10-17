# Independently authorized refresh family retirement

This is a source-only controlled cleanup path, not runtime or provider acceptance evidence. It handles retained refresh-issued work at its original credential version, and X superseded work at the immediately committed next version. It does not turn the exchange-only cleanup grant into refresh permission, or complete O01/O03/O04. Older/later lineage transitions, reconnection and recovery remain separate work.

## Why this is family retirement

A changed token string does not establish an isolated revocation effect. [RFC 7009 section 2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1) permits revocation of related tokens and the underlying authorization grant. [Google's revocation contract](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke) invalidates access and refresh tokens across clients registered under the project. Therefore X superseded material is **not** automatically revoked as harmless housekeeping, and old Google family material is never admitted as superseded-token retirement.

The new `catchplate.oauthRefreshCleanupAuthorization/v1` payload has 29 closed fields and a distinct `oauth-refresh-family-retirement` purpose. The separately pinned Ed25519 root signs the payload schema, NUL, then its exact canonical ASCII JSON. Its explicit `familyScope` identifies provider subject/account/family and requires `externalFamilyRetirementAuthorized: true`. This is an independent authority decision, not proof inferred from a token hash, local inventory or prior enrollment signature. The old exchange cleanup profile remains unchanged.

The grant pins the original refresh reservation, exact held work, current credential and generation, historical enrollment/key, current provider configuration/client material, and original consumed refresh barrier. It selects exact access/refresh token purposes. The worker decrypts the retained originals and checks actual enrolled ownership, verified subject/account and token lineage before coordinating a current drain. An unchanged shared refresh token is excluded. X superseded tokens must be actual changed old-token members; Google issued cleanup selects a changed refresh token when available, otherwise the issued access token. Provider requests are constructed from these genuine decrypted originals; a caller cannot supply a success verdict or arbitrary token/contact URL.

## Effect ordering and interruption

1. Retain the genuine cold custody owner, signed grant, exact history/material and one original deadline (at most 30 seconds, clipped by grant expiry).
2. If the affected current version is the originally drained refresh version, verify its exact consumed historical barrier and original claim digest. Otherwise quiesce the actual current version, freeze its complete registered holder set, and wait for every genuine drained acknowledgement. Missing holders or a timeout never mean drained.
3. In one protected `oauth.refresh-cleanup.claim` transaction, recheck all originals and actual authenticated roots, consume the newly admitted current barrier if needed, reserve the held work, retain exact predecessor credential/generation/work originals, permanently fence the current credential as `revocation_pending`, and write the permanent provider-subject family-retirement row. The claim competes with refresh commit under the real writer fence. No provider contact precedes definite claim result and exact protected readback.
4. For each selected token, perform a distinct protected contact claim/readback before a single HTTPS request. The nonce owner, operation deadline and actual fenced credential/generation are rechecked before contact. No retry, second socket attempt after an uncertain contact, work deletion or history reset is granted.
5. Retain bounded actual status, raw headers and body, or an explicit unknown transport original. Protected finish derives accepted/rejected/unknown from that original. These are local HTTP observations, not proof of global revocation; even accepted does not reactivate the credential, reopen the currentness root, or certify other provider tokens usable.

If the response or protected finish is lost, the attempt remains consumed/uncertain. Restart does not reconstruct the in-memory nonce or replay the contact. Read-only journal inspection may distinguish durable claim/contact/finish records, but cannot erase history or mint a successor. A separately authorized authenticated reconnect must establish a genuinely fresh provider credential/version and handle the irreversible local family fence; that successor is not supplied here.

## Local inventory and permanent refusal

Cleanup reconstructs the complete authenticated local credential population against its actual before-root, bounded to 64 entries, and requires a single exact locally represented provider-subject lineage. The permanent `oauth_family_retirements` key uses canonical provider ID and verified subject, not token bytes. Staging after the actual verified-subject review, activation, and every refresh phase consult an independently root-reconstructed complete retirement population and refuse a retired subject. Both acquisition and root proof are mandatory; membership-only samples cannot establish absence.

This protects the local post-subject workflow. It does **not** prove cross-deployment ownership, enumerate external OAuth clients, or stop an authorization-code exchange before the provider subject becomes known. The signed external-family authorization remains independently required. Retirement does not silently reopen the local fence for new enrollment, and this profile does not implement a generic reconnect/reset path.

The family-retirement population has a separate temporary 32-row admission cap; existing credential/pending/setup populations retain their 64-row caps. Stage/activation fit the unchanged global 256-query-proof bound. Exceeding a bound refuses the workflow; it is not authority to prune, archive or discard a retirement record.

## Actual cold producer and consumer

`authority_oauth_refresh_cleanup.sign_authorization` produces the distinct signed envelope. `oauthRefreshCleanupPolicy` in measured authority configuration independently pins its root and deployment/control-plane binding, separate from application, enrollment, refresh and exchange-cleanup roots. Historical enrollment is checked for original provenance; expiry is not renewed into cleanup authority.

The protected descriptor entrypoint delivers only the fixed `/run/catchplate/authority-trust/oauth-refresh-cleanups.json` startup original, cleanup root `/run/catchplate/authority-trust/oauth-refresh-cleanup-root-public-key`, historical enrollment SPKI-named root, and per-authorization root-owned private client file `/run/secrets/catchplate-oauth-refresh-cleanup-<authorizationId>-client`. No arbitrary path or private signing key is delivered. The startup schema is `catchplate.oauthRefreshCleanupStartup/v1`, selected only by `CATCHPLATE_OAUTH_REFRESH_CLEANUP_CONFIG_FD`.

The cold worker exposes `initialize_from_environment`, `selected`, `reconcile(limit=16)`, and `close`. Production selects even an explicitly empty list, so missing authority cannot fall through to uncontrolled cleanup. The parent control-plane startup and scheduler compose this worker with the other genuine controlled owners before legacy revocation DML. There is no new HTTP caller-supplied authority switch.

The paired [closed schema](../schemas/oauth-refresh-cleanup-authority.v1.schema.json) describes authorization/policy/startup and data-only arguments/results. It is not signature, currentness or permission evidence. Existing MFA/auth modes and separate mandatory workload policy are unchanged.

## Bounds and remaining work

Startup is at most 2 MiB and 16 grants. Signed grants are at most 64 KiB, transition arguments 384 KiB, and exact retained journal originals 2 MiB. Transport originals are at most 128 KiB; responses allow at most 128 header pairs/8 KiB and 64 KiB body. Token contacts remain under the single original operation deadline; looping over tokens never renews it. Currentness uses the real retained holder barrier, not a callback asserting drain.

No project code, build, test, provider request, provisioning or migration was executed for this source batch. Operator-facing grant issuance, complete external family coordination, reconnect successors, historical/malformed-state repair, durable unknown-outcome handling beyond refusal, and end-to-end runtime evidence remain acceptance work. No deletion, global cleanup closure or narrower project completion is claimed.
