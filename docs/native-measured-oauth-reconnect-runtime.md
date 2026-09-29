# Native reconnect runtime ownership

This source slice connects the purpose-specific private reconnect helper to an
actual native browser TLS owner, native proof signer and fixed control-plane
transport. It is not an issuance/Setup permission alias, a public arbitrary
provider client, or evidence of a built or exercised deployment. The separate
v17 cold selection and shared caller joins must retain these actual owners;
there is no version inference from an HTTP body. See
[the private helper contract](native-measured-oauth-reconnect.md) and
[the controlled authority](measured-oauth-reconnect.md).

## Original owners and boundaries

`native_oauth_reconnect::prepare` requires the installed encrypted-service
profile, actual instance/currentness deployment association, genuine native CA
and custody signer. It derives only the origin of the retained HTTPS credential
service endpoint. The two paths are fixed to
`/api/data-plane/oauth-reconnect` and its `/original` child. The browser listener
is an actual source-created vsock listener for parent CID 2, with the signed
configuration port. Its `Arc<BrowserTls>` is shared unchanged with the private
helper and each measured preparation.

The helper independently verifies the root, configuration, verifier signature,
complete FENCE request/result, journal, family authorization and ordered
affected-lineage/currentness originals before producing PKCE. The grant's
authorization UUID is the exchange UUID. Existing target metadata, including
the actual enrolled-application association, remains bound. The final encrypted
token envelope is for that target credential at N+1, not an exchange-ID token or
a fictitious new credential. Reusing scalar/TLS types from the existing native
modules supplies no old-purpose permission.

The controlled writer receipt is authenticated trusted-host-local evidence.
This implementation does not relabel it as a native TEE custody attestation.
The native role-4 proof and independently selected family-retirement/replacement
root remain distinct. Complete affected-family drain/fence admission is owned
by the controlled authority, not acquired by a local mutex or browser message.

## Exact public Rust joins

The library wire module exports `Configuration`, non-Clone `Prepared`, `Reply`
and the existing opaque `BrowserTls` type. `Configuration` is closed exact16:
`apiVersion`, `sourceRevision`, `authorityRootPublicKey`,
`authorityRootSpkiSha256`, `authorityConfigurationOriginal`,
`controlPlaneConfigurationDigest`, `deploymentId`, `instanceId`, `limits`,
`reconnectLimits`, `windows`, `applications`, `recoveryTargets`,
`callbackOrigin`, `portalOrigin`, `browserVsockPort`.

`reconnectLimits` is exact3: `affectedLineageCapacity=7`, `historyCapacity=64`,
`authorizationMaxSeconds=3600`. Existing limits are pending64/revocation64;
windows are contact600/retention600/pending3600/operation30/recovery30 seconds.
Each application retains its encrypted material, signed enrollment original
and fixed provider TLS roots. No configuration field accepts a provider URL.

The broker's actual owner retains
`Option<(Configuration, Arc<BrowserTls>)>` and implements:

```rust
configure_reconnect(config, ingress, identity, boot, key, cp_key, binary, deadline)
reconnect_browser(&Accepted, &NativeUpstreamRelaysV1) -> Result<Reply, String>
reconnect_receipt(Value, &Prepared, deadline, &NativeUpstreamRelaysV1) -> Result<Reply, String>
recover_reconnect(id, Value, deadline, &NativeUpstreamRelaysV1) -> Result<Reply, String>
```

Configuration is projected to the helper's exact18 fields by removing only
`browserVsockPort` and adding actual `identity`,
`ingressLeafCertificateSha256`, `ingressLeafSpkiSha256`. The complete canonical
frame, not merely an inner intent, remains at most 8 MiB. Root owns the mutually
exclusive browser-purpose field initialization and private dispatcher joins.

The binary-local gate exports only `prepare`, `initialize`, and `start` with
the actual `GateState` and original `Arc<NativeRuntimeLifetimeV1>`. Its private
owner retains the listener, configuration, ingress and fixed endpoints.
`Accepted::accept_reconnect` and `reconnect_command` are purpose-specific;
BeginPage, Begin and Callback are the only browser branches. Root supplies
`reconnect_page(portal_origin) -> Result<(Vec<u8>, String), String>` and
`signer.transport.reconnect_evidence` using this actual `Prepared`.

## Finite handoffs, not retries

The browser opens `/oauth/begin#original=<canonical intent>`. The source-owned
page sends one POST `/oauth/begin`; the fragment is not sent to the listener by
ordinary navigation. The private owner verifies the retained fence before PKCE,
then returns `oauth.measured-reconnect.prepare`. The gate signs its distinct
23-field statement and submits PREPARE once. The frozen authority calls that
statement phase `draft`; this does not add a browser draft/review/authorize
round-trip or convert an old prepare-consent operation.

Only a definitely admitted same-owner PREPARE receipt can produce
`authorization-redirect`: exact exchange UUID, fixed Google/X authorization
URL, original cookie name/value and original contact expiry. The gate returns
exact3 `{apiVersion,exchangeId,location}` with
`serverware.nativeOAuthReconnectAuthorizationRedirect/v1`, while setting the
original Secure/HttpOnly/SameSite=Lax cookie. It never sends the private PKCE
verifier, client secret or provider token to the control plane or browser.

Callback processing is finite CLAIM -> CAPTURE -> STAGE, or CANCEL. One genuine
CLAIM receipt permits only the fixed token TLS contact. The helper seals exact
raw response/issued material before requesting CAPTURE. Only its admitted
CAPTURE receipt permits the fixed identity TLS contact and same-account STAGE.
No token contact can follow PREPARE, STAGE or CANCEL. An unusable captured
response is an explicit terminal observation, not a completed credential.
STAGE is not COMMIT: final controlled replacement/approval still has its own
actual authority and durable transition.

Cold-selected recovery acquires exact6 data-only originals, obtains its own
signed RECOVER receipt, and may observe staged/committed or continue retained
captured material to identity/STAGE. It cannot enter PREPARE, CLAIM, CAPTURE or
repeat the token POST. The four raw originals remain journal/exchange/custody/
candidate; no current row is substituted for historical evidence.

Provider transport accepts only encrypted TLS records from that same helper
and same prepared phase, using the fixed relay API. A receipt has one socket,
one provider/purpose, at most 512 exchanges, 64 KiB per record and 512 KiB
aggregate. EOF, deadline failure or unknown write does not reopen a socket.
Private protocol failure poisons and terminates that helper owner; no recovery
acknowledgement or absent response creates retry permission.

## Lifetime, bounds and completion limits

Every original operation interval is at most 30 seconds and is clipped by the
actual retained browser/runtime lifetime. Family admission/contact/retention/
pending deadlines are separately retained by the private helper and controlled
authority. A new accepted request or startup observation cannot renew them.
The gate holds the existing `native_oauth_serial` and actual broker mutex over
each private protocol; these are exclusion, never permission or drain proof.

The serving and cancellation tasks retain the same runtime Arc and actual
shutdown handle. Stop closes the active original browser transport; errors
remain terminal to that owner. Arguments, request originals and signed response
originals retain 2/3/6 MiB bounds. Each complete outer HTTP/private frame stays
within 8 MiB, including canonical/base64 overhead.

No general automatic revoke, retired-family succession, provider-scope fence
clear, currentness reopen or cross-deployment family proof is added. Those
remain separately authorized required work. The source has not been built,
tested, run against a provider, or provisioned by this slice; production
attestation and end-to-end runtime acceptance remain open.
