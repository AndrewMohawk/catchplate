# Measured reconnect helper

This private Python owner implements the separately selected active-family
replacement purpose. It is source-only and has not been built or exercised.
The Rust signer/browser, helper dispatcher and explicit native startup v17 join
this purpose to the actual gate lifecycle. Merely importing these modules starts
no listener, decrypts no token and contacts no provider. Source integration is
not successful provider execution or an accepted pilot.

## Explicit native startup

The enclave entrypoint selector is `--measured-reconnect-v17`; it forwards to
the actual gate's `--native-measured-reconnect-startup-v17` mode. The closed
`catchplate.nativeStartupConfiguration/v17` retains the 22-field v16 layout
and every non-browser owner, replacing `measuredSetup` with
`measuredReconnect`. Enrollment's separate Setup authorizer remains present.
Older selectors/decoders and the default encrypted-v6 selector are unchanged;
older profiles cannot silently select reconnect.

The nested configuration has 16 fields. Actual native preparation supplies the
retained identity and browser leaf commitments, removes the cold VSOCK port,
and produces the helper's closed configuration18. Source-fixed admission
rejects simultaneous issuance, Setup and reconnect browser owners. The same
native OAuth mutex, helper owner and original runtime lifetime cover all actual
begin/callback/recovery progression; no extra helper, renewed lifetime or host
signing fallback is introduced.

The browser serves a hash-CSP page at its own `/oauth/begin`, clears the public
intent fragment from navigation history, and makes one same-origin JSON POST
to that route. The helper obtains its own PREPARE receipt before the gate emits
the reconnect redirect and Secure/HttpOnly/SameSite cookie. There is no portal
draft round trip. The dedicated signer binds the actual 23-field reconnect
statement, family authorization and fenced-row commitments to the retained
native key and fresh NSM evidence under the reconnect-specific nonce domain.
The phase spelling `draft` on PREPARE is the existing reconnect authority
contract; it does not create a browser draft or borrow Setup authority.

Configuration and original acquisition are not permission to replay effects.
Startup recovery uses only the explicit cold target inventory and fresh signed
RECOVER results. The native worker is scoped to the same cancellation and
absolute serving lifetime as the proxy. Browser or helper errors never authorize
a second provider contact.

## Admission before entropy

`native_oauth_reconnect_owner.Owner(broker, message)` receives only the actual
measured broker owner. Its closed configure message selects
`catchplate.nativeOAuthReconnectExchangeConfiguration/v1` and the previously
frozen configuration18, including exact `reconnectLimits` (7 affected lineages,
64 retained histories, 3600-second maximum grant). It verifies the retained
independently signed authority configuration and separate roots. No browser
chooses roots, endpoints, native assignments or the cold profile.

The exact configuration fields are apiVersion, sourceRevision,
authorityRootPublicKey, authorityRootSpkiSha256,
controlPlaneConfigurationDigest, deploymentId, instanceId, limits, windows,
applications, recoveryTargets, identity, callbackOrigin, portalOrigin,
ingressLeafCertificateSha256, ingressLeafSpkiSha256,
authorityConfigurationOriginal and reconnectLimits. Each application is the
existing closed enrollmentOriginal/material/tlsRootsPem triple; identity is
the actual native holder/boot/key/role-measurement assignment, not HTTP metadata.
No policy-selector aliases or fallback assignments are accepted.

The native-origin `/oauth/begin#original=...` message contains the canonical
intent10. The helper verifies the independent family grant, current cold
enrollment/configuration, verifier signature over the exact FENCE request and
result, original journal, exact affected credential/head originals and ordered
barrier vector before generating PKCE, OAuth state or browser cookie. The grant
authorization ID is the exchange ID. The target's existing metadata, including
its real application association, is retained unchanged rather than projected
through the new-credential intent parser.

The protected writer's signed result certifies that its actual FENCE transaction
consumed those barriers. The helper checks this authenticated association; it
does not claim independently to inspect holder processes from a digest. The
writer's consumption receipt explicitly remains `trusted-host-local`, with
hardware/TEE/external-witness assertions false. Its signature and configuration
association are checked separately from the native gate key and family root.
Full production attestation gates remain open.

The original signed fence request/response are retained separately in the live
owner. The exact22-field encrypted private state remains bounded to 64 KiB and
contains `reconnectBinding`7, not those potentially large receipts. Every phase
also retains the exact protected fenced journal. Recovery re-admits its actual
signed RECOVER result and that journal; it does not reconstruct a browser flow
or treat an acquired historical row as current permission.

## Private dispatcher contract

The channel is `catchplate.nativeOAuthReconnectChannel/v1`. Messages are closed:

The complete message, including envelope and base64 overhead, must fit the
existing 8 MiB frame. Nominal intent/original bounds are not permission to
increase that aggregate limit; an oversized composition is refused.

- `configure`: apiVersion, phase, configuration.
- `begin`: apiVersion, phase, intent, deadlineBoottimeNs.
- `callback`: apiVersion, phase, exchangeId, providerId, browserNonce, query,
  deadlineBoottimeNs.
- `recover`: apiVersion, phase, exchangeId, journalOriginal, exchangeOriginal,
  custodyOriginal, candidateOriginal, deadlineBoottimeNs.
- `receipt`: apiVersion, phase, originals; originals is exact
  requestOriginal/responseOriginal, both canonical base64url originals.

After actual fence admission, `prepared` carries apiVersion, phase, operation,
arguments, issuedAtEpochNs and expiresAtEpochNs. Its arguments11 require the
gate's separately purpose-bound native evidence to become the actual
arguments12. PREPARE has a nonnull independently assigned native purpose, like
every later phase. The helper verifies that signature against the actual pinned
native key, exact statement23 and request. Actual authority roles additionally
verify original Nitro evidence and the separately signed assignment.

Only a definite PREPARE receipt produces `authorization-redirect` exact7:
apiVersion, phase, exchangeId, location, cookieName, cookieValue,
expiresAtEpochNs. The source-owned native browser adapter must set that cookie
securely on its own HTTPS origin and redirect once. There is no
`draft-delivered`/`authorize` round trip and no old CP consent converter.

`complete` is exact5: apiVersion, phase, exchangeId, status and
custodyRowSha256. Status is staged, cancelled, captured-unusable,
observed-staged or observed-committed. These are observations, not another
provider permission, cleanup authorization or completed external audit.

## Contact, retention and interruption

The helper burns each begin/recovery ID and callback/receipt attempt. Any
protocol exception poisons the owner. A lost response never makes a second
token POST permissible. Actual broker-wide native OAuth serialization and
original runtime lifetime remain mandatory dispatcher responsibilities.

All separately signed grant windows remain absolute. Each local operation is
also bounded by the supplied original CLOCK_BOOTTIME deadline, actual broker
channel lifetime and at most 30 seconds. Browser callbacks cannot renew the
family grant or its contact/retention/pending expiry. One CLAIM receipt permits
one token contact. Exact TLS response bytes and minimal issued material are
sealed and must receive a definite CAPTURE receipt before identity processing.

Only source-fixed Google/X token and identity hosts/paths are reachable through
`catchplate.nativeOAuthReconnectTls/v1`. MemoryBIO TLS retains certificate,
hostname and configured-root verification inside the measured helper; the
parent sees ciphertext only. The fixed reader preserves bounded framing and
refuses redirects. No arbitrary URL, ambient trust or host token plaintext is
introduced.

Each outgoing TLS event has exact6 apiVersion, providerId, purpose, sequence,
ciphertext and read; purpose is token or identity. Its reply has exact4
apiVersion, sequence, ciphertext and eof. The sequence starts at 1 for each
separate purpose stream, with at most 512 transfers, 64 KiB per packet and
512 KiB aggregate wire bytes. Null ciphertext represents no bytes. The parent
must retain separate source-fixed streams and must not reopen a failed stream.

After fixed identity lookup, the verified provider subject AND account must
match the original family grant. Returned scopes must exactly match the signed
scope set. Replacement metadata changes only the explicit token-lifetime fields.
The final normalized token is sealed for the existing credential ID and N+1;
state/callback/raw/identity and minimal issued capture keep their separate
version1 artifact identities. Actual candidate approval/activation remains the
separate controlled writer and distinct-person hardware ceremony.

Recovery targets come only from the cold inventory. Acquired rows are bounded
untrusted data until a fresh own-purpose signed RECOVER result agrees with the
exact retained journal and capture. Captured processing may decrypt and perform
its fixed identity lookup only then; staged/committed recovery observes only.
No recovery branch can create PKCE, authorize a browser or send a token POST.
Unknown pre-capture outcomes, provider cleanup, retired-family succession,
non-target fenced lineages and full runtime acceptance remain required separate
work. No lifecycle fence is cleared by this module.
