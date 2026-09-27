# Private activation token-release intent

This is a **source-only wire contract**, unbuilt and unexecuted. A signed intent
is neither proof of committed consumption nor permission to return plaintext.
It adds no generic operation, public route, cold service or hardware assurance.

## Exact original contract

The fixed purpose is `authorize-oidc-session-activation-token-release`. The
envelope schema and signature domain are
`serverware.signedOidcSessionActivationReleaseIntent/v1`; the payload schema is
`serverware.oidcSessionActivationReleaseIntent/v1`. The exact canonical original
has its own framed identity domain,
`serverware.oidcSessionActivationReleaseIntentIdentity/v1`.

The envelope is exactly `schema`, `payload`, `signatureBase64Url`. Its closed
payload contains:

- `schema`, `sourceRevision`, `purpose`, `enrollmentDigest`, `callerId` and
  `callerMeasurementDigest`;
- `receiverIdentity`, `configurationDigest`, `databaseId`, `generationDigest`
  and `runtimeClosureDigest`;
- `activationRequestDigest`, `activationOperationId`, `consumeRequestDigest`,
  `deliveryEnvelopeDigest` and `deliveryScope`;
- `consumeBinding`, `intentNonce`, `issuedAtEpochNs` and `expiresAtEpochNs`.

`consumeBinding` is exactly five canonical SHA-256 identities: `packetDigest`,
`pendingDecisionDigest`, `completionRequestDigest`, `effectsDigest` and
`afterVectorDigest`. They are claimed bindings, not substitutes for the original
packet, commit, completion or their independently expected scope.

`deliveryScope` reuses the actual eleven-field
[release-custody grammar](oidc-session-activation-release-custody.md): delivery,
user, session, credential and challenge identifiers; assertion and old/new token
digests; canonical creation/expiry timestamps. Credential encoding, token
rotation and original delivery lifetime are checked. No token plaintext or
private key is serialized. `receiverIdentity` uses the existing exact identity
shape; a signed measurement digest is not measured-runtime evidence.

The nonce is canonical unpadded base64url for exactly 32 bytes, excluding the
all-zero value. Only the actual producer generates it; the wire layer does not
manufacture freshness or durable replay protection.
The intent has a positive interval no longer than
`VERIFIER_RESPONSE_MAX_AGE_NS`, and its expiry cannot exceed the original
delivery expiry. Live admission must separately verify the current processing
window, caller enrollment and independently held expectations; parsing an old
intent never renews it.

## Bounded private interfaces

```text
_read(original, work) -> owned signed-envelope dictionary
_digest(original, work) -> exact-original domain-framed identity
_signature(envelope, public_key, work) -> None
_sign(payload, *, private_key, public_key, work) -> original bytes
```

Originals and outputs are bounded at **64 KiB**, **256 JSON nodes** and depth
**4**. Decode, owned capture, canonical comparison, framing and native Ed25519
operations charge the caller's existing cumulative work. Ordinary input is
captured before cryptographic callbacks; signing binds the actual private/public
key pair, verifies the generated signature and reads back the canonical result
with an exact payload join. No new work allowance or clock is opened.

`_read` and `_digest` do not authenticate. `_signature` authenticates only the
fixed intent-domain signature under the supplied actual key, with input
stability checks; it does not enroll that key or admit its caller. `_sign` is a
private fixed-domain primitive, not an endpoint accepting caller-posted payloads
as authority. No successful verification object is accepted as a proof input.

Actual caller/root enrollment, original intent production and independent live
verification belong to separate composition. Even that intent admission cannot
replace genuine immutable consumption/commit/completion admission, durable exact
outcome retention and guarded plaintext release. Cold key delivery,
private response/handoff, public permission and portal confirmation remain
separate work; this contract closes none of those scopes.
