# Native runtime capture into Setup

Source-only implementation. No build, quote, key provisioning, proxy request,
browser, database mutation or test has been executed for this slice.

The genuine producer already exists: the buffered native proof client checks
the actual response bytes, TLS exporter/peer, signed request/response, native
control-plane dispatch receipt and original Nitro role-4 quote before its
separately held collector key signs `nativeResponseCapture/v2`. This successor
consumes that artifact; it does not invent a new success envelope or copy the
unsigned `native_verification` result as authority.

## Fixed first profile

`setupNativeRuntimePolicy` is a separate purpose in the independently signed
full authority configuration. It supplies the current hardware policy, native
PKI roots and at most 32 uniquely sorted session scopes. A scope pins the exact
Setup/principal/route/credential, empty-body HTTPS GET with no custom headers or
query, collector and control-plane public keys, server instance and native15
boot/release/configuration/CA/binary/PCR/key assignment. Statement runtime-manifest
and provenance digests have their own independent pins: the response provenance
digest is not the quote's release-record digest. No new key is generated.
The first URL profile uses canonical ASCII DNS names (not IP literals), an
optional non-default port and a percent-free path without dot segments, so the
actual collector URL parser preserves the signed client-request bytes.

The existing collector is explicitly trusted to report its real client-side
HTTP/TLS observation. Its key is independent of the native signer, CP response
key, configuration/controlled-role keys and installation/issuer/host signers.
The server repeats original collector and native Ed25519 verification, the
actual Nitro COSE/PKI/PCR/key/boot/challenge checks and the original signed CP
dispatch receipt. It rejoins exact selected response headers/body digest and
the actual credential identity/version. It does not itself observe the remote
TLS connection or prove that the enrolled leaf was the collector's outer TLS
client certificate. Those are not claims of this profile.

Only a buffered successful ordinary non-JIT dispatch with no quotas is accepted.
Streaming, observation-only, durable, JIT, quota and denied-response variants
remain refused, not normalized or treated as covered. This is a deliberate
finite receiver profile over an existing producer, not full pilot acceptance.

## Actual protected sequence

1. Existing Setup revision3, native issuance, authenticated CA readback and
   native-canary publication association must be genuine protected originals.
   The association audit must be completed. Original Setup expiry, current
   credential generation/open root, roles and committed native policy are checked.
2. `options` issues the real purpose-specific hardware challenge. `prepare`
   consumes that challenge and atomically inserts `capture_outcome_unknown`.
   Its nonce is SHA256 of the fixed Setup-runtime domain, the actual verified
   hardware challenge bytes and the exact prepare request digest. One immutable
   session slot prevents another attempt or nonce after loss/uncertainty.
3. The response returns exact attempt/scope/expectations originals. The original
   attempt is bounded by its cold scope and unchanged Setup expiry, at most
   300 seconds. No endpoint refreshes it. Independently provisioned trust roots,
   verifier executable, client certificate/private key and collector remain
   operator prerequisites; the bundle supplies no private material or new trust.
4. The existing `serverware-proof-client` native buffered invocation uses this
   exact attempt nonce via `--nonce` and the exact expectations original/pin.
   Its URL and empty GET must match the independently reviewed `clientRequest`;
   all other native transport/input flags retain their original admission.
   The client places the nonce in the actual proof request header. The server
   signs the same nonce and request digest and derives the quote challenge from
   the nonce, exact statement and signature. This is a real producer binding,
   not a comparison to a supplied success status.
5. `complete` uploads the exact bounded capture file, preserving its original
   whitespace and LF as base64url bytes. Both independent verifier and planner
   reverify the originals. The kernel rechecks the same current source rows,
   original attempt and completed prepare audit, then consumes the slot to
   `runtime_evidence_recorded` and emits its actual audit outbox event.

The new nonce reservation is one-use **evidence consumption**, not authority for
an upstream action. The [fixed operator caller](native-pilot-request-collection.md)
now routes this exact bundle to the real buffered client with a durable local
per-Setup dispatch fence, original-expiry clipping and exact capture export.
The old client can still be invoked directly; the fence trusts its host/operator
and filesystem, not hostile rollback or other hosts. Neither path claims global
exactly-once requests, measured collector custody, final client delivery, or a
generic proxy-ready outcome.
Normal request authorization remains with the real native dispatch owners.

Seconds-valued capture/statement times are treated conservatively as intervals;
the whole reported interval must fit the original attempt and current receipt
deadline. Subsecond ambiguity or an expired dispatch receipt is refused, never
clamped or given a new allowance. Historical grants and old CA-install windows
are not reissued as request permission.

## HTTP and recovery

The [native Setup portal](setup-native-runtime-portal.md) connects these routes
to explicit preparation, exact original downloads, capture review and historical
readback. It never calls the proxy itself or turns browser parsing into proof.

All four POST routes are under `/api/setup/native-runtime`. `options` and
`lookup` take exact `{apiVersion,sessionId}`; `prepare` adds `assertion`;
`complete` adds `captureOriginalBase64url`. The API version is
`serverware.setupNativeRuntimeRequest/v1`. Request cap is 768 KiB, decoded
capture cap 512 KiB and response cap 128 KiB. The [closed schema](../schemas/setup-native-runtime.v1.schema.json)
defines the actual attempt, policy, scope, bundle and result fields.

`prepare` returns 201 with `capture-outcome-unknown`; `complete` returns 200
only after definite protected completion. Any uncertain call keeps its marker.
Lookup returns the exact historical attempt/bundle and definite retained result
if present. It cannot reset the slot, resubmit a request, renew a deadline or
authorize rerunning the collector. Keep nonsecret browser attempt markers and
use read-only lookup after response loss; no automatic retries.

Every response keeps `okForAction`, `automaticRetryAllowed`,
`nativeHostVerified`, `enrollmentComplete` and `proxyReady` false. Legacy Setup
phases and receipt issuers are untouched. Next required source includes actual
native host/hardware completion and independent final Setup receipt authority,
global client contact ownership if claimed, denied-request coverage and the
remaining native effect-service joins. Independent deployment artifacts/keys and
first connected build plus allowed/denied credential-controlled runtime evidence
remain separate, unperformed acceptance work.
