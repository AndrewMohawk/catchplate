# Native response principal profiles

The additive native-principal response profile is source-only. It separates
native UTF-8 principal handling from existing signed families; it does not turn
preflight, a verifier diagnostic or a new version label into provider permission.
No build, test, live Nitro document, provider response or production acceptance
is claimed by this source checkpoint.

## Independent selection, no fallback

The [Rust original verifier](native-verifier.md) and the proof client's protected
verifier adapter select the same profile from the independently pinned
expectations original, never from an incoming statement or a returned verdict.

| Pinned expectations | Allowed statement APIs | Envelope / local verdict |
| --- | --- | --- |
| `catchplate.nativeResponseAttestationExpectations/v1`, exact existing 16 fields | `catchplate.proxyResponseStatement/v2`, `catchplate.streamingResponseStatement/v1`, `catchplate.responseObservationStatement/v1` | `catchplate.nativeResponseRuntimeProof/v1` / `catchplate.nativeResponseAttestationVerification/v1` |
| [`catchplate.nativeResponseAttestationExpectations/v2`](../schemas/native-response-attestation-expectations.v2.schema.json), those 16 fields plus `statementProfile: catchplate.nativeResponseStatements/v1` | `catchplate.nativeProxyResponseStatement/v1`, `catchplate.nativeStreamingResponseStatement/v1`, `catchplate.nativeResponseObservationStatement/v1` | `catchplate.nativeResponseRuntimeProof/v2` / `catchplate.nativeResponseAttestationVerification/v2` |

V1 rejects `statementProfile`, including null, and every new family/envelope.
V2 requires its exact selector and rejects every old family/envelope. There is
no retry, downgrade or automatic profile detection. The proof-client adapter's
`native_principal_profile()` only reports the selection retained after protected
input admission; it is not an attestation or authorization verdict.

The Python `verify_native_response_attestation.py` remains an old-expectations/v1
diagnostic verifier. The explicit v2 selection described here is supported by the
Rust verifier; it is not a claim of blanket Python/Rust input-profile parity.

The expectations remain bounded to 16 KiB. Release, policy, configuration, runtime
CA certificate/SPKI, binary, boot, response key, control-plane response key, full
PCR/EIF/module scope, nonce and freshness meanings are unchanged. Trust-root
originals and their independent provenance remain mandatory. Changing a profile
does not grant permission to change these pins or renew an original deadline.

## Exact signed bytes and genuine role-4 verification

Native statements retain their mode's exact closed field set. Only their explicit
version selects the native principal rule: nonempty UTF-8, at most 1024 bytes,
trim-stable, with no control characters. Other identifiers are not widened.
Legacy families retain their existing mode-specific limits and alphabets.
Buffered nonce originals remain 32–64 bytes; streaming and observation require
exactly 32. All must equal the independently retained nonce.

The explicit API version is part of the sorted, compact UTF-8 JSON signed by the
actual response-key owner. Neither verifier rewrites it, normalizes a native
statement into an old family, or ASCII-reencodes Unicode. The exact statement
digest and Ed25519 signature are checked before reconstructing the unchanged
role-4 challenge from nonce, statement digest and signature. Genuine original
Nitro COSE verification still binds that same key to the independent release,
policy, configuration, runtime CA and boot/control-plane-key commitments.
Relabeling old signed bytes cannot satisfy the new signature/challenge joins.

The native runtime envelope keeps the same six fields and kind. The local
verdict keeps the same fields with the explicitly selected version, still
`resultScope: local-signature-and-native-quote-only` and `okForAction: false`.
The protected adapter invokes the independently pinned sealed verifier on the
actual proof, rechecks held inputs, and compares the entire returned diagnostic
to its own original-derived projection. A supplied success JSON never replaces
signature or quote verification. Existing input, statement, output and process
bounds remain unchanged.

## Receipt, binding and transport joins

Wide-principal response compatibility also requires the actual producer and full
capture validators; accepting a top-level native statement alone is insufficient.
The native contract uses `catchplate.nativeControlPlaneAuthorizationReceipt/v1`
with kind `CatchplateNativeControlPlaneAuthorizationReceipt`. Ordinary/durable
release bindings use `catchplate.nativeReleaseAuthorizationBinding/v1` and `/v2`,
including the actual normalized `approver_policy`; reserve, dispatch, complete
and response APIs have explicit native versions. The response API is
`catchplate.nativeReleaseAuthorizationResponse/v1` or `/v2`, not a renamed legacy
`releaseAuthorization` object.

The reduced native streaming commitment uses
`catchplate.nativeResponseAuthorizationCommitment/v1`: the existing twelve
commitment fields plus `apiVersion` and `approver_policy_sha256`, hashing the exact
canonical ASCII-escaped policy value, including null. These nested originals,
actor/current-policy authority, actual request/response/receipt digests and
ordinary-versus-durable semantics must agree across the control plane, signer
and full client validator. Old receipts, bindings and commitments cannot be
relabeled or accepted under the new profile. Native capture artifacts are v2;
legacy captures remain v1.

Before native reservation, the read-only
[`nativeReleaseAuthorizationPreparation/v1` body](../schemas/native-release-authorization-preparation.v1.schema.json)
has exactly eight fields: `apiVersion`, `principalId`, `routeId`, `policyHash`,
`requestDigest`, `operationDigest`, `approverPolicy` and `approverPolicySha256`.
The existing `responseSignature/v3` must authenticate the exact body and original
signed timestamp; the retained caller deadline is not renewed. The consumer joins
every expected identity/digest and the actual route restrictions before using it.
Native reserve must match the current normalized approver-policy hash before effects.
Only the deadline-bound `native-prepare` response reader has a dedicated 96 KiB
body cap, allowing the bounded normalized policy plus preparation fields. Other
release-authorization transition responses and receipt bodies retain their
existing 32 KiB caps; this does not widen all control-plane response handling.

The shared `native_approver_policy_v1::require_policy` checks only normalized
shape: null is required for non-JIT, while JIT requires the exact eight-field
policy and twelve-field credential object, sorted unique arrays and a 64 KiB
compact ASCII-escaped size bound. It preserves CP text-set rules, including
Python-strip behavior, rather than inventing extra URL/alphabet restrictions.
The native profile explicitly bounds `minimumTrustBundleSequence` to null or
1..u64::MAX; legacy normalization is unchanged. Actual configured RP/origin,
route users/quorum/authenticator/hardware policy, current roles/trust and genuine
approval are separate checks. New native policy hashes use exact Python
`ensure_ascii=True` bytes, including DEL and supplementary-character escaping;
the hash of null is still over its exact JSON value, not an omitted field.

The producer selects native statements from retained native transport ownership
before receipt acquisition and provider effects. Request mode selects buffered,
streaming or observation within that profile, not a fallback to a different
profile. The independently selected client profile must agree with the actual
native transport and full response path. The [.247 principal-preflight owner](native-principal-preflight-verification.md)
continues to retain genuine proof on the same CONNECT transport; preflight alone
does not authorize CONNECT or an upstream action.

The [native credential-lease path](native-credential-leases.md) now has separate
request, authority, envelope and plaintext profiles selected from the actual
native recipient owner. A separately pinned recipient verifier joins the genuine
role-2 quote and exact request digest; the broker checks retained native release
authority before one-use controlled issuance. This replaces the interim refusal
only on the fully native path. Legacy leases retain their limits, and no identity
remapping or profile downgrade is authorized. Source integration still does not
prove an executed credentialed flow, complete onboarding or production custody.

This verifier does not establish full HTTP/exporter/receipt/witness semantics,
install egress rules, authorize canaries, or prove runtime compatibility. Those
checks belong to their actual retained owners and independent acceptance gates.
The [egress design](native-egress-installation-design.md) remains architecture,
not an implemented effect. Legacy packet/runtime-manifest and installation
authority meanings remain unchanged.
