# Setup native loaded-policy observation

This is a source implementation of a fresh, read-only observation. It does not
complete Setup, enroll a workload, resolve a credential lease, contact a
provider, authorize proxy traffic or hot-reload policy. The existing
control-plane `installed` observation remains explicitly control-plane-only.
Build, deployment and runtime acceptance are still required.

## Actual owners and contact

`POST /api/setup/policy-candidate/native-installed` retains the genuine OIDC
cookie/CSRF `credential_owner`, activated Setup revision 3, protected candidate
continuation and completed generation claim. It rechecks the actual current
committed policy high-water, active credential/generation and open currentness
root before and after one authenticated management contact. No row is mutated.
The original request allowance is at most 30 seconds and remains clipped by
the original Setup and admitted custody expiry. Loss or failure returns
unavailable, never a cached observation or automatic retry permission.

The management contact uses the existing fixed local management host/port
allowlist and management service token, with redirects and environment proxies
disabled. Only `/v1/native-loaded-policy` is newly allowed. This transport is
not workload mTLS: the native `/attestation` ingress, its TLS exporter and
principal admission are unchanged and cannot be substituted.

The native route runs only on the authenticated management listener. It holds
the actual `GateState.snapshot` read guard and retained immutable
`native_policy_bytes` through preparation/quotation; it checks the loaded
principal, route and credential reference. Its dedicated signing family checks
the actual held native key/boot/control-plane-key identity, committed policy
and original native lifetime, then obtains a fresh NSM role-4 quote bound to
the exact signature and request challenge. A DTO cannot construct the binary's
private preparation. No currentness, audit, OAuth or response signing family is
relabelled. Late results are discarded; these checks cannot interrupt a
blocked NSM ioctl, so the real native runtime's original watchdog remains
required, unchanged and independent of HTTP delivery.

## Explicit cold input and independent trust

The existing descriptor launcher adds only these exact selections:

- `control-plane --setup-native-observation`
- `control-plane --policy-canary-intake --setup-native-observation`

Old selections do not open this input or preserve injected observation FD/path
environment variables. The source-fixed public input is
`/run/catchplate/authority-trust/setup-native-observation.json`, canonical
ASCII JSON at most 16 KiB with exact ten fields:

`schema`, `sourceRevision`, `controlPlaneConfigurationDigest`,
`authorityRootFd`, `authorityRootSha256`, `authorityRootSpkiSha256`,
`authorityConfigurationFd`, `authorityConfigurationSha256`,
`authorityConfigurationDigest`, `holderId`.

The schema label is `catchplate.setupNativePolicyObservationConfiguration/v1`.
Digests/holder use nonzero `sha256:<64 lowercase hex>`, sourceRevision is the
actual source cohort, and the two distinct public material descriptors are
integers 32..1023. Their only paths are
`setup-native-observation-root-public-key` and
`setup-native-observation-authority-configuration.json` under the same fixed
authority-trust directory. The launcher refuses occupied descriptors and uses
its existing protected-file-to-sealed-memfd copier; it generates no key,
signature, policy, root or authorization. The config descriptor is delivered
as `CATCHPLATE_SETUP_NATIVE_OBSERVATION_CONFIG_FD`.

All three descriptors must be included in the real independently admitted
control-plane runtime/custody descriptor inventory. The request reader borrows
and rechecks the same root-owned sealed originals, identities and bytes; a
browser cannot choose them. The public root must be independently provisioned,
Ed25519 and distinct from the runtime root. Its signature authenticates the
full retained `signedPolicyAuthorityServiceConfiguration/v6` original. The
existing signed `credentialCurrentnessPolicy` supplies the exact selected
holder's boot/key, CP key, release/policy/configuration/CA scope, binary/PCR/EIF,
module, age/skew and Nitro roots. These are identity-verification pins only:
the observer never invokes or derives currentness/effect permission.

The two configuration commitments are deliberately distinct:

- `authorityConfigurationSha256` pins the complete original envelope bytes;
  `authorityConfigurationDigest` is the framed digest of the fully signed
  authority payload, with no excluded fields or reconstructed substitute.
- `controlPlaneConfigurationDigest` must equal the actual retained custody
  binding and the **signed** currentness policy's CP configuration association.

Equating both digest namespaces would create an embedded self-reference.
The selected holder and policy must match the new native boot actually being
observed; stale pre-publication scope refuses. Provisioning these independent
originals is required deployment work, not accomplished by this source code.

## Closed evidence and result

The native request is exact nine fields: `apiVersion` =
`catchplate.nativeLoadedPolicyRequest/v1`, `challenge` (fresh nonzero canonical
32-byte base64url), `contextSha256`, `policyHash`, `principalId`, `routeId`,
`credentialId`, `issuedAtEpochNs`, `expiresAtEpochNs`. It is canonical ASCII
without LF, at most 4096 bytes, and expires within the original 30-second read
window. Context commits the retained continuation digest, actual current
credential/generation/root digest, and reviewed assignment (including version).

Statement exact nine fields: `apiVersion` =
`catchplate.nativeLoadedPolicyStatement/v1`, `request`,
`policyOriginalSha256`, `routePolicyDigest`, `bootId`, `keyId`,
`controlPlaneResponseSigningKeyId`, `dataPlaneBinarySha256`,
`observedAtEpochNs`. Ed25519 signs schema ASCII + NUL + canonical statement.
Fresh quote nonce is SHA256 of
`catchplate/native-loaded-policy-attestation/v1` + NUL + challenge bytes +
SHA256(canonical statement) + raw 64-byte signature.

Evidence exact three: `statement`, `signature` (`ed25519:` + canonical
unpadded base64url), `nativeKeyEvidence` (existing exact role-4 quote originals).
The control plane independently verifies the signature, quote certificate/PCR
chain, exact public key/user data/challenge, freshness, loaded-policy original
and route digest against its retained actual claim—not supplied success flags.

Public request remains the existing materialization exact request3 with
sessionId and expectedRevision 3. The result wrapper exact6 uses
`catchplate.setupNativePolicyObservation/v1`, `okForAction:false`,
`automaticRetryAllowed:false`, `proxyReady:false`, `setupSessionId` and
`observationOriginal`. The latter is canonical ASCII exact10:
`apiVersion:catchplate.setupNativeLoadedPolicyObservation/v1`,
`scope:native-loaded-policy-only`, the same three false flags,
`nativeLoadedPolicyVerified:true`, `continuationSha256`,
`currentCredentialStateSha256`, `requestOriginal`, `evidenceOriginal`.
Limits are 524288 complete response bytes, 262144 observation bytes, 4096
request-original bytes and 131072 evidence-original bytes. All original strings
are canonical ASCII without LF. No raw credential row or token is returned.

Credential **version/currentness** is a retained CP row observation bound into
the challenge, not a native lease/secret-availability assertion. The proof
establishes only this loaded policy/route association during its original
window. Native workload enrollment, TLS client admission, actual dispatch and
end-to-end Setup completion remain separate required successors.
