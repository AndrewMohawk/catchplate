# Policy-aware ordinary response verification

PolicyAware is an explicitly selected ordinary representation, not a native
attestation mode or an automatic upgrade of legacy proofs. Its
[release authorization contract](policy-aware-release-authorization.md) commits
the actual normalized approver policy and uses separate lifecycle and credential
lease families. The receiving profile is selected from independent protected
configuration, never from a statement's incoming version or a successful verdict.

## Independent expectations

The proof client opens the protected expectation original under its inherited
deadline, pins the exact original file SHA-256 and retains its ownership. The
[closed v1 schema](../schemas/policy-aware-response-expectations.v1.schema.json)
contains exactly nine fields:

- `apiVersion`: `catchplate.policyAwareResponseExpectations/v1`.
- `statementProfile`: `catchplate.policyAwareResponseStatements/v1`.
- `responseSigningKeyId`, `controlPlaneResponseSigningKeyId`, `policyDigest`,
  `releaseDigest` and `dataPlaneBinaryDigest`: canonical nonzero SHA-256 pins.
- `serverInstanceId` and `principalId`: independently configured exact identities.

The original is at most 16 KiB. Principal is bounded to 256 UTF-8 bytes; server
instance to 2048; both are nonempty, trim-stable and free of Unicode controls.
The actual configured control-plane verification key must reproduce the pinned
key ID. The retained owner checks the same process, deadline and original file,
and prevents output from replacing that input. It is not serializable permission.

Opt in with both `--policy-aware-expectations PATH` and the independent
`--policy-aware-expectations-sha256 sha256:...` pin, together with the ordinary
mode's existing identity and key arguments. The input is genuinely opened before
contact; combining this profile with native expectations is refused. The held
PolicyAware I/O owner checks the original process and deadline on every plaintext
read and write. Before publication, the client remeasures the protected input and
checks output aliases. These checks do not renew the operation window.

## Original verification

Only the selected statement family is admitted: buffered
`catchplate.policyAwareProxyResponseStatement/v1`, streaming
`catchplate.policyAwareStreamingResponseStatement/v1`, or observation
`catchplate.policyAwareResponseObservationStatement/v1`. The actual statement,
signature key, policy/release/binary and server identity are compared to the pins.
Observation may retain its existing null-principal form where the original
observation contract allows it; that does not assert successful principal
authentication. Other statement principals must equal the independent pin.

The ordinary vendor envelope and `catchplate.vendorTeeVerification/v1` receipt
stay unchanged. Profile-aware entry points reject Native and require the exact
selected original statement version. Expected attested claims use that same
version and actual statement digest; signed legacy bytes are never relabeled.
External ordinary attestation-command adapters must support those explicit
PolicyAware statement values in their request and signed attested claims; the
unchanged outer command version is not permission to substitute a legacy claim.
The ordinary control-plane receipt verifier admits only the selected matching
receipt and binding profiles. Existing original Ed25519 signatures, exact
request/response comparisons, challenge, TLS exporter and time checks still
apply; the expectation document alone proves none of them.

Development fixtures retain their existing explicitly development assurance.
Production still requires the independently supplied verifier key, production
vendor/platform assertions, quote and certificate-chain verification, revocation
checks, non-debug mode, exact signed claims, expected instance and valid receipt
window. Selecting PolicyAware does not relax these requirements or convert a
development result into production evidence. Native role-4 verification remains
on its separate genuine original verifier path.

## Published data shapes

The [closed statement schema](../schemas/policy-aware-response-statements.v1.schema.json)
includes the matching policy-aware receipt and normalized-policy commitment.
The [closed artifact schema](../schemas/policy-aware-response-artifacts.v1.schema.json)
covers these five actual client labels (each prefixed with `catchplate.`):

| Mode | Proof artifact | Capture artifact |
| --- | --- | --- |
| Buffered | `policyAwareProxyResponseProof/v1` | `policyAwareProxyResponseCapture/v1` |
| Streaming | `policyAwareStreamingProxyResponseProof/v1` | `policyAwareStreamingProxyResponseCapture/v1` |
| Observation | `policyAwareResponseObservationProof/v1` | Included in the proof's request/response fields |

The three proof kinds are respectively `CatchplatePolicyAwareProxyResponseProof`,
`CatchplatePolicyAwareStreamingProxyResponseProof`, and
`CatchplatePolicyAwareResponseObservationProof`. Runtime envelopes remain the
ordinary `proxyResponseRuntimeProof/v2`, `streamingResponseRuntimeProof/v1`, and
`responseObservationRuntimeProof/v1` families; their nested statements and claims
must match the independently selected profile. A schema-valid artifact or a
collector/vendor verdict cannot approve its own signing key or authorize release.

Mode-specific identity limits remain in force: buffered principal and route use
the existing bounded 256-byte text profile; streaming and observation retain
their existing restricted identifier alphabet and limits. The expectation
document's 2048-byte server-instance ceiling does not widen a statement's own
limit. This is not the native 1024-byte principal profile.

Legacy wrappers still select Legacy. The producer's ordinary cold switch must
be paired with the independently pinned response and recipient profiles before
use; version disagreement refuses rather than falling back. This is source-only,
unbuilt and unexecuted work, not provider/canary acceptance, host isolation or a
production gate.
