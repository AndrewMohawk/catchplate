# Native bootstrap setup and packet originals

This source slice connects an independently signed public setup association to
the actual private native bootstrap admission and a deterministic packet-v2
original container. It does not enable the enrollment signer, expose a route,
install trust, consume a protected capability or complete enrollment. Legacy
agent-enrollment v1 and native startup v1/v2 retain their existing semantics.

## Independent setup authority

Native startup v3 adds the required `enrollmentSetupAuthorizer` object with exactly
`apiVersion: catchplate.nativeEnrollmentSetupAuthorizer/v1`, `publicKeyPem` and
`publicKeyPemSha256`. Existing `enrollmentAuthorizer` and
`enrollmentProxyEndpoint` remain mandatory. The new independently pinned public
Ed25519 key has a separate setup purpose; delegation authority does not imply
host installation authority. The PEM-original pin differs from the DER-SPKI key
ID inside signed setup. Neither is an environment-selected or per-request root.

Cold admission excludes actual delegation, policy and response key roles.
Setup verification also excludes the genuinely delegated runtime CA, caller
issuer/key and target issuer/key SPKI commitments. Signed pins constrain scope;
only the actual native admission establishes runtime and connection provenance.
See the [cold-key schema](../schemas/native-enrollment-setup-authorizer.v1.schema.json).

The [Python producer and original verifier](../catchplate/native_enrollment_bootstrap_setup.py)
pair with the [Rust original verifier](../data-plane/decision-gate-rs/src/native_enrollment_bootstrap_setup_v1.rs).
The closed envelope contains `apiVersion`, `setup` and `signatureBase64url`.
The envelope version is `catchplate.signedNativeEnrollmentBootstrapSetup/v1`;
the 21-field payload version is `catchplate.nativeEnrollmentBootstrapSetup/v1`
and purpose is `native-enrollment-bootstrap-setup`. Ed25519 signs:

```text
ASCII("catchplate/native-enrollment-bootstrap-setup/v1") || NUL || canonical setup JSON
```

Canonical JSON is sorted, compact and `ensure_ascii=True`, with lowercase Unicode
escapes and surrogate pairs. Payload signing excludes a final LF; the envelope
has exactly one LF, at most 32 KiB and depth 4. Its [closed schema](../schemas/native-enrollment-bootstrap-setup.v1.schema.json)
is descriptive, not a substitute for original signature or scope verification.

The setup commits to exact delegation, target request and selected policy
requirements originals; repeated runtime/policy/target identity must match the
genuinely admitted delegation. Its typed public deployment fields contain:

- Exact HTTPS control-plane/proxy origins, the independently pinned proxy TCP
  endpoint, canonical nonzero-prefix CIDRs and explicit unicast host addresses.
- A public CA-install capability ID/token-digest association, original expiry,
  destination path, UID/GID and mode 0644. Replacement requires explicit
  `replaceExisting: true` and a nonzero `expectedExistingCertificateSha256`;
  that field must be null when replacement is false.
- Required nullable Kubernetes namespace/label selectors and a declared host,
  boot ID, network-namespace device/inode and owner UID.

There is no raw token, shell command, private key, free-form policy graph or
hidden header/proxy-auth value. These declarations do not prove the capability
reservation, token possession, namespace ownership, current destination file or
Kubernetes resource exists. The existing legacy CA-install session is real
protected server state with a secret token; its ID/hash or URLs cannot replace
that authority. Protected reservation/ownership and durable consumption remain
mandatory before any installation or signing is reachable.

## Python original APIs and budgets

`_verify_on_work` takes `setup_bytes`, `setup_public_key_bytes`,
`expected_setup_pem_sha256`, `delegation_bytes`, `delegation_public_key_bytes`,
`expected_delegation_pem_sha256`, `target_request_bytes`,
`target_issuer_certificate_bytes`, `policy_requirements_bytes`, plus the existing
`work`, `live_window`, `transport_deadline_ns`, optional `_current` and
`_additional_original_bytes`. The issuer input is its independently selected
canonical PEM original, not an embedded key or a successful verification object.

`_produce_on_work` replaces `setup_bytes` with canonical `payload_bytes` and
explicit canonical PKCS8 `setup_private_key_bytes`. It performs no key lookup,
generation or secret output, changes no selected field, and genuinely re-admits
its produced setup signature before return. Both APIs replay the actual .240
delegation and .239 target request/CSR/PoP with the independent issuer. Returned
immutable public facts are not native runtime or installation authority.

Both reuse one inherited work ledger and real-clock window, narrowing to at most
30 seconds without renewal. Before decoding, the representation reservation is
caller-held bytes plus 16 times actual input originals (and the bounded output
for production) plus 256 KiB, within the existing 64 MiB remaining allowance.
Actual work is additionally metered. Setup lifetime is at most 300 seconds and
wholly inside original delegation, target request/issuer and capability expiry.
Guards preserve original expiry and nonreversing clocks through return.

Requirements bytes are only hashed by Python as a selected signed commitment.
They do not establish that a current runtime has that policy. The native
[requirements projection](../data-plane/decision-gate-rs/src/native_enrollment_policy_requirements.rs)
comes from the actual current `Snapshot`: complete public identity constraints,
header names/external-auth requirements, entitled routing facts and commitments
to hidden compiled semantics. It contains no secret header/token values. It is
complete-or-refuse, at most 64 KiB and 128 routes, canonical JSON without LF.
Those public facts and opaque component commitments are data, not evaluation of
the fresh target against every prospective identity or issued-leaf selector.

## Unsigned packet v2 and SDK extraction

The [actual private constructor](../data-plane/decision-gate-rs/src/native_enrollment_bootstrap_admission.rs)
retains genuine caller-to-target admission, independently verifies setup, derives
requirements from its current immutable Snapshot and compares the signed hash.
It then constructs exactly these seven [packet-v2 fields](../schemas/native-enrollment-packet.v2.schema.json):

| Field | Exact original / decoded bound |
| --- | --- |
| `apiVersion` | `catchplate.nativeEnrollmentPacket/v2` |
| `purpose` | `workload-bootstrap` |
| `delegationBase64url` | Signed delegation including LF / 32 KiB |
| `setupAuthorizationBase64url` | Signed setup including LF / 32 KiB |
| `targetRequestBase64url` | Original target request without LF / 64 KiB |
| `targetIssuerCertificateDerBase64url` | Selected installed issuer DER / 64 KiB |
| `policyRequirementsBase64url` | Actual requirements JSON without LF / 64 KiB |

All five originals use canonical unpadded base64url. The flat outer JSON is
canonical sorted compact ASCII with exactly one LF, at most 512 KiB. It has no
legacy `runtimeManifestDigest` alias, copied verification result or installation
receipt. This container itself is unsigned.

The [SDK decoder](../catchplate_agent_trust/native_enrollment_packet.py) exposes only
`decode_packet_originals_on_budget(*, packet_bytes, budget)`. It checks the exact
flat shape, canonical encoding, component bounds and caller's existing deadline,
then returns frozen, non-repr original-byte fields `delegation_bytes`,
`setup_authorization_bytes`, `target_request_bytes`,
`target_issuer_certificate_der_bytes` and `policy_requirements_bytes`. It imports
no control-plane code and does not parse component JSON/DER, verify signatures,
accept a quote, create an allowance or return success/permission flags. Its
representation preflight and actual inherited-ledger charges precede/cover
allocation. Only original bytes may enter subsequent genuine native receiving;
this Python object is not trusted authority.

## Remaining boundary

Full prospective target selectors/issued-leaf admission, protected install
reservation/token ownership, durable one-use claims and uncertain-outcome
recovery, actual acquisition/public route, final original packet/role-5 receiving,
issuer grant and trust installation remain open. Existing private admission
does not waive those gates; the signer remains inaccessible. This is source
connection only: no build, tests, runtime, deployment or pilot acceptance is
claimed, and no parent checkpoint closes.
