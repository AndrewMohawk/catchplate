# Offline native workload trust authorization

The purpose-fixed producer is
[`authorize_native_workload_identity_trust.py`](../scripts/authority/authorize_native_workload_identity_trust.py).
It authorizes the complete immutable native client-root set for one exact v22
configuration and launch. It does not generate a key, enroll a signer, fetch a
policy, install trust, start a service, issue a certificate or approve a pilot.
This source batch has not executed the signer or tested runtime acceptance.

The independent operator must supply the already approved inputs:

- The complete `nativeStartupConfiguration/v22` original and its independent
  SHA-256 pin, including `workloadTrustAuthorizer` with the separately enrolled
  Ed25519 public PEM and its exact PEM hash. The trust private key must remain
  outside the gate, configuration, native runtime and workload issuer.
- The exact `nativeStartupLaunch/v1` original and its independent pin. It must
  already reference that full configuration and the actual approved release.
- The signed policy original whose file hash equals `configuration.policy.sha256`.
  The CLI also requires its selected original-file pin; it does not rewrite or
  sign the policy.
- The independently obtained policy-signing public SPKI PEM and its PEM pin.
  Its DER hash must equal both `native.expectedPolicySigningKeyId` and the signed
  policy's `metadata.signingKeyId`. Native startup obtains this key through the
  actual attested control-plane trust-root path. A hash, a policy envelope's
  claimed key, or `native.controlPlaneResponsePublicKeyPem` cannot supply it.
- An inherited read-only FD for the existing matching trust-authorizer private
  PKCS#8 PEM, plus the explicitly authorized grant issue/expiry epoch nanoseconds.
  No local key generation, default signer, approval service or self-approval is
  provided. The operator's independent authority is a prerequisite, not a result
  of passing file hashes to this program.

Configuration, launch and policy are hashed as their retained original bytes;
they are never normalized to make a pin match. Configuration/launch use the
existing bounded strict integer JSON profile; signed policy preserves the
existing v1 or finite-number v2 signature transcript. Policy file hash and the
semantic `policyHash` are distinct and both are checked.

Run once in the project's provisioned Python environment with its pinned
dependencies. The output parent must already be a protected directory. Replace
the descriptive pins/timestamps below with independently admitted values; this
is an operator invocation template, not an executed command:

```sh
python3 scripts/authority/authorize_native_workload_identity_trust.py \
  --configuration /srv/serverware-approval/native-configuration.json \
  --configuration-sha256 'sha256:<approved-configuration-original-digest>' \
  --launch /srv/serverware-approval/native-launch.json \
  --launch-sha256 'sha256:<approved-launch-original-digest>' \
  --policy /srv/serverware-approval/policy.json \
  --policy-sha256 'sha256:<approved-policy-file-digest>' \
  --policy-signing-public-key /srv/serverware-approval/policy-public.pem \
  --policy-signing-public-key-sha256 'sha256:<approved-policy-public-PEM-digest>' \
  --authorizer-private-key-fd 3 \
  --issued-at-epoch-ns "$NATIVE_TRUST_ISSUED_EPOCH_NS" \
  --expires-at-epoch-ns "$NATIVE_TRUST_EXPIRES_EPOCH_NS" \
  --timeout-ms 30000 \
  --output /srv/serverware-approval/grants/native-workload-trust.json \
  3</srv/serverware-independent-authority/native-trust-authorizer.pem
```

The private key is not passed in argv or printed. Protected original FDs remain
held and rechecked; output is exclusive, bounded, mode 0600 and fsynced. It is
not overwritten. A partial or uncertain output stays for operator reconciliation,
not automatic retry. Python/OpenSSL may retain key copies; this is not hardware
key custody or a memory-erasure guarantee. Blocking file/crypto calls require an
external operator watchdog in addition to the bounded processing clock.

The producer derives the ordered 1–32 certificate/SPKI inventory from the actual
configured DER roots (64 KiB each, 1 MiB total, no repeated DER). It reuses the
restricted CA/key/extension checks, retaining each exact original SPKI. The
commitment is the existing native domain plus root-count u32BE and ordered
length-u64BE/DER frames, not a PEM hash. Every mTLS principal in the whole signed
policy is included, uniquely sorted by ID, with the existing normalized selectors
and an explicit issuer in that root inventory; the 1–64 inventory retains its
64 KiB wrapper bound. No caller-authored root or principal summary is accepted.

Deployment comes from `credentialCurrentness.deploymentId`, joined to the existing
succession/canary fields, not inferred from `gate.instanceId`. The grant binds
both identities, actual policy hash/sequence/rollback epoch, full configuration
and launch hashes, release reference and unchanged launch BOOTTIME deadline.
The grant is currently valid, at most 24 hours, and inside every root and launch
CA/ingress interval. The shorter original processing deadline is never renewed.
The offline host's BOOTTIME is not a measurement of the target guest: the native
consumer must independently enforce the copied target deadline and actual keys.

The signed original is exactly canonical ASCII JSON without a final LF, at most
128 KiB. Its envelope/payload schemas are
`signedNativeWorkloadIdentityTrustAuthorization/v1` and
`nativeWorkloadIdentityTrustAuthorization/v1` under the `serverware.` namespace.
The signature preimage is the payload schema, NUL, and canonical payload; the
revision comes only from the shared `authority_contract.SOURCE_REVISION`.
Authorizer/CA/policy/control-plane/enrollment/setup keys must be distinct. The
runtime additionally excludes its actual generated TLS/CA and proof keys.

Transfer the exact public grant to the existing protected startup-original path,
independently admit its SHA-256, and pass it to the real gate selector
`--native-workload-trust-startup-v22` with
`--workload-trust-authorization PATH` and
`--workload-trust-authorization-sha256 SHA256`, alongside the unchanged original
configuration/launch pins. The fixed enclave image selector `--workload-trust-v22`
maps to that `--native-workload-trust-startup-v22` gate mode; it does not select a
different authorization profile. The grant is deliberately absent from configuration
and launch, so their hashes are acyclic. See [native workload trust](native-workload-trust.md)
for retained TLS/policy/currentness checks. Standard v1 PEM trust grants and the
standard publisher remain unchanged and cannot stand in for this native grant.
