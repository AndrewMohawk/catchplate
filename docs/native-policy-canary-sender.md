# Native canary TLS and evidence primitives

This source slice constructs a real dedicated native TLS client and role-4
evidence original. It does **not** select a startup profile, send a request,
durably retain precontact state, recover an uncertain outcome, validate the
twelve event producers or complete a canary rollout. No build, parser, test,
NSM, TLS, provider or cloud execution accompanied this source change.

## Real owner and caller joins

`EnclaveRuntimeIdentityV1::canary_client_identity(deployment, instance, deadline)`
requires the actual generated CA, permanent native serving owner, creator PID
and original CA/BOOTTIME interval. It generates a separate P256 client key and
CA-signed leaf, with exactly ClientAuth EKU and the one source-derived SAN URI
`spiffe://serverware.policy-canary/{deploymentId}/{instanceId}`. Components are
ASCII `[A-Za-z0-9._-]{1,128}`. There is no imported certificate/private key,
audit URI alias, caller certificate DTO or key export. The retained opaque
`NativeCanaryTlsIdentity` rechecks the actual serving owner; the runtime joins
its held CA and same private serving-owner Arc before and after signing.

`native_canary_transport::prepare` binds that owner to actual CP client roots
and the retained native service-relay table. TLS is exactly 1.3; redirects and
idle pooling are disabled. Both exact endpoints use the same HTTPS origin:

- `/api/data-plane/policy-canary/controlled-evidence`
- `/api/data-plane/policy-canary/controlled-evidence/inspect`

The returned `NativeCanaryHttpClient` retains its client privately. It exposes
neither a generic reqwest handle nor a send/retry method. The cold caller must
include this origin in the original immutable service route table; this slice
does not alter an already established table or add a direct-network fallback.

`Owner::prepare_evidence` uses the current active gate snapshot, the actual
instance, real native custody boot/key/CP key, derived holder ID, actual
executable-byte digest and generated TLS bindings. It generates a fresh nonce
and narrows the original BOOTTIME allowance to at most 30 seconds, never
renewing it. Purpose assignment, canary assignment and canary boot hashes
remain explicit claims for the independently admitted CP policy to verify.
The native boot is canonical base64url32; the distinct canary boot is a
prefixed SHA256 digest. They are never copied into one another.

`Owner::sign` invokes the actual native-only
`CustodySignerTransport::canary_evidence` and
`CustodyRuntime::sign_native_canary`. The wrapper rereads the actual binary
before and after. The signer verifies actual policy/key/boot/holder/CP key,
the generated TLS owner, original batch/statement and original operation
deadline; it signs with the retained non-exporting role-4 key and acquires a
fresh NSM document. A UDS/development signer is refused. Identity association
does not replace the retained key lifetime with the shorter command allowance.

## Exact public bytes

The paired [native schema](../schemas/native-policy-canary-sender.v1.schema.json)
references the [receiver contract](../schemas/policy-canary-controlled-evidence.v1.schema.json)
instead of maintaining a second HTTP definition. `BatchOriginal::parse`
retains the original ASCII string after bounded, duplicate-key-free structural
and exact canonical-byte checks. It never rewrites a record or casts epochs
through floating point. An original whose numerical spelling cannot be
reproduced by the native canonical encoder is refused, not normalized. This
structural check is **not** verification of any event's signature, provenance
or actual producer operation.

The signed statement has the receiver's exact 22 fields. Its preimage is
`schemaASCII || NUL || fullCanonicalStatementASCII`, including Python-compatible
DEL escaping. This deliberately differs from audit's digest preimage.
The fresh NSM nonce is
`SHA256("serverware/canary-evidence-intake-attestation/v1" || NUL || nonce32 || SHA256(statementASCII) || signature64)`.
The original role-4 key/scope/boot bindings remain unchanged. Signature text
is `ed25519:` followed by canonical unpadded base64url64.

The evidence envelope has exactly `statement`, `signature`,
`nativeKeyEvidence` and `clientCertificateDerBase64Url`. Certificate DER is the
actual client leaf, not a caller copy. The HTTP body has exactly `apiVersion`,
`batchOriginal`, `nativeEvidence`; intake and inspect carry the same original
batch but fresh purpose-specific evidence. Bounds remain batch 1 MiB, 1–128
events, leaf 16 KiB, NSM document 12 KiB, evidence 128 KiB, HTTP body
1 MiB + 192 KiB, positive integer epochs at most signed-i64 and a 30-second
maximum statement interval.

## Required next integrations

Root's actual durable sender must retain and authenticate the original batch
and signed precontact body **before** contact; join each contact/uncertain/
inspection transition to that retained slot; enforce original lifetime and
same actual TLS identity; authenticate the complete signed CP response under
the original nonce/context and compare the exact result. Merely storing the
public body in `SignedEvidence` is not durability or permission to send.

The twelve real exporters, independently provisioned purpose assignment and
measured CA/native-key admission remain required. The receiver verifies real
TLS peer DER, ClientAuth/URI/leaf/SPKI, full statement signature and fresh
Nitro evidence under independent PCR/PKI/age/nonce policy. Neither local NSM
availability nor this source's signature proves those admissions. Old startup,
audit, signing and network profiles are unchanged.
