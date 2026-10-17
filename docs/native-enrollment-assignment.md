# Native enrollment authorization and signer foundation

Status: partial N05 source implementation, unbuilt and unexecuted. **No production
enrollment endpoint or usable signing API is enabled by this foundation.**
The complete native enrollment, verifier-mediated trust installation, egress and
canary workflow remains required.

The separate [original-evidence receiver](native-enrollment-verification.md) now
joins independently signed assignment, role-3/role-5 quotes and purpose-specific
packet signature to the actual retained client TLS connection. Its bounded
result is diagnostic only, with `okForAction: false`; it does not enable this
private signer, construct a packet or authorize installation.

## Why a separate purpose is needed

The existing role-4 native key signs only the closed response-proof families
after their own authorization and durable-attempt gates. Its quote commits to a
control-plane public-key pin, but does not prove custody of that control-plane
private key or delegate enrollment signing. The Python enrollment packet still
uses its separate HTTP-response signer and a development-only attestation helper.
Neither key is silently repurposed here.

The new assignment is an explicit independent operator authorization for one
exact unsigned packet and its intended principal/runtime/session scope. A
dedicated native enrollment key has a separate purpose and quote role. It cannot
become a generic message signer, accept a copied success verdict, or use a
caller-supplied packet digest as permission without authenticating the original
assignment and hashing the actual packet bytes.

## Original authorization contract

The [closed assignment schema](../schemas/native-enrollment-assignment.v1.schema.json)
has exactly three envelope fields: `apiVersion`, `assignment` and
`signatureBase64url`. Its 22-field payload binds:

- The authorizer key and assignment identity.
- Release, policy, configuration, runtime CA certificate/key, ingress leaf and
  native ordered client-root commitment.
- Principal, workload issuer certificate/key and client certificate/key.
- Ingress host, server instance, literal proxy endpoint and client challenge.
- Exact unsigned-packet SHA-256 and original validity interval.

The signature preimage is:

```text
"catchplate/native-enrollment-assignment/v1\0"
    || canonical compact sorted UTF-8 JSON(assignment), without LF
```

The complete envelope is canonical compact sorted UTF-8 JSON plus exactly one
LF, at most 16 KiB. Duplicate/unknown fields, noncanonical encodings, zero pins,
unsupported endpoints and malformed identities are rejected. Assignment ID and
challenge each encode a 32-byte value that is not all zero. The original interval
is current, positive and at most 300 seconds; subsequent processing never renews
it. Epoch seconds are capped at 9,223,372,036 to fit the shared signed 64-bit
nanosecond window representation, not merely JSON's larger integer range.

The public authorizer is a separately supplied canonical Ed25519 SPKI PEM with
an independent exact-PEM SHA-256 pin. `authorizerKeyId` is the SHA-256 of its DER
SPKI, **not** the PEM pin. The [explicit startup-v2 authorizer and policy/TLS
admission gate](native-enrollment-admission.md) now retain that cold public input
with key-role separation. A matching hash is not proof of how the operator
admitted its origin; independent configuration/trust delivery remains required,
and the per-request assignment cannot select its own trusted key.
Canonical PKCS8 private-key input is accepted only by the explicit Python
operator-signing helper, paired with this public key. No key file, environment
fallback, key generation, network request or private-key output is added there.

Both implementations take the exact unsigned packet original (1–512 KiB) and
compare its actual digest. That comparison is not semantic approval of firewall
commands, routes, installation paths or a principal. The operator authorizes
those exact bytes. The fixed runtime gate now joins the intended assignment to
its actual policy and complete principal, but supported full packet semantics
and reconstruction remain required before enabling signing.

## Source ownership and retained bounds

The [Python producer/verifier](../catchplate/native_enrollment_assignment.py)
uses the supplied original work/window/deadline and real clock, bounded key and
packet originals, genuine Ed25519 verification and sticky failure. The explicit
signing helper returns only the original signed envelope, not an enrollment
receipt or a claim of runtime acceptance.

The [Rust original verifier](../data-plane/decision-gate-rs/src/native_enrollment_assignment_v1.rs)
returns a crate-private, non-cloneable owner with original assignment identity,
validated scalars and a nonrenewing process/clock/deadline guard. Admission clips
the original caller deadline to one 30-second processing cap and the assignment's
original expiry. Rechecking that owner cannot start a new allowance. It is not a
durable one-use reservation: verifying the same signed original again is still
possible unless the future caller's durable claim prevents it.

The [purpose-specific native key foundation](../data-plane/decision-gate-rs/src/enclave_enrollment_key_v1.rs)
consumes the genuine assignment owner and joins actual native identity/ingress,
certificate, challenge and packet originals. The generated key has no import,
private-key export, cloning or debug interface. Its signing operation remains
private and inaccessible to an external caller. The actual main-binary
`Snapshot`/full-principal and native TLS admission gate is now source-connected,
but packet reconstruction, durable claim/recovery and the request route remain
missing producer gates. A supplied hash or synthetic permission object cannot
replace them.

The private signature preimage is fixed, not a caller-selected signing purpose:

```text
"catchplate/native-enrollment-packet-signature/v1\0"
    || SHA256(exact assignment envelope including LF)[32]
    || packet_length:u64BE || exact_packet_bytes
```

Role 5 retains the existing runtime-key-binding layout: release/policy/config,
actual CA certificate/SPKI, generated raw Ed25519 key hash, and one request
commitment. That commitment is SHA-256 over the NUL-terminated
`catchplate/native-enrollment-key-binding/v1` domain, assignment SHA-256, packet
SHA-256, actual ingress-leaf DER SHA-256 and actual ordered framed root-set
SHA-256, each digest exactly 32 bytes. The NSM public key is the generated raw
32-byte Ed25519 key. The nonce uses the existing native challenge/exporter
recipe with the assigned challenge and the actual retained `ServerConnection`.
The `.236` private foundation supplied no role-5 receiver or accepted public
evidence envelope. The separate [receiver increment](native-enrollment-verification.md)
now authenticates those originals through a closed evidence-v1 envelope and
independent expectations on an actual retained client TLS stream. It does not
provide the missing producer gates or treat matching packet bytes as approved
runtime policy.

## Required next connections

1. Independently provision the [startup-v2 public authorizer and endpoint
   pins](native-enrollment-admission.md), preserving their actual configuration
   origin and key-role separation. Keep the signed assignment per request,
   outside self-hashed static configuration; connect its original acquisition.
2. Build the supported full enrollment handoff from admitted originals around
   the source-connected actual `Snapshot`/full-principal/TLS gate, preserving
   routes, runtime-scoped CA, transport, egress and safe canary obligations.
   Assignment hash equality alone does not establish those packet semantics.
3. Durably claim the exact assignment/packet before any irreversible signature.
   Unknown or interrupted outcomes must not authorize re-signing or a fresh
   key/nonce attempt; recovery needs its own exact retained outcome contract.
4. Connect the request/serving path to the gate's actual retained native TLS
   challenge/exporter and client identity, then connect purpose-specific signing
   and original role-5 NSM evidence only after the missing producer gates.
   Preserve role-4 authority; the vsock runtime's public TCP endpoint is a cold
   pin, not a socket observation or a client address inferred from a CID.
5. Connect actual acquisition and an explicit packet/SDK version around the
   [original-only receiver](native-enrollment-verification.md), which now joins
   role-3 and role-5 runtime, policy, signer and actual session scope. Preserve the
   meaning of existing `runtimeManifestDigest`; a native scope hash cannot be
   relabeled as that legacy manifest. Diagnostic verification is not installation
   authority. Finish verifier-mediated scoped installation, proxy/egress setup
   and allow/deny canaries before claiming N05.

The authority foundation and receiver do not close N05's remaining integration
gates. Legacy enrollment stays unchanged, the private signer cannot service it, and `.235`
[native trust checks](native-workload-trust.md) remain supporting components.
No build, test, runtime, NSM invocation, deployment or paid resource ran for this
source work. Independent production acceptance remains **0/6 verified**.
