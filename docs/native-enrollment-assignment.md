# Native enrollment authorization and signer foundation

Status: partial N05 source implementation, unbuilt and unexecuted. **No production
enrollment endpoint or usable signing API is enabled by this foundation.**
The complete native enrollment, verifier-mediated trust installation, egress and
canary workflow remains required.

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
"serverware/native-enrollment-assignment/v1\0"
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
SPKI, **not** the PEM pin. A matching hash is not proof of how the operator
admitted that authorizer. Cold root delivery and independent administration still
have to establish that origin; the assignment cannot select its own trusted key.
Canonical PKCS8 private-key input is accepted only by the explicit Python
operator-signing helper, paired with this public key. No key file, environment
fallback, key generation, network request or private-key output is added there.

Both implementations take the exact unsigned packet original (1–512 KiB) and
compare its actual digest. That comparison is not semantic approval of firewall
commands, routes, installation paths or a principal. The operator authorizes
those exact bytes; the future runtime gate must independently join the intended
native assignment to its actual policy and reconstruct the supported packet.

## Source ownership and retained bounds

The [Python producer/verifier](../serverware/native_enrollment_assignment.py)
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
private and inaccessible to an external caller because the actual main-binary
`Snapshot` policy/principal admission has not yet been connected. A supplied
hash or synthetic permission object is not a substitute for that gate.

The private signature preimage is fixed, not a caller-selected signing purpose:

```text
"serverware/native-enrollment-packet-signature/v1\0"
    || SHA256(exact assignment envelope including LF)[32]
    || packet_length:u64BE || exact_packet_bytes
```

Role 5 retains the existing runtime-key-binding layout: release/policy/config,
actual CA certificate/SPKI, generated raw Ed25519 key hash, and one request
commitment. That commitment is SHA-256 over the NUL-terminated
`serverware/native-enrollment-key-binding/v1` domain, assignment SHA-256, packet
SHA-256, actual ingress-leaf DER SHA-256 and actual ordered framed root-set
SHA-256, each digest exactly 32 bytes. The NSM public key is the generated raw
32-byte Ed25519 key. The nonce uses the existing native challenge/exporter
recipe with the assigned challenge and the actual retained `ServerConnection`.
The eventual receiver must authenticate all originals; no role-5 receiver or
accepted public evidence envelope is supplied by this private foundation.

## Required next connections

1. Deliver the independently admitted enrollment authorizer and assignment
   through explicit cold native startup, with current release/configuration
   authority and key-role separation. Do not borrow the HTTP-response key's role.
2. Join the actual policy `Snapshot`, principal and complete mTLS selectors to
   the assignment; reconstruct the supported full enrollment handoff from
   admitted originals, preserving its routes, runtime-scoped CA, transport,
   egress and safe canary obligations.
3. Durably claim the exact assignment/packet before any irreversible signature.
   Unknown or interrupted outcomes must not authorize re-signing or a fresh
   key/nonce attempt; recovery needs its own exact retained outcome contract.
4. Supply challenge/exporter and client identity from the actual retained native
   TLS owner, then produce purpose-specific signature and original role-5 NSM
   evidence without changing the existing role-4 response authority.
5. Add genuine original-only client verification and an explicit packet/SDK
   version, joining role-3 and role-5 runtime, policy, signer and session scope.
   Preserve the meaning of existing `runtimeManifestDigest`; a native scope hash
   cannot be relabeled as that legacy manifest. Finish verifier-mediated scoped
   installation, proxy/egress setup and allow/deny canaries before claiming N05.

The authority foundation does not close any of those integration gates. Legacy
enrollment stays unchanged, the private signer cannot service it, and `.235`
[native trust checks](native-workload-trust.md) remain supporting components.
No build, test, runtime, NSM invocation, deployment or paid resource ran for this
source work. Independent production acceptance remains **0/6 verified**.
