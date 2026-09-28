# Native enrollment original-evidence verification

Status: partial N05 source implementation, unbuilt and unexecuted. This receiver
authenticates original evidence on an already retained TLS connection. It adds
**no enrollment endpoint, acquisition flow, CLI, enabled native signer or
installation authority**. The [role-5 signer foundation](native-enrollment-assignment.md)
remains dormant, module-private and uncalled. Production acceptance remains
**0/6 verified**; no tested pilot or completed enrollment is claimed.

## Closed original wire

The [evidence schema](../schemas/native-enrollment-evidence.v1.schema.json) has
exactly nine fields. Its fixed `apiVersion` is
`serverware.nativeEnrollmentEvidence/v1`, `evidenceScope` is
`unverified-enrollment-public-material`, and `okForAction` is `false`.

| Original field | Decoded bound and meaning |
| --- | --- |
| `assignmentBase64url` | 1–16,384 bytes: exact signed assignment, including LF |
| `packetBase64url` | 1–524,288 bytes: exact unsigned packet bytes |
| `ingressSessionEvidenceBase64url` | 1–98,304 bytes: exact paired-v2 ingress session evidence, including LF |
| `enrollmentSignatureBase64url` | Exactly 64 raw Ed25519 signature bytes |
| `enrollmentPublicKeyBase64url` | Exactly 32 raw Ed25519 key bytes, not all zero |
| `enrollmentQuoteBase64url` | 1–12,288 bytes: original role-5 Nitro COSE evidence |

Every wrapper uses canonical unpadded base64url. The complete original is
canonical compact sorted UTF-8 JSON plus exactly one LF, at most 1 MiB. Closed
fields, duplicate rejection, canonical spelling and decoded bounds are runtime
requirements; JSON Schema alone does not authenticate or decode the originals.
These caps do not enlarge the nested 64 KiB public-identity or 96 KiB ingress
session limits. Oversized evidence is refused, never truncated or downgraded.

## Independent inputs and the actual connection

The crate-private [`native_verifier::verify_native_enrollment_on_stream` wrapper](../data-plane/decision-gate-rs/src/native_verifier/mod.rs)
borrows the actual `rustls::StreamOwned<ClientConnection, TcpStream>`. It obtains
the connected endpoint from that stream's real `sock.peer_addr()`, not from the
assignment, a posted endpoint or a diagnostic result. No new socket, HTTP request
or private-key input is added by verification.

The caller must independently supply the native session scope, Nitro root
originals, enrollment-authorizer public PEM and its exact PEM SHA-256 pin,
expected principal and challenge, selected workload-issuer original, actual
retained client certificate chain and original deadline. Their cold provenance
and acquisition are not established by accepting this wire object. The same
connection supplies the actual TLS exporter and presented server certificates;
the caller must not replace its retained client-chain original with an echo.
The fixed acquisition owner must have configured that chain and a reviewed TLS
verifier on this stream. This wrapper cannot infer that configuration history
from public originals; the actual acquisition owner remains a required next join.

No successful verification object or serialized summary is an authority input.
The independently pinned authorizer, selected issuer, native framed-DER root
commitment and any legacy runtime-manifest digest remain distinct identities.

## Genuine joins before diagnostic output

1. Re-admit the exact independently signed assignment and hash the actual packet
   bytes. Check its principal, literal endpoint and challenge against the
   independent caller and real connection, retaining the original interval.
2. Genuinely verify paired-v2 [native ingress evidence](native-workload-trust.md):
   original Nitro COSE/PKI/PCR scope, role 3, current quote, challenge/exporter,
   server chain, ordered runtime-held client roots and selected issuer. Verify
   the retained client chain under only that issuer, with the existing 1–8-chain
   profile; a selected root in a response is not a trust choice.
3. Verify the original role-5 quote under the independent Nitro roots. Join the
   enrollment public key, runtime/release/policy/configuration, actual CA and
   ingress identity, challenge/exporter and assignment/packet/root-set request
   commitment to that same authenticated session. Role 4 is not enrollment
   authority, and a copied role-3 success summary cannot replace these originals.
4. Verify the purpose-specific signature using the genuinely quoted enrollment
   key over the fixed preimage:

   ```text
   "serverware/native-enrollment-packet-signature/v1\0"
       || SHA256(exact assignment envelope including LF)[32]
       || packet_length:u64BE || exact_packet_bytes
   ```

5. Retain the original assignment, quote/certificate, process, clock and deadline
   checks through bounded result serialization and return. For both roles 3 and
   5, this includes the earliest expiry along the actually authenticated Nitro
   signing-certificate chain, not only quote age. An unrelated pinned rollover
   root is not part of that selected-chain expiry. The assignment's signed
   interval is at most 300 seconds; its processing allowance is clipped once to
   the original caller deadline, at most 30 seconds, and original expiry.
   Verification does not renew a challenge, redraw a nonce or grant a retry.

The returned JSON is a bounded diagnostic, below 4096 bytes, with
`resultScope: "local-enrollment-signature-and-session-only"` and
`okForAction: false`. It records evidence, assignment, packet, enrollment-key,
quote and ingress-evidence digests plus the independently expected principal and
actual connected endpoint. It is not an installation receipt, signed packet
schema, runtime permission, or durable one-use outcome.

## Remaining integration and verification

The [explicit startup-v2 public authorizer and actual policy/TLS admission
gate](native-enrollment-admission.md) now supply the server-side cold input and
`Snapshot`/full-principal join in source. Independent trust deployment, per-request
assignment acquisition, full packet construction, durable claim-before-sign and
exact interruption recovery, a deliberately enabled serving/client-acquisition
path, and an explicit packet/SDK version remain required. The native server's
public TCP endpoint is a cold pin because its listener is vsock; this receiver
still uses its actual client-side TCP peer. Authenticating an exact packet digest does not
approve its routes, commands, principal selectors or installation instructions.
Verifier-mediated scoped CA installation, proxy/egress setup and allow/deny
canaries remain required. Legacy Python enrollment and role-4 signing are unchanged.

The consolidated verification batch must cover valid original chains; changed
assignment/packet/key/signature; wrong role, runtime, PCRs, issuer, principal,
endpoint, client chain, challenge or exporter; paired-version rejection;
duplicate/noncanonical fields and bounds; expiry/clock/deadline failure; and
retained-connection mismatch. These are future checks, not executed results.
No tests, build, parser/interpreter execution, runtime, browser, NSM, AWS or paid
resource actions were used for this source increment.
