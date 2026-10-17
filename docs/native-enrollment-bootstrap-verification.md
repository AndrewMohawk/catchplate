# Native bootstrap enrollment evidence receiving

Status: partial source implementation, unbuilt and unexecuted. The explicit
caller-to-target receiver is now joined to the bounded native server/fixed-client
[bootstrap exchange](native-enrollment-bootstrap-exchange.md). It adds no
certificate issuance, trust installation or production acceptance. The existing same-target
[enrollment v1 receiver](native-enrollment-verification.md) is unchanged.

## Originals and independent inputs

The [closed eight-field evidence schema](../schemas/native-enrollment-bootstrap-evidence.v1.schema.json)
uses `catchplate.nativeEnrollmentBootstrapEvidence/v1`,
`evidenceScope: "unverified-bootstrap-enrollment-public-material"` and
`okForAction: false`. It carries exact packet, paired-v2 ingress-session, raw
Ed25519 signature/key and original role5 Nitro quote bytes in canonical unpadded
base64url. The complete canonical sorted compact ASCII JSON original has exactly
one final LF and is at most 1 MiB. Nested packet/session/quote bounds are
512 KiB/96 KiB/12 KiB, including applicable LF framing; the key/signature are
exactly 32/64 raw bytes. No v1 fallback is attempted.

The shared private
[`native_enrollment_bootstrap_packet_v2::decode_original`](../data-plane/decision-gate-rs/src/native_enrollment_bootstrap_packet_v2.rs)
decodes the existing seven-field `nativeEnrollmentPacket/v2` only. Before JSON
decoding it bounds the flat shape; it then requires exact canonical bytes and
closed fields. The five original getters retain delegation/setup/target request/
target issuer DER/policy requirements, with respective caps
32/32/64/64/64 KiB. This object contains decoded bytes, not verified authority.
Consumers bracket this bounded operation with their original processing guard.

The crate-private
[`verify_native_bootstrap_enrollment_on_stream`](../data-plane/decision-gate-rs/src/native_verifier/mod.rs)
requires both independently selected public-key PEM originals and exact PEM
SHA256 pins (delegation and setup), original native session scope and Nitro roots,
a nonzero challenge, the actual retained `StreamOwned<ClientConnection,TcpStream>`,
the actual configured caller issuer and client-chain originals, independently
expected caller principal, target principal/nonce/request SHA256, and the original
absolute deadline. The connected public endpoint comes from that same socket's
`peer_addr()`, not a response field. The independent target request digest must
come from the retained request-first preparation, not this packet.

The acquisition owner must preserve the reviewed TLS configuration and actual
selected caller certificate/private-key provenance. A `ClientConnection` cannot
prove that its configuration used a reviewed server verifier or that a supplied
client-chain copy was selected for the handshake. This function neither acquires
a connection nor creates that provenance. Python packet diagnostics and prior
successful verifier outputs are never authority inputs.

## Caller and target are different identities

The existing full TLS1.3 session, client certificate chain and role3 verification
belong to the bootstrap caller. They are joined to the delegation's `caller*`
fields and the independently expected caller principal. The role3 original
authenticates the runtime/release/policy/configuration, actual server leaf/CA,
ordered native DER-root commitment, challenge and actual TLS exporter. Root
expectations, quote age/skew and host/instance remain independently supplied.

The target does not need a certificate. Its issuer DER must occur exactly once
in that same authenticated root inventory. The original target verifier then
checks the independently expected request digest, principal and nonce, genuine
P256 CSR and same-key proof of possession, exact delegated SANs and CSR/SPKI/issuer
digests, and original target/issuer validity. Its direct-CA profile and normalized
target-key versus raw issuer-SPKI commitments remain those of the request-first
verifier. Membership does not itself authorize CA issuance.

The original setup signature is verified under the separate setup root. Its
verifier genuinely re-admits and retains the original delegation; the receiver
uses this same-call child, not a copied success object. The setup binds the exact
policy-requirements bytes and deployment scope to that delegation and target.
Requirements remain data: their hashes do not approve provider operations,
canaries, installation commands, or target authentication.

## Separate role5 bootstrap binding

The bootstrap signature preimage is:

```text
"catchplate/native-enrollment-bootstrap-packet-signature/v1\0"
    || SHA256(exact delegation original)[32]
    || SHA256(exact setup original)[32]
    || packet_length:u64BE || exact_packet_bytes
```

The role5 request commitment is:

```text
SHA256("catchplate/native-enrollment-bootstrap-key-binding/v1\0"
    || delegation_sha256[32] || setup_sha256[32] || packet_sha256[32]
    || actual_ingress_leaf_sha256[32] || native_client_root_set_sha256[32])
```

The existing runtime key-binding frame and role byte `5` are unchanged. It binds
the genuine runtime/release/policy/configuration and actual runtime CA DER/SPKI,
the SHA256 of the raw enrollment key, and this new request commitment. The quote
nonce still comes from the independent challenge and actual held TLS exporter.
Old assignment/signature domains, role4 keys and a standard listener PEM-bundle
digest cannot substitute for this profile.

One original processing bound begins before evidence decoding and is clipped to
the caller's deadline and at most 30 seconds. Delegation/setup/request owners,
role3 session and the actually selected role3/role5 Nitro certificate chains keep
their original validity; the target and caller certificate bounds are not
renewed. Process changes, backwards clocks and expiry fail closed. Final checks
run after bounded diagnostic serialization, including role5 quote freshness and
selected signing-chain expiry.

The result is below 4096 bytes with
`resultScope: "local-bootstrap-signature-and-session-only"` and
`okForAction: false`. It records original digests, expected caller, a hash of the
expected target principal, target nonce and actual connected endpoint. It is not
a durable outcome or permission. Independent pin deployment, deployed exchange
verification, scoped installation and runtime evidence
remain separately required. No legacy `runtimeManifestDigest` is invented.

## Private producer and journal composition

[`PreparedNativeBootstrapPacket::sign_once`](../data-plane/decision-gate-rs/src/native_enrollment_bootstrap_admission.rs)
consumes the actual prepared owner, not uploaded packet bytes or a diagnostic.
Its policy read guard retains the same Snapshot Arc/epoch through signing; the
trust window must cover the original operation. The original TLS connection,
generated ingress owner, runtime identity, dedicated public roots and deadlines
remain joined. Full admission is checked again after releasing the locks; a
failure withholds output and never resets a durable claim.

[`CustodySignerTransport::sign_native_bootstrap_enrollment`](../data-plane/decision-gate-rs/src/native_proof_signer.rs)
accepts only its native variant and passes the actual retained custody runtime
to the identity-owned operation. It does not create a second ledger or use the
Unix transport as an alternative authority. The library operation must genuinely
re-admit originals, then claim before any key generation, signature or NSM call.

The private [`native_bootstrap_attempt_v1::begin`](../data-plane/decision-gate-rs/src/native_bootstrap_attempt_v1.rs)
uses that runtime's existing locked attempt ledger. Its slot binds the setup
authorizer and setup ID to the exact operation digest and original retention
expiry. `BootstrapAttempt::New` owns the claim through the operation;
`NativeBootstrapClaim::complete` accepts only the private generated-output type,
publishes it, and returns exact signature/key/quote originals after durable
readback and equality checks. `BootstrapAttempt::Complete` returns only those
retained public originals, never another signing capability.

An existing claim without completion is burned while retained:
`native_bootstrap_outcome_unknown` forbids another signing attempt, including
after restart. A completed record supports exact same-operation readback only;
changed association or expiry is refused. This is not cross-session recovery:
the receiver still requires its actual TLS exporter/challenge, original packet,
independent pins and current original lifetimes. A future recovery profile for a
different connection needs separate explicit authority; it cannot renew this
quote or reinterpret a lost reply as no signature.

The journal inherits local filesystem custody, its manifest and fail-closed
interrupted-update behavior. It is not an off-host latest-state witness or proof
against hostile-host rollback. The private `sign_once` operation still returns
only public signing originals. The consuming `deliver_once` path now retains the
actual mutable TLS stream, completes that claimed signing/readback first, then
obtains the role3 v2 session quote on the same stream and challenge under the
original Snapshot/trust/runtime guards. It assembles the existing eight-field
evidence and checks original admission around bounded writes, flush and TLS
`close_notify`. A quotation or delivery failure never resets the claim or
resigns. The single processing clock starts before TLS/HTTP intake, includes
prefetched bytes, and can only tighten through the final send. This is public
evidence delivery, not a certificate issuance result, scoped installer result or
completed enrollment.

Consolidated tests remain unexecuted: positive original chains, changed caller
versus target, another TLS exporter/endpoint, missing or repeated target root,
changed nested originals/pins/domains, malformed packet framing/caps, genuine
CSR/PoP negatives, and expiry during final role5 processing and serialization.
