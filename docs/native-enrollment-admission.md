# Native enrollment cold authority and policy/TLS admission

Status: partial N05 source implementation, unbuilt and unexecuted. This increment
adds explicit public authorizer configuration and a fixed internal admission gate
using the actual policy and native server TLS owners. **It does not enable the
native signer, add an enrollment request route, construct an approved packet, or
create a durable one-use claim.** The [original-evidence receiver](native-enrollment-verification.md)
remains diagnostic only. Production acceptance remains **0/6 verified**.

## Additive cold configuration, separate key role

`serverware.nativeStartupConfiguration/v2` retains the existing startup fields
and requires two additional top-level members:

- `enrollmentAuthorizer`, the [closed three-field public object](../schemas/native-enrollment-authorizer.v1.schema.json).
- `enrollmentProxyEndpoint`, a canonical literal unicast socket address with a
  nonzero port, independently pinned by the original startup configuration.

Startup v1 is unchanged and rejects both additions; absent enrollment authority
does not fall back to a control-plane response or policy key. The authorizer
object is exactly:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `serverware.nativeEnrollmentAuthorizer/v1` |
| `publicKeyPem` | Exact canonical public Ed25519 SPKI PEM original, at most 16 KiB |
| `publicKeyPemSha256` | Independent canonical nonzero SHA-256 pin of those exact PEM bytes |

Runtime parses and re-encodes the PEM, requires exact bytes and matching pin,
rejects weak keys, and excludes the actual control-plane response key and policy
signing key. The policy-key join is repeated against the genuinely admitted
`Snapshot` before the authorizer owner is attached. The pin is not the assignment's
DER-SPKI `authorizerKeyId`; both identities retain their own byte domains.

Only public material is carried here. There is no private-key input, key file,
environment lookup, generated fallback, or extension of role-4 response-signing
authority. The existing enclosing startup-original bounds still apply; the
16 KiB key cap does not enlarge the startup profile's allowance.

The original startup configuration is independently pinned. Matching that pin
establishes which bytes were used, not who authorized their deployment or how an
operator admitted the authorizer. Independent administration and release/trust
delivery remain prerequisites; this source path does not turn an unsigned local
configuration into signed or hardware-backed configuration admission.

## The assignment is per request, not static configuration

The [signed assignment](native-enrollment-assignment.md) binds the configuration
digest, runtime-generated CA/ingress identities, exact packet bytes and a fresh
client challenge. Embedding it inside the static configuration whose hash it
names would create a hash cycle and cannot supply the later generated identities
or request challenge. Neither startup version accepts a per-request assignment
as part of this public-authorizer object.

Future acquisition must supply the original signed assignment and exact packet
to the fixed gate. The assignment cannot choose its own authorizer or replace
the original configuration, current policy or actual TLS owner with a copied
verification result.

## Actual policy and connection admission

The internal admission path uses the retained public-authorizer owner, actual
current `Snapshot` and complete `Principal`, original request head, actual native
server TLS stream and retained authenticated mTLS evidence. It verifies original
assignment/packet bytes and joins the principal's full configured mTLS selectors,
not just a principal name or a caller-provided policy digest. Current policy and
the real policy verifying key remain part of admission and revalidation.

The existing handshake constructs a retained stream wrapper holding the exact
ingress-configuration `Arc` used for that connection. The gate uses that
connection-owned configuration; a later caller-supplied configuration DTO or an
equal-looking replacement cannot establish the connection's trust-store origin.

The challenge is taken from the canonical nonzero request value; the exporter
and client certificate evidence come from the actual retained TLS owner. A posted
root, exporter or authority flag cannot supply those facts. Revalidation preserves
the original client-certificate and assignment intervals rather than creating a
fresh allowance. This is a source-bound internal gate, not a successful DTO that
a request can deserialize or reuse as signing permission.

The native listener is **vsock**, not the client-visible TCP listener. Therefore
`enrollmentProxyEndpoint` is an independent cold **pin**, and the assignment must
match that retained pin. The actual accepted vsock local port is separately
checked against the existing `native.listenerPort` retained from startup; it is
not the public TCP endpoint. The native runtime does not claim to observe the public
TCP endpoint, map a vsock CID into a client IP, or prove the parent relay's public
routing configuration. The client-side receiver separately compares its own
actual TCP `peer_addr()` to the assignment. These are distinct checks, not an
invented server-side observation.

## Still required before signing or installation

The source admission path does not interpret or reconstruct the full packet.
Actual supported packet semantics must preserve policy/principal selectors,
runtime-scoped CA, routes, transport, egress and safe canary obligations. Exact
packet hashing is not approval of posted shell commands or installation paths.

Durable claim-before-sign, exact retained outcomes and interruption recovery are
still required. Unknown outcomes cannot authorize another signature, new key or
fresh nonce. The request/serving and client acquisition owners must connect the
gate without weakening its original lifetime or TLS/configuration provenance.
The role-5 signer stays private and inaccessible until those missing producer
gates are genuinely connected.

Explicit packet/SDK/issuer integration, verifier-mediated scoped CA installation,
proxy/egress setup, allow/deny canaries and deployment of independently admitted
trust remain open. Legacy startup v1, Python enrollment and role-4 signing retain
their previous boundaries.

### Existing identity is not first-time bootstrap

The `.238` gate admits an existing authenticated identity. It can consume a
genuinely externally provisioned certificate/key, but does not ship that PKI's
first-time issuance or delivery contract. The current issuer accepts only signed
`agentEnrollment/v1` packets; legacy packet-bound CSR preparation requires such a
packet. The new [request-first local bootstrap profile](workload-identity-bootstrap.md)
prepares target key/CSR possession without that prerequisite, but adds no
authenticated caller, delegation or issuance authority. The legacy operator
enrollment route's attestation helper refuses production; it is not a fallback.

Complete N05 therefore requires explicit bootstrap-versus-target semantics:
an independently authorized bootstrap caller/principal, an original target
issuance grant and genuine target CSR/key-possession proof. The target must not
already need its first Serverware certificate to obtain that certificate.
Existing v1 target-mTLS checks and the meaning of `runtimeManifestDigest` stay
unchanged; no legacy downgrade or weaker selector fallback resolves this gap.
This is remaining work inside N05, not a new parent or implementation credit.

Future consolidated verification must cover v1 rejection of additions, missing
or extra v2 fields, malformed/weak/wrong-role keys, pin mismatch, changed policy or
principal selectors, TLS/client/challenge/endpoint mismatch, original expiry,
and interruption before irreversible signing. These are required future checks,
not executed results. No tests, builds, interpreter/parser execution, runtime,
browser, NSM, AWS or paid-resource actions were used for this source increment.
