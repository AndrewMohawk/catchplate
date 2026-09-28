# Offline native ingress evidence verifier

Status: source-only, unbuilt and unexecuted.
[`serverware-native-ingress-verifier`](../data-plane/decision-gate-rs/src/bin/serverware-native-ingress-verifier.rs)
checks the [startup public identity original](native-public-identity.md) against
independently pinned expectations and Nitro trust roots. It verifies actual
certificate and original Nitro signatures, not just matching digests. It does
not connect to a server, install a CA, establish readiness or authorize an action.

The offline startup CLI remains strict v1. The separate
[native workload-trust session profile](native-workload-trust.md) adds genuine
verification of v2 session root-inventory originals and an independently pinned
issuer/client chain on an actual TLS connection. It does not reinterpret startup
evidence, expand this CLI, or turn its JSON output into enrollment authority.

## Fixed inputs and CLI

```text
serverware-native-ingress-verifier \
  --expectations /approved/ingress-expectations.json \
  --expectations-sha256 sha256:<exact-expectations-original-digest> \
  --trust-roots /approved/native-trust-roots.json \
  --trust-roots-sha256 sha256:<exact-trust-original-digest>
```

These are placeholders, not an admitted configuration. All four options are
required exactly once, with no defaults, extra arguments, shell or environment
selection. Stdin is the exact public-evidence JSON line, including its one
final LF, at most 65,536 bytes; interior literal CR/LF is rejected. Strict JSON
rejects duplicate/unknown fields and unsupported numeric forms. Member order
and otherwise permitted JSON whitespace need not be canonical: the reported
evidence digest binds the exact input bytes. Original signed COSE bytes are
never normalized or reserialized for verification.

The bounded stdin reader waits for **EOF**, while the gate continues serving
after emitting its identity line. A direct pipe from long-lived gate stdout
will not complete on that line alone. The caller must capture exactly one
complete bounded line as a separate original, reject missing LF, partial or
extra lines, then provide that original on closed stdin. Bound capture and
verification with an external deadline/watchdog, and reject a failed verifier
exit even if some output was written. The captured line still proves no gate
readiness or eventual startup success.

The [shared CLI reader](../data-plane/decision-gate-rs/src/native_verifier/cli.rs)
requires bounded, nonempty regular originals at absolute paths, rejects a
symlink at the **final** component, checks the exact SHA-256 pins before
parsing, and retains their file descriptors. Expectations are at most 16 KiB;
trust roots at most 1 MiB. Held bytes/hash/metadata and named identity are
rechecked before result publication. This is not component-by-component
no-follow traversal, hostile-host immutability or independent pin provenance.
No successful output precedes those checks. Success is compact JSON of at most
4,095 bytes plus one LF; errors have fixed diagnostics.

## Independently supplied expectation and trust originals

The [closed expectation schema](../schemas/native-ingress-attestation-expectations.v1.schema.json)
has exactly thirteen required fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressAttestationExpectations/v1` |
| `releaseRecordSha256`, `policyHash`, `configurationSha256` | Independent nonzero scope commitments. |
| `clientTrustBundleSha256` | Independent framed installed-client-root commitment. |
| `expectedPcrs` | Complete expected PCR inventory, 3–32 canonical indices in 0–31, including nonzero PCR0/1/2. |
| `expectedEif` | Exact independent EIF/PCR0 commitment. |
| `expectedModuleId` | Exact bounded ASCII Nitro module identity. |
| `maxAgeSeconds`, `futureSkewSeconds` | Quote age 1–300 seconds and allowed future skew 0–30 seconds. |
| `nonceBase64url` | Independently supplied nonzero raw 32-byte startup challenge, canonical URL-safe base64 without padding. |
| `ingressHost` | Canonical lowercase letter/digit/hyphen DNS labels or literal IP, without wildcard/trailing-dot aliases. |
| `serverInstanceId` | Exact bounded canonical SPIFFE URI expected in the leaf. |

All additional locked PCRs must match; zero reserved PCR values are permitted
only when explicitly included in that independent inventory. Schema shape
alone does not perform the actual canonical-host, SPIFFE, EIF or signature joins.

Trust uses the existing closed `serverware.nativeResponseAttestationTrustRoots/v1`
format and fixed `aws-nitro-attestation-pki-native-v1` profile described in the
[native verifier guide](native-verifier.md). It requires independently pinned
root DERs and an empty CRL inventory. Vendor CRL revocation is not proved;
current root/release/application revocation remains separate. Expected trust,
release, policy, configuration, client-root, host, instance and nonce values
are never adopted from the presented evidence.

## Certificate and role-3 joins

The [certificate helper](../data-plane/decision-gate-rs/src/native_verifier/ingress_certificates.rs)
accepts exactly the generated two-certificate profile from
[`TlsAuthorityV1`](../data-plane/decision-gate-rs/src/tls_authority_v1.rs), not
an arbitrary PKI chain. Each original DER is 1–16 KiB with no trailing bytes.
Both keys must be distinct uncompressed P-256 SPKIs, each at most 1,024 bytes;
ring verifies the leaf's ECDSA/SHA-256 signature and the CA self-signature with
matching issuer/subject and signature identifiers.

The CA has critical certificate/CRL-signing KeyUsage, critical CA constraints
with path length zero, and the expected subject-key identifier. The leaf has
only digital-signature/key-encipherment KeyUsage, serverAuth EKU, its CA's
authority-key identifier, and exactly the expected host SAN followed by the
exact SPIFFE URI SAN. Every extra or duplicate extension, wrong criticality,
other SAN, algorithm or unhandled constraint is rejected. Both certificates
must be live; the positive CA interval is at most 24 hours and the leaf interval
must be contained within it.

The locked rcgen 0.13.2 default generates
[P-256/SHA-256 keys](https://github.com/rustls/rcgen/blob/v0.13.2/rcgen/src/key_pair.rs#L69-L72).
Its default leaf `IsCa::NoCa` [omits BasicConstraints and SKI](https://github.com/rustls/rcgen/blob/v0.13.2/rcgen/src/certificate.rs#L724-L778);
the verifier requires that absence rather than demanding `CA=false`. Its
[key identifiers](https://github.com/rustls/rcgen/blob/v0.13.2/rcgen/src/lib.rs#L473-L498)
use the first 20 bytes of SHA-256 over original issuer SPKI. These are
producer-specific compatibility choices, not a general X.509 acceptance policy.

The [composition](../data-plane/decision-gate-rs/src/native_verifier/ingress.rs)
joins the declared and quoted SPKI to the actual leaf, reconstructs the exact
role-3 binary user data from independent scope plus actual CA/leaf originals,
and checks the fixed TLS-1.3/mandatory-client-auth commitment. The shared
Nitro verifier authenticates the original COSE/PKI signature, complete PCR map,
module, key, nonce, user data and age under its existing fixed native profile.
This proves the signed commitment, not that a live endpoint is enforcing it.

## Local result, not enrollment or session authority

The result is `serverware.nativeIngressAttestationVerification/v1`, with
`resultScope=local-ingress-quote-only` and `okForAction=false`. It carries exact
evidence/expectation/trust-original SHA-256s, scope/client-trust digests, CA and
leaf certificate/SPKI digests, original Nitro-document digest, nonce,
`quoteIssuedAtUnixSeconds` and `verifiedAtUnixSeconds`. The latter is the opening
local wall-clock sample used for verification. A closing sample additionally
rejects clock reversal, leaf expiry and excessive quote age; neither sample is
trusted-time or rollback evidence.

The challenge is still the supplied **startup** nonce. This program neither
delivers/reserves a fresh client challenge nor observes a TLS handshake,
exporter, live peer possession, HTTP response, mTLS enforcement or readiness.
It does not supply release/configuration admission, current witness/CAS state,
one-use consumption, KMS Recipient custody or verifier-mediated CA installation.
The [public-identity enrollment boundary](native-public-identity.md#verification-and-enrollment-remain-separate)
and all production acceptance gates remain unchanged. A successful local
verification result is not a transferable action or CA-installation token.

The separate [session verification API](native-ingress-session.md#actual-client-verification-api)
accepts an actual completed outer `rustls::ClientConnection` and requires the
fresh session scope. There, `nonceBase64url` is the raw caller challenge and
the quote nonce is derived from the actual exporter; this startup CLI keeps
its original quote-nonce meaning. No standalone session CLI or automatic
network bootstrap client is supplied by that API.

## Packaging and deferred validation

The existing pinned offline Alpine build in
[Dockerfile.production](../data-plane/decision-gate-rs/Dockerfile.production)
adds this autobin without new dependencies, downloads or an entrypoint switch. Its
recipe requires no ELF interpreter/dynamic `NEEDED` entries and at most 64 MiB.
`native-ingress-verifier-artifact` exports `/serverware-native-ingress-verifier`;
the runtime path is `/usr/local/libexec/serverware-native-ingress-verifier`,
root-owned and mode 0555. This recipe has not been built or independently admitted.

Frozen validation still needs genuine generated CA/leaf and original Nitro
positives, DNS/IP and exact-instance cases, all signature/key/extension/SAN/time
and independently pinned scope/nonce/PCR negatives, malformed/duplicate JSON or
CBOR, file drift and output failure, and exact static-artifact verification.
No tests, runtime probes, imports, builds or deployments were performed here.
