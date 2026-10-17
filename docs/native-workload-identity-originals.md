# Native request-first issuer originals

Status: partial source implementation, unbuilt and unexecuted. This server-side
profile does not issue a certificate or create authority by itself. The separate
native issuer grant supplies independent issuance approval over exact originals.
Legacy signed-packet/request v1 admission is unchanged.

[`native_workload_identity_originals.py`](../catchplate/native_workload_identity_originals.py)
accepts the exact seven-field native packet-v2 original, separately supplied
target request, actual cold issuer PEM, independently pinned delegation/setup
public-key PEM originals, independent expected target principal/nonce/SANs, and
the caller's existing work/window/deadline/current guard. It accepts neither a
role3/role5 evidence envelope nor a CLI verification diagnostic.

It extracts public originals only, genuinely verifies both independent
signatures and the request-first P256 CSR/PoP, requires the packet's request
bytes to equal the separately supplied original, and compares the packet's
issuer DER byte-for-byte with the certificate parsed from the independent PEM.
The returned issuer PEM digest and request's issuer DER/SPKI digests remain
separate. No `packetSigningKey` or `runtimeManifestDigest` alias is invented.
Setup admission reuses its genuine same-call delegation, not an external
successful-result input. Grant admission compares the resulting native scope
to the separately authenticated cold scope.

## Complete public requirements, certificate-only compatibility

The [requirements schema](../schemas/native-enrollment-policy-requirements.v1.schema.json)
describes the actual Rust `native_enrollment_policy_requirements::project`
output: canonical compact sorted ASCII JSON without LF, at most64 KiB and128
complete entitled routes. Policy metadata, public route facts and all exact
component commitments remain present. Arbitrary adapter/constraint/JIT values,
header values and proxy-authorization secrets are not exposed. Shape checking
does not reconstruct those hidden values or prove a current Snapshot.

The native issuer joins the signed requirements' policy hash and target ID to
the genuine delegation/request. It keeps all six mTLS projection fields:
`sanSpiffeIds`, `sanDnsNames`, `sanUris`, `certificateSha256`, `spkiSha256` and
`issuerSpkiSha256`. Empty arrays/null hashes mean no constraint; nothing else is
silently dropped. Each nonempty SAN category must intersect the prospective
certificate category (AND across categories, OR within each), matching runtime
selector semantics. The independently signed grant approves the exact requested
SAN inventory; SPKI-only policy is not silently turned into a SAN allowlist.

Before signing, a non-null certificate DER hash is rejected as a circular
first-issuance profile. Configured SPKI and issuer-SPKI hashes must match the
genuine CSR and issuer, and every SAN constraint must be satisfiable. Returned
leaf admission then checks the full exact emitted SAN inventory, retained CSR
key, empty subject, critical CA=false/digitalSignature constraints, clientAuth,
allowed extensions, direct issuer signature and every configured selector.
It independently checks the grant's exact serial and notBefore/notAfter, and
contains leaf validity within the original setup/delegation/request/issuer
intersection. The explicit interval helper is shared cryptography; it is not a
fabricated legacy packet binding.

This is certificate compatibility only. Inbound source CIDRs, external header
values, bearer/legacy authentication, current trusted ingress, provider request
constraints, credential references, JIT, canaries and response obligations still
require their actual runtime owners. The full identity-policy hash is retained
as a commitment, not described as proof that these requirements were met.
The certificate-selector commitment hashes the canonical **six-field mTLS
projection**, including nulls and original array order, not the complete hidden
identity policy and not a synthesized authenticated-ingress record.

## Bounds and receiving APIs

`_verify_on_work` returns private original facts and genuine same-call
delegation/setup/request children. `_verify_certificate_on_work` takes those
same raw inputs plus the returned leaf original and independently expected
serial/notBefore/notAfter; it re-admits all originals rather than accepting the
first result. Both return original signed interval bounds and a live guard.
No result grants signing, installation, policy or network permission.

Packet/request/issuer/leaf limits are512/64/64/64 KiB. Before decoding, the native
lane reserves caller-held bytes plus24 times actual packet bytes,16 times the
other actual request/issuer/key/optional-leaf originals, and512 KiB. The existing
nested setup preflight additionally accounts for retained outer originals. All
checks use the same64 MiB ledger and its actual remaining work; no fresh budget,
clock allowance or automatic retry is created. Original issuer, request,
delegation, setup and leaf validity remains live through the returned guard.

Runtime tests, issued-leaf interoperability, request-first SDK publication under
the retained local private key, deployment, rotation/revocation and complete
workload authentication remain open. Source/schema readback is not execution
evidence or production acceptance.
