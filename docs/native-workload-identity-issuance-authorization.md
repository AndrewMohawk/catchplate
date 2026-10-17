# Separate native workload issuance authorization

The native request-first issuer profile requires its own explicit signed grant.
A native packet, setup/delegation signature, CSR proof, role-5 evidence capture or
successful diagnostic is not permission to issue a certificate. The dedicated
grant authorizer directly authorizes the exact originals and certificate scope;
it does not infer permission from an enclave quote or a Python result object.

The implementation is source-only: unbuilt, unexecuted and unprovisioned. It does
not establish production acceptance, issuer key hardware custody, protected
installation, namespace ownership, recovery or egress canaries. See the
[issuer boundary](workload-identity-issuer.md), [native setup](native-enrollment-bootstrap-setup.md)
and [fixed acquisition client](native-bootstrap-client.md).

## Separate cold and grant profiles

The independently root-signed issuer bootstrap v2 selects
`native-request-first-v2` with purpose `native-workload-identity-issuance`.
Its `nativeEnrollment` object pins the native release, runtime configuration,
runtime CA DER/SPKI and separate delegation/setup public-key originals. The
issuer certificate, independent issuance authorization key, policy hash, actual
launcher/listener/CA-key/journal bindings and trusted-host-local boundary remain
explicit cold inputs. The actual cold root, issuer, issuance authorizer,
delegation authorizer and setup authorizer have distinct key roles.

Native material has no packet-signing-key bytes or legacy runtime-manifest
digest. Missing legacy fields are `None`, never invented aliases. Legacy cold
v1 and legacy grant v1 retain their schemas, signature domains and meanings;
neither packet contents nor caller-supplied profile hints select worker dispatch.
The actual authenticated cold owner alone selects the verifier.

The [new grant schema](../schemas/native-workload-identity-issuance-authorization.v1.schema.json)
is a closed three-field envelope:

- `schema`: `catchplate.signedNativeWorkloadIdentityIssuanceAuthorization/v1`;
- `payload`: exact 34-field `catchplate.nativeWorkloadIdentityIssuanceAuthorization/v1`;
- `signature`: `ed25519:` plus canonical unpadded base64url of the raw 64-byte signature.

The entire envelope is sorted compact `ensure_ascii=True` JSON, at most 32 KiB,
without a framing LF. The signed message is the payload schema's ASCII bytes,
one NUL byte, then the exact canonical payload bytes. `sourceRevision` must equal
the verifier's source-owned current authority revision. This is a new purpose
and domain, not the old native packet signature domain or old issuance grant.

| Signed association | Exact commitment |
| --- | --- |
| Authority | Cold bootstrap original, issuer cold configuration, authorization SPKI, journal namespace and explicit grant ID |
| Native scope | Release record, native runtime configuration, runtime CA DER/SPKI and policy hash |
| Native originals | Packet v2, setup, delegation and policy-requirements original hashes |
| Target policy | Complete target identity-policy commitment and canonical certificate-selector commitment |
| Target request | Exact principal, nonce, request, CSR, SPKI and selected DNS/URI SANs |
| Issuer | Exact canonical issuer PEM hash **and separately** actual issuer DER and SPKI hashes |
| Certificate | Explicit positive serial below 2^159 and exact whole-second validity |
| Original grant lifetime | Current interval of at most 300 seconds, fully contained in original setup/delegation/request/issuer/cold validity |

`configurationDigest` is the issuer's cold configuration commitment;
`runtimeConfigurationSha256` is the separate native runtime commitment. Neither
stands in for `runtimeManifestDigest`. The native packet is an exact bounded
original container, not a host-signed legacy enrollment packet.

## Original-only producer and admission APIs

The private source module
[`native_workload_identity_issuance_authorization.py`](../catchplate/native_workload_identity_issuance_authorization.py)
provides `_verify_on_work`, `_verify_certificate_on_work` and `_produce_on_work`.
The verification entrypoints receive raw grant/bootstrap/packet/request originals,
the independent cold root public key, and the caller's existing work ledger,
live window and absolute deadline. The leaf entrypoint additionally receives
the exact returned certificate original. No preverified material, runtime
diagnostic, signature verdict or role-5 capture is an authority parameter.

`_produce_on_work` is an explicit authorizer operation: it receives the exact
canonical payload and actual matching authorization private key, signs under
the separate domain, then genuinely re-admits all originals before returning
the grant. It never generates a key, selects a grant from a CSR, fills an identity
or lifetime, opens a grant service, or turns setup approval into issuer authority.

Each admission replays strict native cold v2 and the dedicated grant signature.
The native-original verifier independently replays setup and delegation under
the retained separate roots, exact packet/request association, genuine target
CSR/PoP and actual issuer. It checks the selected target certificate selectors
against the requested key, issuer and complete SAN inventory. Nonempty selector
categories are conjunctive; alternatives within a category remain alternatives.
A precommitted leaf-certificate hash is circular for first issuance and refuses
before signing. SPKI-only policy remains distinct from a requirement for SAN
intersection. Actual leaf admission subsequently repeats the original authority
checks, signature/path profile, selected predicates and exact grant serial/time.

The complete identity-policy commitment also binds hidden/non-certificate
requirements. Issuance does not pretend to evaluate target source CIDRs, external
headers, proxy credentials or canary behavior merely because their commitment
is present. Actual target authentication and operational acceptance remain
separate gates.

The target principal retains the request-first nonempty Unicode profile with
at most 1024 UTF-8 bytes; the old printable 512-byte grant rule is not silently
applied. SANs remain sorted unique canonical DNS/URI lists, 1–8 names total,
bounded by the original request and canonical grant/journal representation.

## Same worker and irreversible claim boundary

Native grants use the existing dedicated software issuer, fixed transport,
independent CA private-key owner and journal. The worker's source-selected
verifier returns `_NativeIssuanceMaterial`; it cannot be substituted for the
legacy result by relabeling an untrusted packet. The existing 17-scalar journal
association is unchanged. Its issuer-original slot remains the PEM hash used
by the builder, while the new grant carries DER separately. Principal spelling
is never a journal filename or path.

Claim still precedes certificate signing. Exact completed bytes are retained
and independently re-admitted after durable readback; an incomplete/uncertain
claim is not a retry permit. No raw transport limits, journal quota, callback
authority or fresh timeout are introduced by the native profile. Native packet
input is at most 512 KiB, request/issuer/leaf at most 64 KiB, and grant at most
32 KiB. Representation forecasts and actual work share the original 64 MiB
ledger; original processing stays at most 30 seconds and narrows through all
live authority/issuer/request/leaf intervals.

This slice connects separate grant admission to the worker's existing signing
and readback boundary. It is not a new public submission route or complete
native SDK issuance/install flow. The journal's authenticated minimum prefix
does not establish latest-state rollback resistance. Protected reservation and
installation ownership, complete target authentication, deployment/runtime
verification, recovery and full production acceptance remain open.
