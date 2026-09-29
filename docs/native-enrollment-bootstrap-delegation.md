# Native enrollment bootstrap delegation

Status: partial N05 source implementation, unbuilt and unexecuted. This is a
dedicated caller-to-target authorization original, not a reachable enrollment
signer, complete enrollment route or certificate-issuance grant. Production
acceptance remains **0/6 verified**.

## Separate caller and target

The [request-first target bootstrap](workload-identity-bootstrap.md) creates a
fresh local P-256 key, CSR and same-key proof of possession without requiring an
existing target certificate or enrollment packet. That proves possession only;
it does not establish SAN entitlement or authenticate a caller to the runtime.

This delegation separately binds an existing authenticated caller's intended
principal, issuer and certificate/key to that exact fresh target request. The
target does not impersonate the caller, inherit its certificate, or silently
bypass the actual current policy/full-principal/TLS checks. Caller and target
issuers may differ. Actual native admission must select the target issuer from
the retained installed DER roots and then reverify the target originals; a
certificate supplied inside an untrusted target request is not an authority.

The [existing exact-packet assignment](native-enrollment-assignment.md) remains
strictly separate and unchanged. This delegation contains no packet digest and
cannot be substituted into its private role-5 signing operation.

## Closed signed original

The [schema](../schemas/native-enrollment-bootstrap-delegation.v1.schema.json)
has exactly three envelope fields: `apiVersion`, `delegation` and
`signatureBase64url`. Its exactly 32 payload fields bind:

- Dedicated authorizer identity, nonzero delegation ID and fixed bootstrap purpose.
- Runtime release, policy, configuration, runtime CA DER/SPKI, ingress leaf and
  existing native ordered framed-DER client-root-set commitment.
- Caller principal, issuer DER/SPKI, client leaf DER/SPKI, ingress host, server
  instance, independently pinned public TCP endpoint and nonzero session challenge.
- Target principal, nonce, exact request/CSR/SPKI digests, requested DNS/URI SANs,
  independent target issuer DER/SPKI and exact original target request interval.
- An independently signed current delegation interval, at most 300 seconds and
  wholly contained in the target request's exact millisecond interval.

The signature preimage is:

```text
"serverware/native-enrollment-bootstrap-delegation/v1\0"
    || canonical compact sorted JSON(delegation), without LF
```

Canonical JSON uses the existing Python `ensure_ascii=True` representation:
non-ASCII Unicode uses lowercase `\uXXXX` escapes and supplementary characters
use surrogate pairs; slash is not escaped. UTF-8 target identities are preserved
semantically, not replaced by an ASCII-only principal rule. The payload is at
most 32 KiB; the complete envelope is at most 32 KiB **including exactly one LF**.
The outer object, payload, SAN object and SAN arrays require a maximum depth of
four. Alternative escaping, whitespace, duplicate or unknown fields and extra
LFs are rejected. Signature is canonical unpadded base64url of raw Ed25519 bytes.

Caller principal keeps the existing non-whitespace printable-ASCII 1–256 profile.
Target principal keeps the request-first profile's 1–1024 UTF-8-byte limit; its
nonce keeps `[A-Za-z0-9_-]{32,256}`. Target SAN lists are strictly sorted and unique,
with 1–8 combined entries and at most 8 KiB aggregate UTF-8 bytes, using the same
DNS/URI and exact CSR rules as the original target request. These are signed
requested identities, not an observation of live runtime policy.

The public authorizer is a canonical Ed25519 SPKI PEM, at most 16 KiB, accompanied
by a separately supplied SHA-256 pin over those exact PEM bytes. Payload
`authorizerKeyId` instead hashes DER SPKI. This new profile excludes that actual
key from the runtime CA, caller issuer/client and target issuer/key SPKI pins.
Python also joins the target issuer and target key to their genuine originals.
Actual current policy/response-key separation remains the cold owner's duty;
signed pins do not prove those runtime keys were observed.

## Producer, receiver and retained bounds

The [Python module](../serverware/native_enrollment_bootstrap_delegation.py)
provides `_produce_on_work` and `_verify_on_work`. Both require actual target
request bytes (at most 64 KiB), separately selected issuer PEM bytes (at most
64 KiB), dedicated public-key original/pin, and the inherited work, live window
and transport deadline. Production additionally takes exact canonical payload
bytes and a matching canonical unencrypted Ed25519 PKCS8 original. No file/key
lookup, generated authorization key, private-key output or environment fallback
is added. The explicit producer never fills in a missing digest, changes an
expiry or substitutes target identity fields before signing.

Both Python paths reverify the genuine .239 CSR and same-key request signature,
the actual issuer profile, every target digest and exact target identity/SAN/time
association. Previously returned verification material is not an input authority.
The producer verifies its complete signed output again before returning original
bytes. The paired Rust delegation owner authenticates the signed original and exact request hash;
its separate target-original verifier and native admission must supply the actual
CSR/PoP/issuer and live caller/runtime checks, not a copied success object.

Predecode capacity uses the unchanged 64 MiB inherited ceiling, including held
caller reservation, bounded originals/decoded representations and production
output reserve. The same real-clock processing window is at most 30 seconds and
can only narrow. Target and delegation remain within their original issuer and
request lifetimes; second-based delegation endpoints must fit inside the exact
millisecond target interval without outward rounding. Reverification cannot
renew any allowance. The returned live check retains the same budget and is a
sibling check, never installed as that budget's own callback.

## Source-connected private admission

The [private native admission module](../data-plane/decision-gate-rs/src/native_enrollment_bootstrap_admission.rs)
now joins the delegation to the actual current snapshot and full caller
principal, retained native runtime/TLS configuration, original session challenge
and exporter, and actual accepted listener. The caller authenticates with its
existing certificate and complete policy requirements; the fresh target does not
replace that caller identity.

The distinct target check requires the exact configured target principal to
exist and genuinely verifies its original request, CSR and same-key proof of
possession. Its issuer is independently selected from the actual generated
ingress's installed native DER roots and may differ from the caller issuer.
The request cannot install an arbitrary CA. This is not prospective target
packet or issued-leaf selector admission: merely finding the configured target
does not establish those later semantics. No request route or private signer is
enabled by this borrowed admission owner.

## Still required

The signed original is not proof that its caller is currently authenticated or
that runtime policy admits all caller and target constraints. Those checks must
use the retained actual TLS/configuration/runtime owners, not this material as
permission. Native vsock's public TCP endpoint remains a cold pin, and a vsock
CID cannot become a client IP.

Supported packet semantics and reconstruction, durable one-use delegation and
packet claims/recovery, actual request acquisition/serving, separately authorized
issuer grant/issuance, versioned SDK packet admission and verifier-mediated trust
installation remain required. No private enrollment signer is enabled here, and
no first certificate, enrollment completion, deployment or pilot is claimed.
Dependency-source work resolved ten new Cargo lock entries while preserving
existing versions/checksums and downloaded/read three checksum-matched RustCrypto
sources for API compatibility. That is not build or runtime verification. No
tests, builds, application execution, NSM calls, application network operations
or provisioning ran; deployment and pilot acceptance remain absent.
