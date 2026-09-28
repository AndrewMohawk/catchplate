# Local workload identity preparation and admission

N04 is **in progress**, not source-landed or production-verified. The local
[provisioning module](../serverware_agent_trust/workload_identity_provisioning.py)
and [enrollment CLI](../serverware_agent_trust/enrollment.py) prepare a
packet-bound key/CSR/request and admit an independently issued certificate.
They do not contact an issuer, create a CA, install system trust or authenticate
a proxy channel. No execution or deployed identity is claimed here.

## Independently pinned inputs

Both operations require `PinnedFile` path/SHA-256 pairs for the original signed
workload packet, its independently supplied signing public key and the issuing
CA certificate, plus the expected principal and nonce. Packet signature,
original-file identity, live expiry and any issuer-SPKI constraint are checked.
The reply cannot choose its issuer or packet-signing trust.

The initial profile permits fresh local P-256 keys and SAN authorization only.
Preparation rejects packet constraints selecting an existing certificate hash
or SPKI hash; those cannot authorize a newly generated key. Selected DNS names
and URIs must satisfy the signed packet's selectors, with at most eight SANs
and 8 KiB combined. Each list is sorted; exact certificate order is DNS then
URI. A permitted SPIFFE URI is an identity string, not a SPIFFE issuance service.

## Local APIs and files

`prepare_identity(packet=..., packet_signing_key=..., issuer=...,
expected_principal=..., expected_nonce=..., selected_sans={"dnsNames": [...],
"uris": [...]}, output_directory=..., timeout_ms=30000)` returns
`PreparedIdentity(request, csr, private_key)` containing file pins only.

The existing output directory must be owned by the current user and mode 0700.
Preparation publishes a sticky `preparation.claim` before generating the key,
then `private-key.pem`, standard `request.pem` CSR and signed `request.json`.
The request uses `serverware.signedWorkloadIdentityRequest/v1`; its same-key,
domain-separated signature binds the original packet, issuer, principal/nonce,
selected SANs, CSR and public key. It proves possession, not issuance authority.
There is no custom CSR OID carrying a replacement authorization.

`admit_certificate` takes the same common arguments plus pinned `request`,
`private_key` and single-leaf `certificate` originals, not replacement SANs.
It authenticates the retained request, direct issuer signature and exact key
match. The leaf must have an empty subject, exact requested SANs, client-auth
EKU and the fixed key-usage/basic-constraints profile; its entire validity must
fit both packet and issuer intervals. Unsupported extensions and issuer
NameConstraints fail closed. Only one directly issuing CA is supported, with
Ed25519, P-256/P-384 or 3072–4096-bit RSA keys; there is no path-building fallback.

Successful admission publishes `client-certificate.pem` as leaf followed by
issuer and returns `ProvisionedIdentity(client_certificate, client_private_key)`.
Those pins fit the unchanged `WorkloadProxyClient.from_signed_handoff`
interface; they are not proof that any TLS connection succeeded.

Files are mode 0600, exclusively published without overwrite, fsynced and
checked against retained descriptors/names and final readback. Partial files
and the preparation claim remain on uncertainty; do not retry preparation in
that directory. Keys are local software-held PKCS#8, not HSM custody or a
memory-erasure guarantee. Public key/request/certificate inputs are bounded at
64 KiB, CSR at 16 KiB and the retained private-key original at 1 KiB; the signed
packet keeps its existing 8 MiB limit and the published chain its 64 KiB limit.
The processing timeout only tightens packet expiry. Blocking native operations
still need an external watchdog; these source bounds are not an RSS guarantee.

## Explicit CLI modes

The existing `serverware-enrollment` entry point adds two mutually exclusive
local modes; neither falls through into ordinary enrollment networking:

- `--prepare-workload-identity`, with repeatable `--workload-san-dns` and
  `--workload-san-uri` selectors.
- `--admit-workload-certificate`, with `--workload-request`,
  `--workload-private-key`, `--workload-certificate` and each corresponding
  `-sha256` flag. Admission rejects separately entered SANs.

Both require `--workload-packet`, `--workload-packet-signing-key`,
`--workload-issuer` and each corresponding `-sha256` flag,
`--expected-principal`, `--expected-nonce` and `--workload-output-directory`.
`--workload-timeout-ms` defaults to 30000. Network, receipt and ordinary
enrollment options cannot be mixed into these local modes.

CLI output describes paths/digests with status `prepared-local-only` or
`certificate-admitted-local-only`. `issuanceAuthorized`, `proxyAuthenticated`
and `enrollmentComplete` remain false. Never place private-key contents in chat.

## Remaining N04 boundary

The separate [software-key issuer worker](workload-identity-issuer.md) now has
source for independent issuance authorization, durable one-use claims, certificate
signing and original-only admission. Its verifier shares the local public-input
checks while retaining the worker's original work and deadline; it does not
turn request possession or a CA-install capability into issuance authority.

The [control-plane caller and authenticated issuance action](control-plane-workload-identity-issuance.md)
are connected in source. Explicit CLI submission and portal orchestration are
still missing; these local modes remain network-free. Client-CA
distribution, rotation/revocation, SPIFFE lifecycle/service, sidecar integration
and verified runtime workload channels also remain open. N04 earns no landed
parent credit: project status is 35/46 landed, two active (H05/N04), nine todo;
production acceptance remains 0/6. Source is unbuilt, unexecuted and unprovisioned.
