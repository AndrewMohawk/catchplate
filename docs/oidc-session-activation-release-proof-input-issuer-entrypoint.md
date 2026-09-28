# Proof-input issuer root delivery

The fixed isolated launcher starts one independently configured proof-input
issuer, then permanently drops to UID/GID **65494** in the same PID. This is
source-only delivery code: it neither provisions resources nor establishes that
issuance, staging, a proof exchange or credential release has succeeded.

## Fixed public and private inventory

The launcher accepts only `--root-delivery` under the isolated production
Python runtime. Root receives one activated listener named
`serverware-oidc-session-activation-release-proof-input-issuer`, at
`/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock`.
Its pathname is `65494:65532`, mode `0660`; the actual service authenticates the
public peer before reading request bytes.

The protected directory
`/run/serverware/oidc-session-activation-release-proof-input-issuer-trust`
contains six root-owned, single-link, mode `0444` public files:

- `root-public-key.pem`
- `bootstrap.json`
- `issuer-policy.json`
- `completion-bootstrap.json`
- `proof-enrollment.json`
- `intent-enrollment.json`

Their sealed copies occupy FD 198, 199 and 201 through 204. FD 200 is the
original listener. FD 205 is the separately protected runtime-root signer,
read only from
`/run/secrets/serverware-oidc-session-activation-release-proof-input-issuer-root-signing-key`.
That source file must be root-owned, single-link and mode `0400`; its exact
size, hash and Ed25519 key pair must match the admitted launch and runtime root.

The actual [cold bootstrap admission](oidc-session-activation-release-proof-input-issuer-delivery.md)
authenticates the independent policy, completion and enrollment originals
before any private signer or TLS-key read. No request can select these paths,
replace the policy, provide a private packet or install a successful-material
carrier. There are no AES/history keys, completion signer or journal in this
issuer inventory.

## Issuer-local read-only TLS

The issuer opens only `ca.pem`, `custody.crt` and `custody.key` below the fixed
`/run/serverware/oidc-session-activation-delivery-completion-tls` directory.
Sizes and bytes hashes come from the genuinely admitted completion originals.
Public files require root ownership and mode `0444`; the private key requires
`root:65494`, mode `0440`. Protected ancestors, single links and unchanged
file/path identities are checked as well.

These are separate issuer mount permissions at the exact existing DSN paths,
not a relaxation of the proof worker's UID 65497 checks. Commit TLS files are
not opened. No supplementary group or arbitrary descriptor exemption bridges
the roles, and the root signing key never enters the public application.

## Original allowance and finite continuation

Public reads, root admission, signer/TLS checks, permanent privilege drop and
the actual runner retain one work ledger, original opening samples and only
narrower deadlines. The source-bound delivery guard retains the exact sealed
originals, listener, TLS identities and restrictive clock observations. Its
measured byte count is private continuation metadata, not incoming authority.
Startup separately owns its accepted, staging and transient reader descriptors.

Whole-held originals and known decoded graphs share the 64 MiB cap. Source
reads, sealed copies, public rereads and cold decoding are bounded before their
allocations; the actual startup uses retained capacity when reserving packet,
produced-bootstrap and transport space. Individual file caps are not additive
allowances.

The policy FD accepts the versioned 6 MiB upper bound; genuine admission still
caps legacy v1 at 64 KiB. Public cold reads reserve eight footprints before
each body, inherited intake preflights all sealed lengths before body one, and
known retained graphs include the explicit current planner from policy v2.
Request and packet caps subtract repeated policy-admission captures and reserve
eight body footprints. The 64 MiB total, roles and eight-descriptor inventory
are unchanged; larger otherwise valid originals can refuse before allocation.

The runner invokes the actual startup once and requires exactly one successful
`serve_once()` result, followed by normal close. There is no post-drop `exec`,
new processing window, retry or second public request. Startup performs the
independent packet read and genuine issuance; its staging ACK remains only
exact-byte/resource staging, not worker readiness or a committed-release proof.
Failures emit fixed diagnostic text, never token, packet or key content.
Cleanup acts only on still-owned matching descriptors and treats uncertainty
as failure. Resource provisioning, installation and runtime acceptance remain
separate work.
