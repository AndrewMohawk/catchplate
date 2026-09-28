# N04: workload identity provisioning contract

This is an implementation decision, not a landed capability or permission to
provision an issuer. N04 remains open. Existing signed identity selectors and
TLS client support do not by themselves provision a workload identity.

## Client ownership

The planned client module is `serverware_agent_trust/workload_identity_provisioning.py`,
called through two explicit local modes of the existing enrollment CLI:
`--prepare-workload-identity` and `--admit-workload-certificate`.

Both modes must genuinely reverify the signed workload packet against its
independently pinned signing key, expected principal and nonce, and preserve the
packet's original validity interval. Both require an independently pinned issuer
certificate. The issuer is not discovered from the returned leaf, operating
system trust store, packet contents or a network response.

Preparation locally creates a P-256 private key and standard PKCS#10 CSR with
the permitted SANs. The retained key also signs a domain-separated canonical
`serverware.signedWorkloadIdentityRequest/v1` envelope with a
`serverware.workloadIdentityRequest/v1` payload binding:

- Exact packet and packet-signing-key digests, principal and nonce.
- Selected identity/SAN constraints, public SPKI and original interval.
- Exact CSR bytes/digest and independently pinned issuer certificate/SPKI digests.

There is no custom CSR extension OID or secret challenge password. A request
proves possession and preserves the authenticated association; it does not grant
certificate-issuance authority. The CA-install token remains a separate purpose.

Admission verifies the same request, packet, retained key and requested issuer.
The first profile uses a direct leaf signature from that one pinned issuer,
checks issuer CA constraints/key usage and validity, and requires exact leaf
key/SAN identity, client-auth usage, signed packet constraints and original
requested interval. Unsupported chains fail closed rather than choosing a new
trust root.

Private files stay local in an owner-only descriptor-pinned directory, with
no-overwrite publication, readback and durability checks. Neither packets, portal
responses nor request envelopes contain a private key. The resulting pinned
certificate/key descriptions feed the existing workload client constructor.

## Separate server and production work

The server still needs an independently admitted certificate provisioner and
issuer lifecycle, authenticated one-use issuance authorization, and client-CA
distribution to the actual proxy. A client-signed request or a valid enrollment
packet alone cannot grant those privileges. This is not an extension of the
WebAuthn enrollment owner's private-key role by default.

Authenticated service channels, SPIFFE lifecycle integration, local sidecar
support and deployed end-to-end evidence remain part of N04. The implementation
follows the project-wide source-first workflow; key generation, certificate
issuance, runtime tests and provisioning are not being performed by this plan.
