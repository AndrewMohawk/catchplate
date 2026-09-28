# Independently authorized workload identity issuer

This is an authored, source-only worker contract. It is unbuilt, unexecuted and
unprovisioned; no issuance, mTLS handshake, production acceptance or N04 closure
is claimed. The control-plane startup owner, public HTTP action and explicit CLI
submission are not connected by this worker slice. Existing local preparation
and certificate-admission CLI modes remain network-free. The
[remaining integration plan](workload-identity-issuer-plan.md) preserves those
boundaries and the broader lifecycle/channel requirements.

## Separate authority and exact originals

`workload_identity_issuer_bootstrap.py` admits a canonical Ed25519 root-signed
`serverware.signedWorkloadIdentityIssuerBootstrap/v1` envelope whose payload
domain is `serverware.workloadIdentityIssuerBootstrap/v1`.
`workload_identity_issuance_authorization.py` admits a separately signed
`serverware.signedWorkloadIdentityIssuanceAuthorization/v1` envelope whose
payload domain is `serverware.workloadIdentityIssuanceAuthorization/v1`.
Each signature covers the ASCII payload domain, a zero byte, and the canonical
payload original. Unsupported source revisions are rejected.

The cold root independently admits the direct CA certificate, packet-signing
key, separate grant-authorizer key, policy/runtime pins, journal identity and
fixed listener/resource pins. The CA SPKI must differ from the cold root and
packet signer; the authorizer must differ from all three. The CA private key is
not in any packet, request, bootstrap, portal or response. The software worker
alone reads the preprovisioned key after public admission and verifies its exact
signed byte count, canonical PKCS#8 form and admitted CA SPKI.

A request supplies exactly three originals: independent grant, genuine signed
enrollment packet, and the existing signed P-256 identity request. The grant
binds the bootstrap/configuration, issuer and authorizer, packet and request
digests, principal, nonce, CSR, subject SPKI, exact SANs, serial and original
validity. Its serial is canonical lowercase hexadecimal, with no leading zero,
and represents a positive integer below `2**159`. Digest strings use
`sha256:` followed by 64 lowercase hexadecimal digits.

The shared `serverware_agent_trust/workload_identity_originals.py` preserves the
local client profile: standard P-256 PKCS#10 CSR, empty subject, critical exact
DNS/URI SANs, genuine CSR signature and a separate canonical low-S request proof.
The independent issuer digest is inside that request proof. The worker replays
the real packet signature under its cold-admitted packet key, not a key supplied
by the request. A CSR, CA-install capability, ordinary role check or successful
verification object is never issuance authority.

The fixed leaf is a directly issued non-CA client-auth certificate for the exact
CSR public key and SAN inventory, with digital-signature-only key usage. Its
serial and validity must equal the independent grant. Validity cannot exceed
the original packet/request, grant or issuing CA. The final original-only
certificate verifier replays the grant and public request originals as well as
the retained certificate's actual issuer signature, key, SANs and constraints.

Both cold and grant modules provide `_produce_on_work` for explicitly supplied
signing keys and bounded canonical `payload_bytes`, followed by genuine
round-trip admission. These are operator/provisioner source APIs, not an
automatic grant-signing service or issuance permission minted from a CSR.

## Fixed preprovisioned worker resources

| Resource | Source-fixed contract |
| --- | --- |
| Worker | UID/GID 65492; process mode `workload-identity-issuer` |
| Socket peer | UID/GID 65532 |
| Inherited descriptors | 198 root public original; 199 bootstrap; 200 listener; 201 CA key; 202 journal directory |
| Public trust originals | `/run/serverware/workload-identity-issuer-trust/root-public-key.pem` and `bootstrap.json` |
| CA private key | `/run/secrets/serverware-workload-identity-issuer-ca-key` |
| Listener | `/run/serverware/workload-identity-issuer/issuer.sock`, named owner 65492:65532, mode 0660 |
| Journal | `/var/lib/serverware/workload-identity-issuer`, owner 65492:65492, mode 0700 |

The bootstrap separately pins the listener descriptor's device/inode and the
named socket's device/inode; those are not assumed equal. The launcher checks
the real Unix stream/listening socket, fixed path and peer/resource profile,
not merely a pathname string. Resource parents and original-file protections
are enforced by the actual launcher. Missing resources are not created on
demand and no fallback CA is generated. No deployment commands are provided
while provisioning and acceptance remain unperformed.

One inherited `_ValidationWork` and original dual-clock window cover cold reads,
request admission, durable publication and response. The source-fixed initial
window is at most 30 seconds with zero admitted clock skew; signed intervals and
the configured request timeout only narrow it. No new per-stage budget or
timeout is opened. Cold originals are bounded at root 16 KiB, bootstrap 128 KiB
and CA key 64 KiB, with the actual signed private-key byte count required.
Grant/packet/request caps are 32 KiB, 8 MiB and 64 KiB; response association and
leaf caps are 4 KiB and 64 KiB. These individual caps do not override the shared
64 MiB aggregate or cumulative work limits: oversized combinations fail before
body admission. Representation reservations are not heap measurements.

## Durable single-shot behavior

`workload_identity_issuer_journal.py` uses a separate fixed journal family with
exclusive publication, fsync/readback and its own lease. Before the first CA
signature, the service durably claims the namespace/principal/nonce slot and
the signed serial. A different grant, request, issuer or bootstrap association
cannot make that spent slot fresh. Serial reuse under the same issuer SPKI is
also rejected. The namespace must remain stable across CA/grant renewal.

Only the closed scalar association and public certificate are journaled. The
packet body is deliberately absent because it can contain a CA-install token.
An exact complete result can be read back and genuinely re-admitted without
signing again, while its original authority remains valid. A claim without a
complete retained certificate is unknown: it permits no re-sign, deletion,
expiry extension or inferred nonissuance. A changed association fails closed.

The root-signed checkpoint requires the exact head at its retained record-count
prefix and allows valid later extensions. It is not an independent rollback
witness. Local fsync, locks and software-held keys do not establish HSM/TEE
custody, privileged-writer resistance, off-host durability or production safety.

The actual service is single-shot and returns only bounded public association
data plus the retained certificate original, under the final live guard. The
client must still admit that leaf against its independently pinned issuer and
retained local request/private key. Issuance does not install proxy trust, prove
client authentication or complete enrollment. Operator provisioning, trusted
deployment configuration, real mTLS acceptance, rotation/revocation/retirement,
service authenticated channels, SPIFFE lifecycle and sidecar support remain
separate work and acceptance obligations.
