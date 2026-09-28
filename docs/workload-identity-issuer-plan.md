# N04: independently authorized workload certificate issuance

This is the next implementation contract, not an implemented issuer, an issuance
authorization or a deployment instruction. The local client preparation/admission
lane is source-only; N04 and all production gates remain open. No keys,
certificates, services, trust stores or cloud resources were provisioned for this
plan. See [the local client contract](workload-identity-provisioning.md).

## Existing integration points

| Actual source | Reuse and boundary |
| --- | --- |
| `serverware/enrollment.py:build_agent_enrollment` | Produces the genuine signed packet from the current policy snapshot, attestation pins, principal and nonce. `_identity_block` includes public mTLS selectors only. Packet signing is `response_identity.sign_statement`; that response key is not a certificate-issuance key. |
| `serverware/app.py:agent_enrollment` (`POST /api/agents/enrollment`) | Currently requires `policy_author`, builds the packet, creates a purpose-specific CA-install session, and binds the final packet to that session. This route and its session token authorize neither workload certificate signing nor an issuer key read. |
| `serverware/control_plane_runner.py:main` | Admits custody, then enrollment, before application/DB/HTTP imports. A new public issuer-transport owner belongs in this cold sequence, with matching exceptional and normal cleanup. |
| `serverware/control_plane_custody_startup.py:require_started` and `control_plane_custody_client._snapshot` | Supply the actual already-admitted runtime root, original inherited descriptor inventory and current receipt. Reuse those originals; do not repeat runtime inventory admission after a journal has opened descriptors. |
| `serverware/control_plane_startup.py:validate_control_plane_configuration` | Requires genuine startup owners. Add a check for the new optional issuer-transport owner; do not replace it with a PID environment flag or lazy app initialization. |
| `data-plane/decision-gate-rs/src/main.rs:load_proxy_ingress_config` | `mtls` mode loads `SERVERWARE_PROXY_TLS_CERT`, `SERVERWARE_PROXY_TLS_KEY` and `SERVERWARE_PROXY_CLIENT_CA_BUNDLE`; rustls requires TLS 1.3 and client authentication. The loaded public bundle digest is recorded in `ProxyIngressAttestation.client_trust_bundle_sha256`. Issuance alone does not install that bundle or prove a handshake. |
| `serverware_agent_trust/workload_identity_provisioning.py` | Current local producer/admitter consumes exact pinned packet, packet-signing key and issuer originals, then the retained request/key and returned leaf. Its standard CSR and signed request establish possession only. |

`control_plane_enrollment_startup._EnrollmentOwner` is a WebAuthn/registration
authority owner, not a workload CA. `ca_material.ensure_mitm_ca_material` concerns
the interception CA and has a local creation path; it must not be repurposed as
the workload issuer or called to satisfy missing issuer configuration.

## Chosen smallest usable server

Add one dedicated local issuer worker, distinct from ASGI and the existing
enrollment owner. The initial profile matches the client exactly: new P-256
workload keys, explicitly permitted DNS/URI SANs, an empty subject, one directly
issuing independently provisioned CA, and client-auth leaves. It is not a general
CA path builder, key-rotation service or SPIFFE registration server.

The worker receives a root-signed closed bootstrap and original descriptors for
its public roots/configuration, preprovisioned CA key, bounded durable journal
and listener. A distinct source-fixed UID/GID, descriptor inventory, process
mode and private-resource separation must be selected in the implementation's
actual launcher contract; no currently allocated enrollment key slot is reused.
Public originals, CA/key SPKI pairing, independent authorization-key exclusion,
directory/listener ownership and original intervals are admitted before private
operations. The worker alone can use the CA signer. ASGI receives no CA key,
generic sign callback, caller-selected key path or successful admission DTO.

The bootstrap independently pins the CA certificate and SPKI, the packet-signing
public key, a **separate issuer-authorization public key**, allowed current
policy/runtime scope, listener peer and exact journal identity/quota. The
operator provisions the authorization key and CA under separate permissions;
neither is inferred from the packet, CSR, TLS peer, response key or CA-install
session. A software-key source profile must say so explicitly; it is not an
HSM/TEE custody claim.

For the first usable slice, an independently authorized operator/provisioner
supplies a signed per-request grant as an original. Do not introduce a new
automatic control-plane grant signer merely to avoid that explicit authority
boundary. A later approved grant-issuer service may replace manual delivery of
the same original contract, not bypass it.

## Original-only issuance contract

Proposed new closed domains are
`serverware.workloadIdentityIssuerBootstrap/v1` and
`serverware.workloadIdentityIssuanceAuthorization/v1`, each with an explicitly
paired signed envelope. The implementation must freeze canonical encoding and
bounded originals before exposing a service.

Each issuance authorization pins:

- Its purpose, supported source/configuration, unique grant identifier and
  original issuance/expiry interval.
- Exact issuer certificate/SPKI digests and independently enrolled authorizer
  identity; exact packet-signing-key digest and permitted policy/runtime pins.
- Exact signed packet bytes digest, principal, nonce, signed identity request
  bytes digest, CSR bytes digest and workload public SPKI digest.
- Exact selected SANs, the fixed client-auth certificate profile, and the
  authorized certificate validity bounds. These cannot exceed the original
  packet/request interval or the issuing CA's validity.
- The configured journal namespace/checkpoint and one issuance for that
  principal/nonce. A new grant ID or changed request must not create a second
  issuance slot for the same nonce.

The request is the existing canonical
`serverware.signedWorkloadIdentityRequest/v1` original. Its P-256 signature is
over `b"serverware.workloadIdentityRequest/v1\x00" + canonical(payload)`;
the PKCS#10 signature must independently verify under the same exact CSR key.
The worker must also genuinely verify the signed enrollment packet under its
independently configured packet key and match all original bindings. No
packet-supplied public key, accepted-result parameter, signed-request possession
or ordinary `policy_author` status substitutes for the separate issuance grant.

The worker receives a fixed bounded tuple of originals: issuance authorization,
enrollment packet and identity request. The CSR is already inside the request;
there is no second independently selected CSR or issuer from the wire. Pinning
the signed packet's exact file bytes is distinct from its internal signed
unsigned-packet digest; both checks remain necessary.

The response contains only a public certificate original and bounded public
association data. The client re-admits it against the retained local request,
private key and originally pinned issuer. A response echo, TLS peer or matching
CSR digest is not certificate admission. No private key, CA-install token,
browser credential, provider credential or successful client-auth claim appears
in the response or journal. Persist packet digests, not the packet body: the
existing enrollment packet can contain a CA-install capability. Its original is
verified in the bounded invocation, not copied into this new journal family.

## Durable boundary and retry semantics

Use a new purpose-specific issuer journal, not a registration/activation record
disguised as an issuance permission. Reuse the existing bounded descriptor and
exclusive-publication primitives behind `authority_witness_journal.WitnessJournalIO`
and the control-plane journal's fsync/readback pattern, with a separate closed
record codec and authorization checks.

Before the first CA signature, atomically publish and read back an irreversible
claim for the configured issuance namespace plus **principal and nonce**. Pin
the exact packet/request/grant/issuer association and a unique valid serial in
that record. Keep this nonce namespace across issuer/grant renewal: changing an
issuer certificate, grant ID, request signature or output directory must not
silently make an already spent principal/nonce fresh.

Retain the exact certificate bytes and association durably, then independently
verify the certificate/request/key/SAN/profile/validity join and read the retained
bytes back before returning them. Any malformed, changed or ambiguous durable
state fails closed. A recovered complete result permits **read-only return of
the identical certificate**, never a fresh signature or extended expiry.
A claim without a complete retained certificate is an unknown result: no resign,
claim deletion, automatic retry or optimistic inference of nonissuance.

Admission/readback share one bounded work inventory and a nonrenewing processing
window. Reserve inputs, decoded originals, journal frames and certificate output
before bodies or signing. Original grant, packet, request and CA limits remain
hard. Filesystem fsync/locking is not rollback resistance against a privileged
writer; independent checkpoint/witness or equivalent protected monotonic state
is a production gate, not an implicit property of the local journal.

## Concrete implementation split

The following names are proposed new files/interfaces, not existing APIs:

1. `serverware/workload_identity_issuance_authorization.py` and
   `workload_identity_issuer_bootstrap.py`: closed producer/verifier contracts
   and original-only cold admission. Reuse the client request encoding and
   genuine packet verifier, factoring shared public verification only through
   an explicitly coordinated source change. Do not accept the local
   `PreparedIdentity` or `ProvisionedIdentity` objects as authority.
2. `serverware/workload_identity_issuer_startup.py`,
   `workload_identity_issuer_service.py`, `workload_identity_issuer_journal.py`
   and a fixed-role entrypoint: exact cold resource ownership, one guarded
   `issue_on_work(authorization_bytes, packet_bytes, request_bytes, ...)`,
   irreversible claim and bounded original certificate return. Lifetime/work
   arguments are the actual service's inherited context, not posted values.
3. `serverware/control_plane_workload_identity_startup.py` plus a small
   `control_plane_workload_identity_client.py`: public-only bootstrap and one
   endpoint/peer-bound socket. Integrate the startup owner after existing
   custody admission and before app imports in `control_plane_runner.main`,
   then require/close it through the existing startup lifecycle. The new public
   bootstrap must already be present in the original runtime-admitted FD
   inventory; no second scan or inherited-descriptor bypass.
4. A separate bounded `POST /api/agents/workload-identity/issue` and matching
   action-bound options, not a semantic expansion of `/api/agents/enrollment`.
   Use the real current-role, mutation-MFA and two-person machinery
   (`app._require_control_plane_mutation_mfa`,
   `app._require_control_plane_two_person`) for a new fixed action such as
   `workload.identity.issue`; those checks are additional prerequisites, not
   the CA grant. Route input is the original tuple plus that action's fresh
   assertion, with no configurable CA, endpoint or signer. Enable this route
   only after the genuine grant/worker/journal/client chain is connected.

The protected worker and original authorization/response contract can be
implemented first, independently of portal polish. The HTTP/CLI submission
bridge must then call that actual owner; neither an unused helper nor an
operator plan alone completes the server slice. Existing local CLI modes remain
network-free until a separately explicit submission mode is implemented.

## Operator and deployment boundary

An authorized operator must provision the CA and separate grant authorizer,
their admitted cold originals, dedicated identities/resources and durable
storage. The issuer CA public certificate must be independently distributed to
the proxy's `SERVERWARE_PROXY_CLIENT_CA_BUNDLE`; proxy server trust remains a
separate client input. Bind the actual ingress bundle digest and policy issuer
selectors to deployment evidence. Never install trust from the CSR or issuance
reply, mutate trust implicitly at HTTP request time, or claim the intended bundle
is already loaded from a desired configuration value alone.

Preserve explicit CA rotation, retirement, revocation, policy change and rollback
procedures. The local first profile rejects preselected leaf/key hashes during
fresh-key preparation, unsupported issuer constraints/chains and expired packet
intervals. General existing-key enrollment and broader CA profiles need explicit
versioned authority rather than relaxed client checks.

Real acceptance still requires a provisioned trust path and a workload request
through mandatory mTLS, wrong-key/SAN/issuer/expiry rejection, durable uncertainty
and restart behavior, and unchanged inner provider TLS/egress controls. Service
channel bearer replacement, SPIFFE lifecycle, local sidecar support, HSM/TEE and
off-host/rollback evidence remain separate N04 and production obligations.
