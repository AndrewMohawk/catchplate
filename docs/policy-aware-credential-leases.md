# Policy-aware ordinary credential leases

This is an explicit third representation, not a Native alias or a widening of
legacy contracts. The ordinary producer retains `ReleaseProfile::PolicyAware`
from its independently selected cold response-authorization owner before key
generation and request hashing. Native transport retains `Native`; old ordinary
configuration retains `Legacy`. Returned versions, principal length, attestation
JSON and cached material cannot choose or change that selection.

The closed `serverware.policyAwareCredentialLease` families are Request v1
(metadata or uncontrolled dispatch) and v2 (controlled dispatch), RequestAuthority
v1, ReleaseAuthorization v1/v2 (ordinary/durable), Envelope v1/v2 and Set v1/v2.
They preserve the paired fields and omission/null rules: controlled requests
require request authority and a present nullable release authorization; controlled
envelope AAD and plaintext retain the exact request and authority hashes. There
is no invented envelope/set `kind`. All PolicyAware principal, route and credential
IDs remain trim-stable, Unicode-Cc-free and at most 256 UTF-8 bytes. Only the
separate Native family admits a 1024-byte principal. Schema character limits do
not replace the runtime byte predicate.

PolicyAware request, operation/parent, metadata, authority and AAD hashes use
sorted compact Python-compatible `ensure_ascii` bytes, including DEL escaping.
The exact selected wire labels enter the originals. Legacy hash recipes and
Gmail child/material-v1 originals are unchanged; Gmail parent checks use the
retained profile. The existing X25519/HKDF/AES-GCM cryptography is unchanged.

## Recipient original and independent verifier

The ordinary PolicyAware path holds its own generated one-use
`CredentialRecipientV1`, distinct from the actual Native NSM pending/quoted owner.
The Native owner records `Native` and rejects PolicyAware preparation before
key generation. PolicyAware requires an independently configured attestation
command before generating its key. Its explicit command inputs are
`serverware.policyAwareRecipientAttestationRequest/v1` or `/v2`, with the exact
`leaseRequestApiVersion` marker, public key, nonce, request digest and nullable or
required authority digest. Legacy command inputs remain unchanged.

That command must return genuine original
`serverware.nativeCredentialRecipientEvidence/v1` naming the actual generated
public key. The reused role-2 evidence family describes its cryptographic
original, not ordinary transport becoming Native custody. The broker requires
the real configured independent verifier even in development. No successful
JSON verdict substitutes for the original quote/key/request association.

`scripts/verify_native_lease_recipient.py` accepts an independently pinned
`serverware.policyAwareCredentialRecipientExpectations/v1` original with exact
`leaseRequestProfile = serverware.policyAwareCredentialLeaseRequest`. Its independently
pinned trust-root original and genuine role-2 checks remain required. Stdin and
stdout include the exact PolicyAware `leaseRequestApiVersion`; v1 has no authority
digest, while v2 requires dispatch-secret purpose and that digest. Native
expectations v2 and legacy expectations v1 remain strict and reject substitution.
Existing `_expectations` import overrides are unchanged.

Deployment must independently provision and pin the new expectations and the
command capable of the new input contract. No automatic pin upgrade, command
generator, attestation service or successfully provisioned deployment is supplied
by these source changes. Missing or old-profile configuration fails closed.

## Retained lifetime and authority

The actual pending and consumed owner preserve the selected profile through
request creation, evidence, envelope verification, decryption and material/cache
publication. Every use compares material with the current genuine runtime/cold
selection; changing the family cannot reuse cached secrets or generations.
Controlled PolicyAware fetch inherits the original authorization deadline;
metadata has at most 30 seconds from its own opening. Command, request and cache
lifetimes are clipped to that original interval. A controlled cache miss cannot
mint a new allowance. Current policy, actor, reservation, JIT/quota/durable scope,
signed broker response and final upstream-send checks remain mandatory.

See [policy-aware release authorization](policy-aware-release-authorization.md)
for signed normalized policy preparation and reservation/current-policy joins.
This source integration is not a build, execution, provisioning, successful
credentialed provider journey, egress/canary, installation or production claim.
