# Per-request proof setup policy and receiving

Source `.199`; unbuilt, unexecuted and unprovisioned. Independent root policy,
original-only derivation, public acquisition and private receiving now connect
to the [finite issuer service](oidc-session-activation-release-proof-input-issuer-service.md).
It acquires the exact packet, signs the derived bootstrap and stages that original
within one bounded attempt. Neither an endpoint setting nor a staged ACK means
the private proof worker has completed its later proof request.

## Independent policy

`oidc_session_activation_release_proof_input_issuer_policy.py` admits the closed
root-signed `serverware.signedOidcSessionActivationReleaseProofInputIssuerPolicy/v1`
envelope. Its payload contains `schema`, `sourceRevision`, `purpose`, `trustMode`,
`completionBootstrapDigest`, `proofEnrollmentDigest`, `intentEnrollmentDigest`,
`proofScope`, `callerId`, `proofLaunch`, `issuedAtEpochNs`, and `expiresAtEpochNs`.
Purpose is `issue-oidc-session-activation-release-proof-inputs`; trust mode is
`trusted-host-local`. No posted target, packet hint or successful result object
supplies authority.

The completion identity frames the exact signed original using
`serverware.oidcSessionActivationReleaseProofInputCompletionBootstrapIdentity/v1`.
Both enrollment identities retain their existing enrollment domains. All three
originals are independently authenticated, not merely compared to these hashes.
The completion original pins the packet, pending head, database, generation,
configuration, historical custody, and read-only resources. The seven-field
proof scope and fixed launch bind the distinct proof signer, producer and release
receiver. Intent/proof keys remain separated from actual root, configured,
state, consume and historical signing purposes.

The full verifier takes `policy_bytes`, `completion_bootstrap_bytes`,
`proof_enrollment_bytes`, `intent_enrollment_bytes`, `root_public_key`, and the
mandatory original `live_window`, `transport_deadline_ns`, and `work`, with an
optional restrictive two-clock `_continuity`. Its immutable 16-field material
is a same-call observation, not an accepted authority input. The root-only
publisher receives these independent originals plus a closed payload and actual
root private/public pair; it verifies the joins before signing and reads back
the signed output. It is not a public payload-signing endpoint.

Policy admission preserves the original clock samples and cumulative ledger.
The fresh policy interval must fit all admitted completion/custody intervals;
enrollment limits and launch timeout may only narrow it. Policy bytes are capped
at 64 KiB; nested originals remain within the complete 64 MiB bound, not the sum
of individual contract maxima.

## Public request and private packet boundary

The public wire uses `SWOPIQ01` / `SWOPIR01`, with raw4 request:

1. Fixed purpose `issue-oidc-session-activation-release-proof-inputs`.
2. Exact signed completion request.
3. Exact signed state receipt.
4. Exact signed release intent.

The raw1 response is the exact proof bootstrap, which already embeds release
custody. The fixed root listener is
`/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock`;
only caller UID/GID `65532` is accepted. The caller's remaining capacity narrows
the 48 MiB bootstrap ceiling before response-body allocation. Opaque returned
bytes are durably retained before semantic admission; framing itself admits no
signature, target or readiness claim.

The public permission **does not hold the private consume packet**. Unsigned
SQL hints, digests and encrypted bundle bytes cannot manufacture it. The
[producer](oidc-session-activation-release-proof-input-production.md) therefore
requires a separately acquired exact `consume_packet_bytes`, in addition to
the three request originals and independent policy/enrollments. The issuer uses
the actual read-only reader and independent packet/pending pins, not a posted
packet. The reader accepts optional tightening `maximum_packet_bytes` and
original `_current` arguments. Its bounded SQL return prevents an oversized
packet text from reaching the client driver; it repeats the cap before ASCII
encoding. Default read/write paths remain unchanged.

## Private staging and worker

The staging wire is distinct: `SWOPDQ01` / `SWOPDR01`, raw2
`(stage-oidc-session-activation-release-proof-inputs, proofBootstrap)`, with ACK
`(staged, framedBootstrapIdentity)`. It fixes issuer UID/GID `65494`, root peer
`0:0`, and `/run/serverware/oidc-session-activation-token-release/proof-bootstrap.sock`.
The bootstrap identity uses
`serverware.oidcSessionActivationReleaseProofInputDeliveryBootstrapIdentity/v1`.
Length/cap/peer checks precede body allocation. The sender requires the actual
issuer-owned delivery channel, preserves its exact descriptor inventory and
matches the returned identity to the staged original before normal close.

Receiving independently authenticates the policy and all four signed originals,
compares exact completion/enrollment bytes, scope, caller, signer and resource
launch, and retains the same work/window. Its seven-field result remains
same-call data. It has neither the private packet nor old-token possession and
does not claim to rederive those facts. Conservative decoded-original capacity
reservations tighten the wire ceiling before admission.

The [dynamic worker](oidc-session-activation-release-proof-dynamic-delivery.md)
holds exact keys/TLS resources before ACK, seals the existing seven descriptors,
permanently drops privilege in the same process, and enters the actual one-shot
proof service. Old-token possession and genuine private committed replay remain
inside that later proof request. No root signing key is delivered to the worker.

## Remaining acceptance

The grant issuer still cold-pins an exact proof bootstrap; connect it to the
fresh per-request original under independent authorization. Provision all
independently admitted resources, then connect public HTTP/current-auth/cookie
completion, recovery and portal work.
Full verification follows source freeze. This source checkpoint supplies no
SQL commit, proof, token delivery, current-session, hardware or production
acceptance evidence.
