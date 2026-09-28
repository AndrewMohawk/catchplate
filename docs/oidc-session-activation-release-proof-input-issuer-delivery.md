# Root-original proof-input issuer launch

[oidc_session_activation_release_proof_input_issuer_bootstrap.py](../serverware/oidc_session_activation_release_proof_input_issuer_bootstrap.py)
defines the separately root-signed launch for the one-shot
`oidc-session-activation-release-proof-input-issuer`, UID/GID 65494, with public
caller UID/GID 65532. This module performs no file, socket, key-byte or database
I/O and creates no resources. Its source does not establish deployed custody,
runtime acceptance or provisioning.

## Closed v1 launch and originals

The signed and payload schemas are
`serverware.signedOidcSessionActivationReleaseProofInputIssuerBootstrap/v1` and
`serverware.oidcSessionActivationReleaseProofInputIssuerBootstrap/v1`. Purpose is
`launch-oidc-session-activation-release-proof-input-issuer`; trust mode is fixed
to `trusted-host-local`. The bootstrap identity has its own
`serverware.oidcSessionActivationReleaseProofInputIssuerBootstrapIdentity/v1`
domain.

The payload pins the exact issuer policy, completion bootstrap, proof enrollment
and intent enrollment identities using the existing
[policy identity functions](oidc-session-activation-release-proof-input-policy.md).
Those four originals remain separate inputs, not embedded base64 documents.
The payload also pins root-signing-key byte count/digest, source revision,
fresh issue/expiry and the closed launch. A byte digest is not proof that a
private key was opened, paired, sealed or independently provisioned.

The only launch schema is
`serverware.oidcSessionActivationReleaseProofInputIssuerLaunch/v1`.
`deliveryEndpoint` is mandatory from v1; there is no non-staging profile or
version fallback. The exact inherited inventory is:

| FD | Source-fixed input |
| --- | --- |
| 198 | Runtime root public original |
| 199 | Signed issuer launch bootstrap |
| 200 | Public request listener |
| 201 | Independent issuer policy original |
| 202 | Independent consume-completion bootstrap original |
| 203 | Independent proof enrollment original |
| 204 | Independent intent enrollment original |
| 205 | Runtime root-signing-key original |

The launch fixes the role, process, UID/GID, peer and descriptor fields, exact
inventory, listener path and socket/path device/inode pins. The request listener
is `/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock`,
named `serverware-oidc-session-activation-release-proof-input-issuer`.
Request timeout is an exact integer from 1 to 30 seconds.

The mandatory staging endpoint is
`/run/serverware/oidc-session-activation-token-release/proof-bootstrap.sock`,
with expected root peer 0:0 and timeout 1–30 seconds, no larger than the launch
request timeout. Signed resource pins are independent policy; this module does
not observe matching listeners, files, directories or a ready worker.

## Genuine admission and lifetime

`_verify_on_work` requires `bootstrap_bytes`, `issuer_policy_bytes`,
`completion_bootstrap_bytes`, `proof_enrollment_bytes`,
`intent_enrollment_bytes`, `root_public_key`, `live_window`,
`transport_deadline_ns` and `work`. Optional `_continuity` only exchanges
restrictive epoch/monotonic floors.

It authenticates the root launch, compares all four exact original identities,
and invokes the genuine independent policy verifier. That verifier admits the
actual completion configuration and enrolled purposes, not caller-selected
target data. The launch interval must fit wholly within the policy interval;
request and staging timeouts only narrow the inherited allowance. The actual
policy and original clock guards remain live through return.

The private immutable `_IssuerMaterial` has 15 fields: the five original-byte
fields, actual `policy_material`, owned `launch`, root-key byte count/digest,
attestation interval, opening sample, narrowed `live_window`/`deadline_ns`,
`live`, and mandatory tuple4 `delivery_endpoint`. No admission API accepts this
material in place of originals.

`_produce_on_work` replaces `bootstrap_bytes` with a closed `payload` and actual
`root_private_key`, retaining the same other arguments. It genuinely admits
the independent originals before pairing/signing, precharges the fixed
signature envelope, signs, and verifies exact original readback. It does not
generate or provision a signing key.

`_construction_on_work(work)` is solely for the cold root owner to create its
first bracket before public-file or key I/O. That exact work/window must remain
in force through root delivery, permanent same-PID drop, startup, private packet
acquisition, issuance, staging and response; it is not a request-time reset.

## Capacity and owner obligations

The launch cap is 16 KiB, 256 nodes and depth 6; the signer-original cap is
16 KiB. Policy is bounded by its actual 64 KiB codec, completion by its actual
32 MiB codec, and enrollments by their original codecs. Before policy admission,
the verifier reserves actual cold originals, maximum signer bytes and a
decoded-completion allowance; it subsequently checks the actual nested
inventory against the same 64 MiB source cap. The resource owner must separately
account for its root bytes, TLS material, live request, packet and other held
copies, rather than interpreting this local check as a whole-process quota.

The cold owner must finish this genuine public admission **before private root
key access**, then check exact signer bytes and actual key pairing. The issuer
uses the admitted completion's read-only custody configuration and three
independently pinned, issuer-local TLS files; it does not acquire completion
signing, historical AES, delivery AES, journal or state/SQL-write powers.

The [setup producer](oidc-session-activation-release-proof-input-production.md)
accepts optional `maximum_original_bytes` only to tighten its 64 MiB inventory.
The service subtracts measured cold/resource/transport holdings before passing
remaining capacity, which is checked before decoded inputs and before output
wrapper/signature allocation. No returned size check substitutes for that
preallocation bound.

The service still must acquire the exact packet through its actual fixed
read-only reader, issue from the original complete/ACK/intent request, stage the
exact raw1 bootstrap and verify the identity-only ACK before returning. The
public caller never supplies or receives the private packet. A staged ACK is
not proof-worker readiness, private replay, proof completion, token delivery
or a current session. Runtime validation and independent resource provisioning
remain separate acceptance work.
