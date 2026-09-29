# Native request-first retained-key certificate admission

`serverware_agent_trust.native_workload_identity_provisioning.admit_certificate`
locally verifies an actual direct-issued leaf against the original request-first
CSR/PoP, independently pinned issuer and exact retained target P-256 private key.
It publishes a leaf-plus-issuer chain without replacing an existing identity.
It performs no network operation, issuance, system trust installation or native
runtime admission. This source has not been built, executed or provisioned.

## Explicit local trust contract

The standalone function requires:

- pinned `packet`, `issuer`, `request`, `private_key` and `certificate` files;
- independent `expected_principal`, `expected_nonce` and `requested_sans`;
- an existing current-user-owned mode-0700 `output_directory`;
- `timeout_ms` in 100–30000, default 30000;
- optional `expected_leaf=(serial_number, not_before_epoch_seconds, not_after_epoch_seconds)`.

The packet is the exact canonical `serverware.nativeEnrollmentPacket/v2`
original, not a capture verdict. Its bounded decoder extracts original bytes
only. The contained target request must be byte-equal to the independently
pinned request, and its issuer DER must equal the genuine issuer parsed from
the independent PEM. Setup, delegation, policy requirements and role-5
diagnostics do not supply local issuance permission. This module neither
verifies those native authorizations nor fabricates a legacy packet signature
or `runtimeManifestDigest` binding.

The actual request is `serverware.signedWorkloadIdentityBootstrapRequest/v1`.
Original verification checks canonical request framing, P-256 CSR signature,
domain-separated low-S proof of possession, exact principal/nonce/SANs and
issuer DER/SPKI. The issuer is one canonical PEM certificate under the existing
direct-issuer CA/key/extension profile. The leaf must have that issuer's actual
signature, the exact request public key and ordered SAN inventory, empty
subject, critical non-CA/basic/key-usage constraints, clientAuth-only EKU and
the existing bounded extension profile. Its validity must be current and wholly
inside the original request and issuer intervals.

The retained key is an independently pinned, current-user-owned protected local
PKCS8 P-256 original. Its public key must exactly equal the genuine request key.
It is read only after public request/issuer admission, then held and rechecked;
publication reopens the same pinned named key and repeats the key association.
No new key is generated and no key bytes are printed, sent or copied to the
output directory. Software key reads are not HSM custody or a memory-erasure
guarantee.

If `expected_leaf` is supplied, every value must be an exact integer (not a
boolean); the positive serial must be below 2^159 and the leaf's whole-second
validity must exactly match the tuple. These expectations can only narrow local
admission. They are not a signature-verification result or authorization to
issue. Without that tuple, standalone admission still verifies the actual leaf
signature/profile/key/SANs and request-contained lifetime, but does not claim
agreement with a separate issuer grant's chosen serial or dates.

## Same-budget submission interface

The private `_certificate_admission_on_budget` factory accepts the same packet,
issuer, request, expected identity and SAN inputs plus the caller's original
`Budget` and `ExitStack`. `private_key=None` is options-only and reads no key;
when supplied, the actual key is admitted and retained before submission. The
factory accepts no successful verification DTO or replacement clock callback.

The resulting source-owned context offers `.current()`, the held `.directory`,
named `.packet_original`, `.request_original`, `.issuer_original`, the genuine
same-call `.requested` result, and data-only `.packet_components`. `.selected`
returns a fresh copy of the actual requested DNS/URI inventory. These are
same-call original associations, not native policy or issuer permissions.

Submission calls `.verify_leaf(raw, expected_leaf=...)` before retaining a
successful response receipt. This performs genuine direct-leaf verification
and returns no transferable verdict. Later `.publish(certificate_pin,
_expected_leaf=...)` re-reads the exact response original, repeats verification
and key admission, then publishes. The first verified raw leaf and expectations
are retained: a changed response or loosened expectation cannot silently replace
them. The publish attempt is one-use, including failures.

One original monotonic `Budget` covers all reads, parsing, cryptography and
publication. A nonrecursive raw wall/monotonic/PID guard retains the intersection
of request, issuer and actual leaf lifetimes; verifier live checks remain
siblings, never callbacks bound back into the same budget. There is no new
timeout after HTTP or certificate receipt. Static representation limits remain
inside 64 MiB; packet is at most 512 KiB, request/issuer/leaf at most 64 KiB each,
and the protected retained key at most 1024 bytes. The submission caller must
also reserve its HTTP and protected assertion/receipt lanes on that same scope.

## Publication and uncertainty

The existing no-follow directory and pinned-descriptor primitives create only
the source-fixed `client-certificate.pem`: canonical leaf PEM followed by issuer
PEM, mode 0600, with no-overwrite link publication, file/directory fsync and exact
named/held readback. The result is the existing `ProvisionedIdentity` containing
that public chain pin and the unchanged private-key pin. This is usable local
input material, not proof of a successful proxy connection or enrollment.

An existing destination refuses. Late failures can leave published originals;
the module does not delete, overwrite or automatically retry them. The caller
must retain those files and handle uncertainty explicitly. Native crypto and
filesystem calls still need an external watchdog for hard interruption; checks
reject late results but do not cancel blocked kernel/library work.

Complete target runtime policy, separate grant authority, protected CA install
capability/reservation and namespace ownership, actual trust installation,
egress canaries, recovery and production verification remain separate gates.
The original [local request preparation](workload-identity-bootstrap.md),
[native grant](native-workload-identity-issuance-authorization.md) and legacy
packet-bound provisioning profiles are not redefined by this local path.
