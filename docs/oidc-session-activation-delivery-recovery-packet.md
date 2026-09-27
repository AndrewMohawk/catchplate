# Consume recovery packet decoding

`authority_oidc_session_activation_delivery_recovery_packet.py` decodes the
dedicated consume packet without granting historical admission or execution.
It preserves the neutral outer packet schema and framed identity domain; generic
recovery decoding and generic plan replay remain closed to consume originals.

`_decode_on_work(packet_bytes, expected_packet_digest=...,
expected_pending_decision_digest=..., work=...)` first holds the immutable packet
and both independently supplied identifiers. It checks the packet identity before
bounded parsing, canonical encoding and source-fixed consume shape checks. A
stored packet never supplies its own expected packet or pending identity.

The exact nine original fields are `currentRootEnrollment`, `grantEnrollment`,
`grant`, `reserveRequest`, `reserveReceipt`, `computationSnapshot`,
`callerEnrollment`, `callerAuthorization` and `plan`. The last is exactly two
frames: signed consume plan and encrypted consume originals. The eight controls
use the actual producer's caps and order. All frame lengths and the whole decoded
inventory are bounded before any base64 body is allocated; the canonical outer
packet and raw-original aggregate each retain their 64 MiB ceiling. Actual
decoding and hashes charge the same supplied work. Ciphertext framing is checked,
but no bundle is decrypted.

The detached `_RecoveryDeliveryPacket` exposes the ordinary payload, raw2
`originals`, current-root `enrollment_bytes`, `grant_enrollment_bytes`,
`grant_bytes`, `reserve_request_bytes`, `reserve_receipt_bytes`, `snapshot_bytes`,
`authorization_enrollment_bytes` and `authorization_bytes`. Effects, vectors,
marker and original interval pass structural bounds only. No successful result
of this decoder is accepted as authority; a completion consumer must genuinely
authenticate original controls and replay proofs under independent keys/scope,
then compare the same-call effects, vectors, marker and interval.

There is no clock, lifetime renewal, SQL, signing, storage mutation, key input,
plaintext release, retry or currentness claim. The source is unbuilt and
unexecuted; this module alone closes no runtime or production gate.
