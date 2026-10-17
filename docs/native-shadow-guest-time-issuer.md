# Independent native guest time issuer

This is the external issuer for the explicit pre-key native-guest time exchange.
It does not grant custody readiness, generate deployment keys, provision a
service, or prove a production time source. Source is unbuilt and unexecuted.
The tentative point-time anchor v1 is not accepted; the actual producer is
`catchplate.nativeShadowGuestTimeAnchor/v2`, carrying an uncertainty interval.

## Actual ownership and authority

`scripts/issue_native_shadow_guest_time.py` is a fixed no-argument isolated
Python 3.11 entrypoint. It consumes FD3 (the exact root:root0400 named original
`/etc/catchplate/native-shadow-guest-time-issuer.json`), FD4 (a separate 32-byte
issuer-identity-owned0600 unlinked memfd with all four seals), and FD5 (an actual
connected root-owned TCP stream). The latter must match the cold local IP/port
and peer IP. Protected ancestors, held-file identity/bytes, own PIDFD/start,
boot/time namespace, final nonroot UID/GID, no groups/capabilities, no dumps,
NNP and the retained socket identity/tuple are checked through the exchange.
Inherited descriptors are reserved before other opens. There is no connect,
listener, caller-selected path/key/root, or generic signing operation.

The independently provisioned cold config names three distinct authorities:
the signed-config authorizer, the time signer and the genuine C9 delivery root.
Its authorization commits the canonical whole config excluding only the
`authorization` field, under the separate time-issuance purpose. The signature
is checked before emitting a challenge and again before signing the anchor.
The retained seed's real public key must match the cold time key. Time keys use
SHA-256 of Ed25519 SPKI, not raw-key IDs; C9 retains its existing raw-key ID and
signature framing unchanged. Actual original C9 configuration/delivery bytes
are independently authenticated; their exact Guest13 is derived, not supplied
as a free caller identity. Signed credential keys cannot alias issuer keys.
The guest consumer separately enforces distinction from its full actual role
and assignment inventory and joins its actual process/FD/C9 owner.

File protection supplies retained cold provenance, not Nitro attestation.
The actual original COSE document is verified by the existing Nitro verifier,
including signature, chain, independently pinned complete PCR map, non-debug
PCR0/1/2, EIF, module, nonce, public key and user data. Current application-level
certificate denials remain explicitly not an AWS CRL. The external signing
process and independently managed wall clock are trusted-host authorities,
not relabelled TEE custody.

## Fixed exchange and time semantics

Each frame is an exact eight-byte tag, a big-endian u32 length, and canonical
ASCII/integer JSON without LF, at most 64 KiB including the complete JSON
envelope. Tags are `SWNGTC1\0` (challenge), `SWNGTE1\0` (one evidence), and
`SWNGTA2\0` (anchor). No request half-close is used: the actual parent relay
tears down both directions on its first EOF. The issuer sends a full result
and closes. Queued-extra-data rejection is not proof of future silence.
An incomplete handoff consumes its phase; there is no reconnect/retry API.

The issuer generates the nonce itself. The measured guest creates a one-shot
ephemeral Ed25519 key before any role-key admission, samples BOOTTIME before
and after its separate fixed-purpose NSM quote, and signs the exact statement,
after sample and quote SHA with that quoted key. NSM user data is
`catchplate/native-shadow-guest-time-evidence/v1\0` plus raw SHA-256 of the
canonical statement; NSM nonce is the issuer challenge and `public_key` is the
same ephemeral key. A caller's unsigned after-time cannot establish a bracket.

AWS documents the signed timestamp as UTC document-creation time in
milliseconds; it does not establish an exact guest clock sample or a public
clock-accuracy SLA. [AWS attestation specification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
The independent cold policy explicitly authorizes `timestampErrorNanos`
(0..1 second) and `maximumClockRateErrorPpm` (0..10000). These are deployment
trust assumptions, not facts proved by a signature. With signed timestamp T
in nanoseconds, measured bracket W and rate P, the interval at the original
before sample is:

```
E = 1 millisecond + timestampErrorNanos + ceil(W * P / 1,000,000)
[T - W - E, T + E]
```

The extra millisecond is conservative in either rounding direction. The guest
widens both ends further by `ceil(elapsedBoottime * P / 1,000,000)` and checks
the whole interval, not a midpoint or whichever end favors admission.
The original guest startup/lifetime remains absolute and unchanged.
Issuer arrival realtime is only a challenge/certificate/freshness input, never
substituted for the guest epoch anchor. Bracket width is <=1 second; the original
issuer operation/challenge is <=30 seconds; anchor expiry is <=300 seconds from
its earliest base and clipped to original authorization, keys, collateral and
certificate validity. Near-edge/uncertain intervals conservatively refuse;
an operator cannot repair them by relabelling a returned timestamp.

All time-purpose signatures use the existing exact framing:
`catchplate.signedEnvelope/v1\0` + domain +
`\0catchplate.canonicalJson/ascii-integer-v1\0` + canonical payload.
Domains are `catchplate.nativeShadowGuestTimeIssuerAuthorization.signature/v1`,
`catchplate.nativeShadowGuestTimeChallenge.signature/v1`,
`catchplate.nativeShadowGuestTimeSample.signature/v1`, and
`catchplate.nativeShadowGuestTimeAnchor.signature/v2`.
The schema owns closed config17, authorization6, challenge10, statement6,
evidence5, sample3 and anchor12; challenge/anchor have exact2 signed envelopes.

## Deployment boundary

An independent provisioner must supply the actual C9 originals, separate keys
and signed config, measured PCR/EIF/module expectations, pinned interpreter and
dependency/source closure, final external identity, inherited TCP endpoint,
the original external boot/window and an external hard process watchdog.
The code checks that same <=30-second window before/after all operations;
checks do not claim to cancel a stalled kernel or cryptographic call. Python
key-object copies are not claimed zeroized; the fixed issuer exits after two
purpose-fixed signatures, wiping only its owned seed bytearray.

No key is created or deployed by this source slice, and no image build, live
quote, time accuracy validation or end-to-end transport acceptance occurred.
Actual package/launcher deployment and the independently pinned time source
remain required. The guest's own consumer implementation must be composed with
this issuer; neither source nor a framed response substitutes for runtime proof.
