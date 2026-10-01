# Late native launch authorizations

The `.381` source batch connects 31 missing prerequisites before the ten native
endpoint launch installers. Supervisor coverage is **116/136**, with **20
decisions remaining**. The startup guard still refuses, source checkpoints stay
**36/46**, and production acceptance remains **0/6**. The larger job inventory
corrects missing dependencies; it is not a product-readiness percentage.

## Fixed sequence and actual inputs

Service jobs 79–109 run in the existing ten-role order. Every role has closure,
encrypted-delivery and verifier-transport authorizations. CommitRequest also
has a separate request-commitment authorization immediately before its encrypted
delivery. Each job has its own approval and makes exactly one signature.

| Authorization | Independent selections | Authenticated prior inputs |
| --- | --- | --- |
| Closure | Original UNIX interval | Actual C9 Guest13, observed executable, signed assignment/trust and exact closure-set member |
| Request commitment, CommitRequest only | Provisioner's public secret descriptor and original interval | Actual role-key/admission pair, signed assignment's commitment key ID/epoch and distinct authority identities |
| Encrypted delivery | Provisioned KMS transport/ciphertext commitments and original interval | Actual C9 encrypted-inventory metadata and role-key/admission pair; CommitRequest also requires its actual preceding signed descriptor |
| Verifier transport | Parent port and original interval | Actual role-key/admission pair and assignment-authenticated verifier/supervisor keys |

The complete original inputs—not substitute payload summaries—are retained and
reverified at every continuation. No future guest, secret, ciphertext, KMS
response, Nitro verdict or successful launch is synthesized. Transport digests
bind independently provisioned material but do not prove that material exists
or that KMS will release it. C9 ciphertext metadata must match the selected
encrypted inventory and contain no plaintext role-key slots.

## Explicit independent policy

`serverware.nativePilotSupervisorCommissioningPolicy/v11` adds only the literal
`nativeLaunchAuthorizationsOriginal` to v10's eighteen fields. Its purpose is
`initial-driver-bootstrap-precreation-endpoints-generations-and-native-launch-authorizations`.
The outer 4 MiB bound remains. The nested fragment is bounded to 256 KiB and
has exactly `apiVersion` (`serverware.nativePilotLaunchAuthorizationPolicy/v1`)
and `endpoints` with ten closed role rows.

Each row has `closure`, `encryptedDelivery` and `verifierTransport`; CommitRequest
also has `requestCommitment`. All operations select their original UNIX interval.
Encrypted delivery additionally selects `transportOriginal`, verifier transport
selects `parentPort`, and request commitment selects the literal three-field
descriptor `requestCommitmentOriginal`. The last is public key ID/epoch/hash
metadata, never a secret. The policy and all actual preceding intervals remain
independently approved and unrenewed.

The coordinator has 108 fixed signing selectors. V1–v3 retain 42, v4–v7 retain
57 and v8–v10 retain 77; no older policy silently acquires these decisions. Every
new selector must match the supervisor key resolved through the actual signed
assignment and independent trust. Separate purposes do not mean generating
31 new keys.

## Producers and retained owner

The existing closure issuer shares pure preparation with its result verifier;
its live signing wrapper retains actual key and clock checks. The new
`native_pilot_encrypted_authority` supports separate `request-commitment` and
`delivery` operations. `native_pilot_verifier_authority` produces the existing
verifier-transport wrapper. Existing v3 closure, v2 HMAC, v1/v2 encrypted-delivery
and v1 verifier wire formats remain unchanged. Detached HMAC and encrypted
outputs retain 64 KiB limits, verifier output 32 KiB and closure output 1 MiB.

Their protected-FD CLIs require complete input bytes, exactly one matching
existing supervisor key, full output and successful exit. They do not provision
credentials or claim hardware custody. No late result is published by its
signing job; the existing launch installer later consumes the actual originals.

The supervisor owner accepts only the real coordinator and its opaque pending
request, fences failures without retry and retains at most 128 MiB. Earlier
completed-owner rechecks extend only through first launch job110,
`install-launch-retrieval`. Its handoff is read-only, not a launch composer.
The newest owner closes first, only after genuine terminal cleanup.

## Remaining work and evidence

The ten launch composers still need complete bundle construction and independent
time-bootstrap settings, with TrustedTime using its actual earlier signed
bootstrap bytes. Service-material publication, bridge configuration/delivery,
release, constructed admission, origin observation and shutdown decisions follow.
Executable supervisor packaging, approved immutable dependencies, provisioning,
independent services and connected application/provider/hardware acceptance
remain required. No newly generated hash replaces any of those authorities.

One focused assembled verification pass is pending. No actual signing entrypoint,
retained-owner acceptance, service, hardware, cloud or paid execution is claimed.
