# Measured holders and irreversible credential-version barriers

This source implements protected `credential.currentness.challenge`,
`register`, `quiesce`, `ack`, and `admit` transitions. It is source-only:
unbuilt, unexecuted and unprovisioned. Its data
[schema](../schemas/credential-currentness-authority.v1.schema.json) is not an
authority grant or evidence of a successful live drain.

## Independent permission and measured originals

The actual independently signed measured configuration must carry
`credentialCurrentnessPolicy`, schema
`serverware.credentialCurrentnessAuthorityPolicy/v1`. Its exact seven fields
are schema, deployment ID, control-plane configuration digest, original
operation maximum (1–30 seconds), fixed maximum holder inventory (64), native
trust roots, and independently assigned holders. The verifier and planner each
admit their own configuration and verify the original proof before SQL or
persisted-plan admission. Merely having an application enrollment, UDS hello,
configured boot string, response receipt or caller-supplied root grants no
holder authority. Ordinary applications may use this measured native gate;
an unmeasured ordinary gate is not relabeled native.

Each independently provisioned assignment fixes the real boot ID, Ed25519 SPKI
identity, control-plane signing SPKI, release/policy/configuration/CA scope,
binary expectation, complete PCRs, EIF, module and bounded quote age/skew.
The policy also carries original canonical native Nitro CA certificates and
the fixed native certificate profile. No network root lookup occurs. The
native profile has an empty CRL inventory and does not claim vendor-CRL
revocation checking. Independent current release/PCR admission must establish
the binary expectation's meaning; it is not an extra signed NSM field.

The envelope is exactly `statement`, `signature`, `nativeKeyEvidence`.
The eighteen-field statement has profile
`serverware.nativeCredentialCurrentnessStatement/v1`, phase `register` or
`ack`, exact credential/version/epoch, independently assigned holder/boot/key,
one-use challenge, deployment/policy/binary and original time bounds. Epoch
equals credential version. Barrier ID/hash are null only for registration.
Signature is `ed25519:` plus canonical base64url of the signature over the
statement schema, NUL and sorted Python-ASCII JSON, including escaped DEL.

The holder ID is SHA-256 of
`serverware/credential-currentness-holder/v1\0`, boot32 and SPKI-SHA32.
The actual role-4 raw Ed25519 NSM document is verified using the unchanged
COSE/chain/PCR implementation. Its nonce is SHA-256 of
`serverware/credential-currentness-attestation/v1\0`, challenge32,
SHA-256(statement ASCII) and raw signature64. The wrapper enforces the original
role-4 key userdata, boot/CP-key commitment and quoted public key. A copied
success object cannot substitute for this original verification.

## Protected membership, never a timeout inventory

Four source-keyed protected relations retain roots (11 columns), holders (17),
challenges (17), and barriers (13). The metadata owner maintains their real
primary roots; no runtime DML grant is added.

The internal authority request has exactly credential ID, credential version,
request, and `control_plane_configuration_digest`. Only the actual retained
cold custody snapshot produces that digest; both independent admissions require
equality to their signed policy pin. Registration retains it in the protected
holder row and every strict lease checks it against the actual startup owner.
A changed configuration cannot silently use, acknowledge or readmit an old
registration. Native statement18 and the public wrapper remain unchanged;
there is no caller-selected configuration authority or automatic migration.

New OAuth activation atomically creates version-one strict currentness root
alongside the new credential, generation, consumed approval and audit, before
any lease can exist. An older credential without this root is refused: an
empty present-day holder query cannot prove that an old lease was never issued.
There is no lazy migration or reinterpretation of an older envelope profile.
Authenticated migration remains required work.

1. A source-selected cold controlled-custody caller commits a fresh challenge
   for an independently assigned holder and actual current credential/head.
   Registration requires the genuine native proof and consumes that exact
   protected challenge. The immutable registration original and raw proof key
   remain retained; a holder string alone cannot obtain a secret lease.
2. Quiesce serializes against the same protected root, blocks registration and
   new strict lease issuance, and freezes the complete sorted membership set.
   Completeness is checked by reconstructing the holder primary root against
   the same transaction's authenticated before-root, not by `COUNT(*)`, a
   truncated list, a local cache, a five-second TTL or an absence assertion.
3. Each frozen member acknowledges the exact immutable barrier under its real
   native owner and a fresh protected challenge. The paired gate must acquire
   its actual dispatch mutation owner, drain active sends, purge all cached
   scopes for that credential/version and permanently block that epoch before
   producing the sealed acknowledgement. An acknowledgement from a different
   boot, key, version, barrier or challenge is rejected.
4. Admit reconstructs the same complete holder inventory and requires a
   retained exact acknowledgement from every frozen member. An unresponsive
   holder blocks. No timeout, expiration, new grant, missing process or new
   configuration removes it. Empty membership is valid only under the genuinely
   new, never-issued strict root and complete-root proof.

Root state only advances `open` → `quiescing` → `admitted` → `consumed`.
The immutable eight-field barrier commits credential/version/epoch, exact
five-field frozen holder entries and original interval. Changing mutable
status does not change that original digest. Challenges and acknowledgements
cannot be replayed or used to rejoin a drained epoch. Unknown or expired
operations remain consumed/blocked; there is no retry, reset, deletion or
reconstruction-based success.

## Effect and lease integration

The barrier proves the selected local inventory drained; it does not itself
authorize refresh, revocation, family retirement or another provider action.
`oauth.refresh.claim` now requires an exact twelfth field,
`currentnessBarrierSha256`. Its existing due-only policy independently
authorizes refresh, while the actual claim atomically consumes the admitted
barrier with retained-material capacity and the refresh reservation, before
contact. Retain and commit require the consumed barrier's exact claim digest.
Successful refresh commit creates a separate never-issued N+1 strict root;
it never reopens N. The existing 27-column refresh original remains unchanged.

Separately authorized family-retirement kernels may consume a newly admitted
barrier using the fixed `effect_queries`/`consume_barrier` interface. Historical
`require_consumed_refresh_barrier` checks do not prove that a newer active
generation is drained, and never renew a contact deadline. A cleanup that
drains the current version cannot reset it; authenticated reconnect is a
separate required successor. Unequal token bytes do not prove provider grant
isolation, nor does a complete local inventory establish cross-deployment
ownership.

Activation and every refresh phase also reconstruct the separately protected
`oauth_family_retirements` population and refuse an actual provider/verified
subject fence derived from the retained metadata. The query does not accept a
caller-supplied subject or pretend a primary-row observation proves absence.
This permanent local fence is not proof of pre-subject provider issuance or
external/cross-deployment population completeness. Its 32-row complete-table
bound keeps four populations plus original assertion rows inside the unchanged
256-proof ceiling; other inventory tables retain their 64-row bound. No history
is pruned to make room.

The paired strict lease wrapper must bind the real admitted holder key to the
entire original lease request, and check the open root, unchanged head and
registered member before and after secret release. Late-arriving old responses
cannot bypass the gate's permanent epoch block. Metadata-only responses do not
authorize sends. Old profiles remain byte-for-byte distinct and cannot be
served as a fallback for strict credentials. HTTP responses and SELECT-only
projections remain data until the actual nonce-bound signed response and
retained owner checks succeed.

The initial bounded population contract is 64 rows per complete holder or
challenge table, including retained history; it is an explicit temporary
capacity limit, not permission to prune. Arguments are capped at 64 KiB,
evidence at 32 KiB, row originals at 128 KiB, trust roots at 128 KiB and signed
policy at 512 KiB. Existing cumulative proof-work, response, configuration and
operation bounds can refuse earlier. Challenge and barrier windows are at
most 30 seconds and never renewed. Larger-population acquisition, protected
archival/migration, independent service provisioning and full live validation
remain required; this source is not production or pilot evidence.
