# Measured credential holders and one-shot drain barriers

This is a source-connected architecture, not a built, provisioned or exercised
runtime claim. A control-plane SELECT cannot revoke a credential already cached
inside a gate, and a five-second lease or a timeout cannot prove that every
holder stopped sending. This profile therefore records the actual measured
holders before secret release and requires their explicit drain acknowledgements.

## Explicit cold selection and original evidence

`catchplate.nativeStartupConfiguration/v4` adds required `credentialCurrentness`
with exactly `profile: "measured-holder-barrier-v1"` and `deploymentId` to the
existing v3 shape. The original configuration digest is part of the actual
native role-4 key scope. Versions 1–3 remain unchanged; no environment switch,
ordinary UDS hello, caller key, or locally ephemeral signer substitutes for the
native owner. The [paired schema](../schemas/native-startup-configuration.v4.schema.json)
describes the closed data shape; the actual source additionally enforces original
byte bounds, protected inputs, URLs, tokens, certificate/pin relationships and
the unchanged native lifetime.

The independently signed authority configuration must assign this exact holder
boot/key, control-plane key, deployment, release, policy, configuration, CA,
binary and Nitro PCR/EIF/module expectations. It also supplies the genuine
attestation roots and current-purpose operations. Gate configuration alone is
not that assignment. An ordinary application may use this genuinely measured
gate; this does not admit an unmeasured ordinary custody profile.

Every controlled operation also carries the configuration digest from the
actual retained control-plane custody owner, independently matched by the
authority policy and retained in the protected holder record. Strict leases,
acknowledgements and barrier membership refuse a different current custody
configuration; changing configuration does not migrate or rejoin old holders.
This internal provenance pin does not change the native statement or lease wire.

`catchplate.nativeCredentialCurrentnessStatement/v1` has exactly 18 fields.
Its Ed25519 signature covers its schema, one NUL byte, and sorted compact
Python-compatible ASCII JSON (including escaping DEL), without a trailing LF.
The evidence envelope has only `statement`, `signature` (`ed25519:` plus
canonical base64url), and original `nativeKeyEvidence`. A fresh genuine role-4
quote binds the dedicated currentness domain, authority-recorded challenge,
exact statement hash and signature. The existing response-signing and recipient
profiles are not relabeled. Native custody remains in the gate's address space;
this adds no intra-process isolation claim.

## Registration, leases, and local send authority

A genuinely new credential activation creates its never-issued version root in
the same controlled transaction, before any strict secret lease. Existing
credentials without this root refuse the profile; absence of a record is not
evidence that old leases do not exist. Authenticated migration remains unfinished.

The fixed authenticated endpoint `/api/data-plane/credential-currentness` accepts
only challenge, register, acknowledge and SELECT-only poll phases. Quiesce and
admit are retained cold-client operations, not public HTTP actor permissions.
Each actual writer result is verified through the existing custody/authority
receipt path and compared with its protected original rows. HTTP replies retain
the existing nonce-bound control-plane response proof.

The additive `catchplate.nativeCurrentCredentialLeaseRequest/v1` wraps the
unchanged native inner request as `leaseRequest`, plus `currentness`:

- Metadata uses null. Its response context contains only credential version,
  epoch and root digest; observation does not register a holder or permit sends.
- Secret dispatch requires holder ID, epoch, registration digest and a signature
  over the complete actual inner request, including recipient key, quote, nonce
  and any original release authority. Verification uses the exact registered
  native key, so a holder ID cannot authorize a different recipient by itself.

`catchplate.nativeCurrentCredentialLeaseEnvelope/v1` similarly wraps the actual
existing encrypted envelope. Metadata may return a newly refreshed version;
the gate must register that version before requesting its secret. Secret replies
echo the exact signed currentness pin. Existing inner AAD/encryption and old
profile bytes are unchanged. Strict control-plane selection refuses a bare
legacy/enrolled lease; there is no attempted-request fallback.

The hot send path remains database-free and network-free: it checks the actual
local holder map while retaining the existing upstream dispatch permit. Secret
cache insertion repeats this check under the existing mutation lock. No response
observation or stale cached generation is promoted into currentness authority.

## One-shot quiescence and completion

The protected quiesce transaction closes new membership/lease admission and
freezes the complete ordered holder set for this credential version. The scoped
native background task polls signed observations. On a matching barrier it:

1. Irreversibly blocks that version locally, including all cached scopes.
2. Acquires the actual dispatch mutation guard, waiting for already-held send
   permits to drain within the original deadline; clears all matching secret
   and generation cache entries.
3. Retains that guard while obtaining and signing a fresh barrier-bound challenge
   and submitting its one-shot genuine native acknowledgement.

Only the controlled writer can admit the exact barrier after every frozen holder
acknowledges. Refresh claim then atomically consumes it; refresh commit creates a
separate N+1 root with its predecessor barrier digest. Cleanup uses its distinct
actual signed-purpose owner and original allowance; a retained consumed barrier
can only be reused when its exact original refresh claim and still-current
version join. It never reopens membership or grants provider effects by itself.

The gate retains at most 64 version entries in this first profile; originals,
HTTP replies and evidence are bounded. It never deletes membership, resets an
epoch, automatically rejoins, repeats uncertain registration/ack mutations, or
counts time passing as acknowledgement. Poll failure blocks local sends without
inventing an acknowledgement. An unreachable/dead holder can permanently block
the one-shot barrier. Explicit recovery, holder retirement/capacity lifecycle and
existing-credential migration remain required follow-ons, not completed product
scope. Already dispatched provider effects are not retroactively undone. Original
request/native lifetimes are clipped, never renewed, and blocked kernel calls
still require the existing outer hard watchdog.
