# Durable recovery acquisition boundary

The recovery acquisition records are a separate, token-free journal family.
They do not extend the LIVE consume stage grammar, grant release permission or
prove that a durable private outcome exists. Existing activation and consume
originals remain unchanged.

## One claim per independent policy

The fixed client/journal method
`claim_oidc_session_activation_recovery_grant_attempt` receives four canonical
digests: retained finalization, activation authorization association, original
release intent and independently authenticated issuer policy. Their framed
identity selects the irreversible recovery acquisition slot. The journal also
binds the exact retained intent-record digest, selected internally rather than
supplied as an admitted authority object.

Before publishing the claim, the journal rereads the original activation and
consume claims plus the bounded intent record. It checks the actual intent
original's existing framed identity. This is local content/association checking,
not a second signature admission or proof of protected execution.

The caller must finish genuine fresh actor and independent policy admission,
precharge `MAX_CLAIM_IO_BYTES` and the bounded hash work, then guard the fixed
claim callback before any issuer contact. Every duplicate same-policy claim
fails, including an identical claim recovered after process restart. Recovery
does not repopulate the in-memory continuation set. An explicitly fresh,
independently authorized policy has a different slot; this is not permission to
automatically retry under the previous policy.

## Exact original retention

`append_oidc_session_activation_recovery_grants` receives the same four scalar
identities and immutable original raw3: client authorization, recovery server
bootstrap and canonical outcome. Only the owner that successfully published the
new claim may append once. Neither identical replacement nor resumed publication
under a recovered claim is accepted.

The codec bounds opaque frames at the existing 16 KiB / 16 MiB / 64 KiB caps;
it does not parse grant JSON or authenticate a successful result. The current
caller obtains the triple from the genuine `.204` admission path before durable
retention. This slice therefore does not claim to preserve malformed or otherwise
unadmitted issuer replies. Its genuine callsite never supplies token, cookie,
assertion or recovery request frames to this journal family.

The actual caller precharges `_append_io_bytes(originals)` and bounded hashes
before the stable append callback. Publication uses the existing exclusive
immutable-file/readback/fsync path. Quota and logical-record limits are shared
with the existing journal; one recovery acquisition consumes one logical slot
and at most two physical files within the unchanged physical ceiling. Capacity
or publication uncertainty is terminal, not an excuse to contact the issuer
again. The claim remains consumed even when no response was retained.

## Bounded historical reads

`load_oidc_session_activation_recovery_inputs` directly charges the original
work and selects only five admitted-index records: activation claim, consume
claim, release intent, proof raw4 and completion-hints raw2. Actual immutable
sizes bound the selected reads before body allocation. It never loads the full
consume prefix or its prepared/exported ciphertext. Missing required originals
return unavailable, not fabricated success or retry authority.

`load_oidc_session_activation_recovery_grants` selects only one policy slot's
claim and optional exact raw3. Its ordinary immutable return is history, not an
input accepted as authority. Both readers retain the supplied original guard;
that guard must not recursively select records or reacquire the journal I/O lock.

Constructor recovery admits fixed filenames, exact codec framing, bounded
metadata and immutable identities. Unknown/temporary files fail closed. No
cleanup removes claims or recycles their authority. Local fsync and file
identity checks do not provide an independent rollback witness or exclude a
privileged writer.

This source slice is unbuilt, unexecuted and unprovisioned. It does not stage a
recovery worker, read its outcome store, open a token, perform protected recovery
or expose a public recovery/cookie endpoint. No automatic SQL retry is permitted.
