# Private release dispatch claim

This is source-only local uncertainty control, not release permission or a
receipt. The dedicated codec stores only the exact client-authorization digest,
request identity, live/recovery profile, server-bootstrap digest, expected
outcome digest and original source revision. It stores no request or response
frames, old/new tokens, ciphertext, signing key or AES key.

`ControlPlaneCustodyClient.claim_oidc_session_activation_release` accepts those
five independently admitted identity/profile arguments as keyword-only scalars
and returns `None` only after the actual journal publication and byte readback.
The configured caller must first authenticate the root client original and exact
request, charge `MAX_CLAIM_IO_BYTES` on its original work object, then invoke the
claim through the stable native callback before any socket exchange. It retains
its original current guard before and after the claim; a claim is not authority
to send after that guard expires.

The journal uses the separate `release-client-claimed-<authorization-digest>`
namespace. It is not a prepared business-record family and cannot be forwarded,
observed or reconciled by generic custody transport. The maximum record is 395
bytes. Claims share the existing logical record limit with prepared records,
the existing physical-file ceiling and quota; reserved legacy marker capacity
is not consumed.

The exact client-authorization digest, not the request identity, is the slot key.
Every existing claim rejects another exchange under that root authorization,
including after restart and even when all metadata agrees. A separately issued
fresh root authorization may explicitly permit an exchange of unchanged
historical originals, including recovery after an uncertain recovery exchange.
No code here reissues root authority or automatically retries.

The actual journal lease, process/directory identity, no-replace publication,
file and directory `fsync`, normal close and exact byte readback precede success.
Publication or readback uncertainty poisons the owner; a published record is
never removed. Restart performs the existing bounded recovery scan and restores
claims before use. Unknown or temporary files fail closed. Neither a claim nor
its absence establishes remote execution, durable release, delivery or current
session state. Local storage still depends on the provisioned filesystem and
does not provide an independent anti-rollback witness against privileged
replacement. No provisioning or runtime verification is claimed.
