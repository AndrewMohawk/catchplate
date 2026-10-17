# One-shot private committed-release proof service

This is a source-only private worker connection: unbuilt, unexecuted and
unprovisioned. It produces an original committed-release proof, not a plaintext
token, release outcome, session-currentness claim or public HTTP response.

The [root bootstrap and entrypoint](oidc-session-activation-release-proof-service-bootstrap.md)
admit a separate per-intent worker with seven inherited descriptors: public
root, original bootstrap, listener, dedicated proof signer, and the three
existing historical-custody keys. The same process permanently drops to
UID/GID 65497, with no supplemental groups and the existing fixed completion
process mode. There is no completion signer, completion journal, state client
or SQL-write owner in this service.

`oidc_session_activation_release_proof_startup.initialize_from_environment`
requires the actual inherited `work`, `live_window`, `transport_deadline_ns`
and root-delivery `delivery_current` guard. It does not allocate a replacement
allowance or open another clock window. Its private owner admits the original
historical custody and constructs only the fixed packet recovery reader and
commit reader. Sealed input identities, listener/path pins, original TLS files,
reader configurations, process identity and environment remain checked.
The signed request timeout tightens that original window from its original
epoch anchor before key/custody construction or socket waiting; it is never a
new timeout starting when a later phase begins.

## Fixed private exchange

The separate socket is
`/run/catchplate/oidc-session-activation-token-release/proof.sock`. The service
checks the actual Unix peer UID/GID 65532 before reading even the request
header. The client expects the root-created listener peer, UID/GID 0.

Request magic `SWORPQ01` selects exactly three length-prefixed byte frames:

1. `prove-oidc-session-activation-release`;
2. the exact canonical 71-byte identity of the independently pinned intent;
3. the original 64-byte old token, held ephemerally for possession verification.

The request must end at exact EOF. Header and complete body bounds are checked
and charged before allocation. A launch is spent before its sole accept; a bad
peer, timeout, malformed request or missing possession does not permit another
accept or production attempt.

Response magic `SWORPR01` carries raw4:

1. `proved`;
2. the exact root-signed release-custody original, at most 8 MiB;
3. the exact signed proof, at most 64 KiB;
4. the exact proof enrollment, at most 16 KiB.

The response framing helper deliberately accepts only bounded immutable bytes;
it does not authenticate status, custody, enrollment or proof. The receiving
caller must retain its exact raw4 before interpreting it and independently
admit all relevant originals. Socket credentials and successful local send are
not proof admission or an acknowledged protected credential handoff.

## Actual production and terminal boundary

The worker compares the request intent identity with its root-held original,
reads the independently pinned packet using the actual read-only recovery
reader, and calls
`authority_oidc_session_activation_release_proof_production._produce_on_work`
once. That producer genuinely admits intent/enrollment and old-token
possession, authenticates the original release target, performs the existing
committed-original verification with private historical custody and a normally
closed commit read, and signs only those same-call derived facts. It also
authenticates its exact signed output before returning bytes.

The optional private producer continuity hook exchanges only increasing epoch
and monotonic floors with the actual worker. It cannot replace originals,
skip admission or reset work. Returned floors must remain strictly inside the
producer's current narrowed deadlines. The worker keeps its root-delivery,
bootstrap and custody guards, narrows to the actual proof expiry, and uses the
same allowance through every send chunk and normal connection close.

There is no error/uncertainty frame, retry, token regeneration or second request
on an old completion worker. Failure is terminal and cleanup failures remain
truthful; cleanup never closes an identified replacement descriptor. The old
token is never retained in a journal or response. Historical decryption stays
within its existing private custody purpose; this worker never opens the
release envelope. Independently operated per-intent root issuance, matching
worker provisioning, protected token release and public caller handoff remain
separate requirements.
