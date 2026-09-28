# Completion-to-intent hints

The explicit consume caller `/v4` and independently signed completion-service
launch `/v3` connect a same-context release-intent candidate. This is source
integration, not a completed protected handoff or production verification.

## Closed wire and retained originals

The fixed completion socket and root listener peer stay unchanged. Request
`SWODCM03` carries the existing purpose and exact signed consume authorization.
The service compares that original to its root-held authorization before using
its independently pinned packet. Response `SWODCR02` has six frames:

1. The unchanged four completion frames, including signed complete/state
   originals on acknowledgment.
2. An unsigned packet-digest hint, exactly 71 ASCII bytes on acknowledgment.
3. A canonical descriptor of at most 1,024 bytes with exactly `schema`,
   `effectsDigest`, `deliveryEnvelopeBase64Url`, `createdAt`, and `expiresAt`.

The descriptor schema is `serverware.oidcSessionActivationReleaseHints/v1`.
Its encrypted envelope decodes to the existing exact 100-byte format, never a
plaintext credential. Dates retain their canonical original UTC spelling and
the existing maximum delivery lifetime. Uncertainty is `uncertain` and five
empty frames. All lengths and the whole exchange are bounded before body
allocation. The tenth literal guarded transport preserves the original work,
deadline, peer checks, exact EOF and terminal close behavior.

The caller retains the original raw4 completion record and then the separate
raw2 hints record before interpreting the result. Existing raw4 encodings stay
unchanged. Failure between those writes leaves an incomplete, non-resumable
prefix; neither recovery nor missing intent output authorizes a retry.

## Hints are not authority

The completion owner derives hints from its same root-pinned packet read,
including the retained-completion branch. It projects the encrypted delivery
row and hashes the exact selected rows, mutations, result and work-unit count
using the existing effects identity codec. This is an additional bounded
decode/hash, not another private historical replay, database read, key grant
or plaintext export.

The public caller cannot independently reconstruct those private effects or
the inner encrypted delivery row from signed completion controls. It therefore
uses the hints only as candidate expectations in a fresh intent, together with
its own exact request, target, possession and authenticated completion/vector
bindings. Neither the completion/state signatures nor the intent signature
authenticates the hint-to-packet relationship.

The existing private committed/proof verifier must independently recompute
packet/effects identities, authenticate the actual commit and completion, and
compare the complete release target and ciphertext. A changed hint must fail
there; it cannot authorize credential opening, current-session claims, retry
or cookie issuance. This avoids a redundant new root target grant without
weakening the existing private proof requirement.

## Explicit profile selection

Legacy launch `/v1` remains private selector/raw4; `/v2` remains original-bound
dispatch/raw4. Neither accepts the new magic or response. `/v3` keeps worker
UID/GID65497, peer65532 and the same eight inherited resources; only the signed
profile selects raw6. The optional uninstalled `release-v3.conf` socket drop-in
matches that launch. It is not selected by request bytes or installed here.

Parent `/v9` separately delivers the dedicated intent signer at FD207 through
the [cold intent configuration](control-plane-oidc-session-activation-release-intent-bootstrap.md).
The optional `docker-compose.oidc-session-activation-release-intent.yml` mounts
only that pre-provisioned key, not private history, root or proof signing keys.
Private proof production, post-intent exact server/client grants and actual
protected socket handoff remain separate integration work.
