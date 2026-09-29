# Authorized admin-token publication resolution

This source connects a separate, narrowly authorized terminal-observation path
for an intact interrupted [generated-admin-token publication](control-plane-approval-verification.md#protected-generated-admin-token-publication).
It does not replay token publication, recover token plaintext, or establish a
tested deployment. The owner is
[`control_plane_admin_token_resolution.py`](../serverware/control_plane_admin_token_resolution.py);
the actual HTTP route and strict request model are in
[`app.py`](../serverware/app.py), and the predecessor-chain reader remains in
[`control_plane_admin_token_publication.py`](../serverware/control_plane_admin_token_publication.py).

## Public contract and fresh authority

`POST /api/control-plane/tokens/admin/publication/resolve` accepts exactly these
five required fields; unknown fields are rejected:

| Field | Contract |
| --- | --- |
| `publicationId` | The original attempt's 32 lowercase hexadecimal characters. |
| `intentSha256` | `sha256:` followed by 64 lowercase hexadecimal characters; must match the retained original intent. |
| `outcome` | Exactly `finalize-installed` or `abandon-uninstalled`. |
| `reason` | Required, but nullable; a string is at most 500 characters. |
| `mfa` | Required object carrying the actual assertion and approval association; its retained canonical original is bounded to 16 KiB. |

The distinct action is `control_plane.token.publication.resolve`, with resource
`admin-token`. Its payload binding contains exactly `token: "admin"`,
`publicationId`, `intentSha256`, `outcome`, and `reason`; the existing canonical
payload-digest helper binds the human approvals to those values.

This purpose always requires genuine fresh WebAuthn for the requester and a
different administrator approver, even where unrelated mutation policy makes
MFA or two-person approval optional. Existing rotation policy is not broadened.
The resolver invokes the actual requester verifier, requires user presence and
verification, and checks the live credential and action/resource/payload-bound
challenge. Caller-supplied authority metadata is not a successful-verification
substitute. The existing approval path verifies the approver and the resolver
consumes the matching one-use row in its own durable transaction. The row must
identify the same requester and a different approver with a WebAuthn credential.

The owner freshly authenticates the retained request and checks administrator
role and CSRF. It retains the request, exact binding and MFA bytes, policy,
actor, credential, PID/thread, and protected file originals. Its initial maximum
30-second wall/monotonic processing interval is sampled when the owner opens,
after framework body/dependency processing. That interval is only narrowed to
the actual requester challenge and consumed approval expiry. It is not renewed
after a filesystem or database operation, and it cannot preempt a blocking call.

## Two admissible observations

The resolver takes the same nonblocking exclusive parent-directory lock and
then protected journal lock as the publisher. It opens the existing journal;
it does not create or reconstruct one. Only the unique intact unresolved tail
with the exact requested intent and no previous resolution claim is eligible.
The selected records and token file are retained by descriptor, exact bytes,
named/held identity and secure ownership/mode checks, not by an inspection DTO.

| Outcome | Required actual observation |
| --- | --- |
| `finalize-installed` | The original publication has a claim, its staged `.new` pathname is absent, and the current token matches both new-file and new-token hashes and the retained staged file's rename-stable identity. If an original completion exists, its full installed identity must also match. |
| `abandon-uninstalled` | There is no original completion; the staged `.new` original remains intact, while the current token exactly matches the previous file/token hashes and full previous-file identity. The staged descriptor must still match the intent's new-file identity. |

Neither outcome performs a rename, token generation, token-file write, deletion,
rollback, or resubmission. In particular, finalization does not repeat an
uncertain rename, and abandonment leaves the retained staged secret in place.
Malformed, partial, orphaned, branched, conflicting, or already-claimed
resolution histories are refused rather than repaired. A missing published
token is not regenerated.

## Append-only completion and uncertainty

The original publication's intent, authorization, claim and any completion
remain unchanged. Three new record kinds form a separate resolution chain:

1. In an owned durable metadata transaction, consume the exact approval and
   append `control_plane.token_publication_resolution.authorized`, keyed by
   `admin-token-resolution-intent:<publicationId>`. Before leaving that
   transaction, create-exclusive and flush `resolution-claimed`, binding the
   original intent, chosen outcome, current file, approval and any prior
   completion. This is an irreversible one-shot guard, **not evidence that the
   database commit succeeded**.
2. Only a definitely returned first commit permits completion. Recheck and
   fsync the held originals, token parent and journal, including the case where
   the original rename stopped before its directory flush. Append
   `resolution-complete` with the exact claim digest, intent, outcome and actual
   file hash/full identity. No token bytes are changed.
3. Commit `control_plane.token_publication_resolved` in a second owned durable
   transaction, keyed by `admin-token-resolution-complete:<publicationId>`.
   Only its definite return permits `resolution-settled`, which links that audit
   identity to the completion digest. Re-read the exact terminal history and
   retained originals before success.

The transactions retain the publication owner's local SQLite WAL/FULL or
PostgreSQL synchronous durability requirements. A crash, expiry, uncertain
first commit, or later failure after `resolution-claimed` leaves the attempt
consumed and blocks another resolution. A completion without settlement also
remains blocked. Neither a claim nor a successful-looking diagnostic establishes
committed approval or audit settlement; there is no automatic retry endpoint
for these ambiguous states.

Only a fully settled resolution can anchor a later, independently authorized
rotation. Its predecessor is the `resolution-complete` digest plus the observed
file hash and full identity, not a rewritten original publication completion.
The old records and secret originals remain retained. The journal is bounded
to 64 attempts and ten fixed file kinds per attempt, 16 KiB per metadata record
and 256 bytes per token original. Resolution does not reset that capacity or
authorize archival/pruning.

## Result, inspection and operator boundary

Success is the closed seven-field response:
`schema: "serverware.adminTokenPublicationResolution/v1"`, `ok: true`,
`publicationId`, `intentSha256`, `outcome`, `resolutionCompletionSha256`, and
`automaticRetryAllowed: false`. The route sets no-store/no-cache response
headers. It never returns the old, new or current token. Non-authentication
owner failures are reported as refusal or uncertainty with an inspection
endpoint; an absent response does not authorize repeating resolution.

`GET /api/control-plane/tokens/admin/publication` remains read-only and
data-only. Its observation/v1 rows now include the resolution phase and
`resolutionOutcome` (null before resolution). They do not grant authority or
prove a request may be replayed.

If publication installed a token whose plaintext was lost, resolution does not
recover it. An independently usable administrator identity, such as a separately
configured OIDC administrator, plus the required authenticators and distinct
approver must still be available. Existing authentication and CSRF policy is
not bypassed to regain access. Host inspection of protected records is not a
substitute for this public authorization or permission to rename/delete secrets.

This is source-connected local resolution only: no runtime/test claim, generic
provider recovery, policy-publication recovery, malformed-history repair,
multi-host coordination, independent rollback witness, or archival authority is
established. Those boundaries remain separate from this fixed-purpose path.
