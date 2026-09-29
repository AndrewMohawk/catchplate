# Measured pending-retirement originals

This source component joins existing initial-issuance history to the exact
normalized pending credential. The
[controlled retirement kernel](measured-pending-family-retirement.md) calls it
on authenticated selected rows; the binder itself supplies no cleanup authority.

## Two different token originals

The measured exchange first captures a minimal issued-token envelope. Later,
after measured identity discovery and normalization, Stage creates a different
envelope and pending row and deletes the earlier revocation-work row.

The retained exchange's `token_secret_sha256` therefore commits the minimal
capture. The stage request's `tokenSecretSha256` commits the normalized pending
material. Cleanup must open the staged envelope under the pending ID/version
and compare the staged hash, not substitute the earlier capture hash.

`read_staged_pending` joins the exact exchange and measured-custody rows,
enrollment original, consent, claim, capture, stage and optional recovery
arguments. It reuses the actual stage-review predicates, preserves the original
pending expiry, and returns immutable public/ciphertext data. It never unwraps
a token, verifies a quote, selects a signer, or issues effect permission.

Historical request commitments contain their original operation manifest.
They are not reconstructed using the currently loaded manifest. Authenticating
those stored rows and any historical request/receipt belongs to the caller's
actual protected-state and historical-authority owners.

## Before a retirement claim

`current_pending_before_claim` compares the current row against the retained
initial pending row. Only lifecycle fields can differ; ciphertext, metadata,
identity, target, payload, review and expiry stay exact. A prior attempt, lease,
error or claimed state is not adoptable. An expiry reason requires actual
expiry under the supplied database time.

Both the returned record and its dataclass are data, not capabilities. The
controlled kernel must call the binder on authenticated selected rows and bind
those exact originals into a separately verified retirement grant. Receiving a
serialized record or constructing the dataclass never establishes authority.

## Actual caller integration and remaining scope

The authority/kernel path provides independent pending-retirement permission,
complete local family inventory, actual currentness drains for every affected
active credential, and one atomic pending/family/credential fence. A pending
credential has no fabricated refresh history or active
currentness root. An old consumed refresh barrier cannot stand in for a new
affected-lineage drain.

The [measured helper and native/control-plane callers](native-oauth-pending-retirement.md)
join those exact originals before decryption and one separately claimed provider
contact per selected token. They retain encrypted transport observations,
authenticated state receipts and no-contact recovery. These connections remain
unexecuted source, not runtime evidence. An accepted HTTP response is not proof
that a provider-wide family is invalid.

Pre-subject captured tokens are a separate unresolved case: there is not yet a
verified identity with which to construct the known-subject family scope. This
component cannot authorize their retirement, infer external ownership from a
token hash, or broaden a refresh-family grant. That branch remains part of the
full project, alongside setup, reconnect, migration and external coordination.

No builds, parsers, tests, cloud/provider calls or runtime checks were executed
for this component or its integration. Deployment dependencies and consolidated
post-freeze verification remain required; this earns no production acceptance.
