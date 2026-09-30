# Native pilot fresh-ledger startup

The .369 source profile separates a newly measured scope's empty initial ledger
from a legacy immutable receipt archive. It does not invent a receipt to satisfy
a pre-launch manifest requirement. The profile must be selected explicitly in
both public inputs and the independently signed native service grant.

## Public manifest and directory

`serverware.nativeShadowRetrievalStoreManifest/v2` has exactly four fields:

| Field | Required value |
| --- | --- |
| `apiVersion` | `serverware.nativeShadowRetrievalStoreManifest/v2` |
| `proofScopeOriginalBase64url` | Canonical unpadded base64url of the exact production proof scope/v2 original |
| `initialization` | `fresh-ledger` |
| `objectOriginalsBase64url` | Exactly `[]` |

`fresh_ledger_manifest_original(scope_raw)` validates that explicit scope/v2 and
constructs only this public manifest. `manifest_initialization(raw, expected_sha256)`
fully validates the original and pin before returning `fresh-ledger` or `None`
for legacy mode. Neither function approves an assignment or grants service access.
Legacy manifest/v1 remains exact three fields with 1–16 supplied objects;
`manifest_original` still rejects an empty list.

The existing installer requires an actual empty root:root0700 directory reached
through protected no-follow ancestors. It retains and locks that directory,
checks its population, fsyncs it, changes its mode to 0555, and rechecks identity
and emptiness. Fresh mode creates no object files and performs no fs-verity file
measurements. It does not create a ledger genesis or start a service. Failure
preserves partial state; no repair, adoption or automatic retry is provided.
An external watchdog is still required for filesystem stalls.

Its `serverware.nativeShadowRetrievalStoreInstalled/v2` observation contains the
same fields as Installed/v1 plus `initialization: "fresh-ledger"`; `objects` is
exactly empty, `releaseAuthority` and `serviceReady` remain false. Directory
device, inode and mode describe the actual retained directory, not a hypothetical
installation. Installed/v1 and its schema remain unchanged. The new
[v2 schema](../schemas/native-shadow-retrieval-store-manifest.v2.schema.json)
covers both closed v2 forms.

## Native service admission and first real receipt

`serverware.nativeLedgerSpoolRetrievalGrant/v4` retains the existing v3 payload
fields and adds only `initialization: "fresh-ledger"`, using signature domain
`serverware.nativeLedgerSpoolRetrievalGrant.signature/v4`. It requires strict
production proof scope/v2 and actual ledger admission at sequence zero with
`headSha256 == genesisSha256`. The native owner reads the genuine genesis and
checks its guest, scope and hash; an empty manifest is not a substitute for it.
Older grant versions do not acquire fresh-ledger semantics.

The fixed activation inventory remains four actual FDs: `retrieval-listener`,
`retrieval-objects`, `ledger-spool-store`, and `ledger-spool-lock`. The objects FD
retains the empty root:root0555 directory, whose emptiness is rechecked. The
separate writable ledger and retained lock keep their existing ownership,
durability and bound checks.

Only actual authenticated runtime operations produce the first stored core and
scope-bound receipt. Retrieval writes and verifies the core with fs-verity before
signing its stored result; the operational signer then completes the receipt.
Fresh mode retrieves only those genuine retained ledger objects. An unknown ID
fails: there is no immutable-object fallback, successful absence response, or
conversion of genesis into an operational receipt.

The explicit retrieval producer input
`serverware.nativePilotNativeServiceAuthorityInput/v2` requires
`retrievalManifestOriginal`, joining this exact manifest and scope to the fresh
grant request. This is a complete independently approved input, not permission
inferred from an empty directory or a new observation.

## Evidence boundary

These are source contracts, not a launched pilot or verified first request.
The `.370` [endpoint composers](native-pilot-supervisor-endpoints.md) connect this
profile to preparation and the first three C9 decisions. Supervisor coverage is
7/60 and full-run startup still refuses. Genuine assignments, protected originals,
service authorization, actual storage and subsequent connected acceptance remain
required. No preexisting custody evidence, readiness, deployment, or new runtime
success is claimed by this profile.
