# Private activation-original journal

This is source-only encrypted local retention for the [activation plan](oidc-session-activation-plan.md), not a deployed custody service, an execution permission or proof of session activation. The source has not been built or exercised. No directory, key, launch authority or recovery checkpoint is provisioned by this slice.

`catchplate/authority_oidc_session_activation_journal.py` owns one nonroot, PID-bound `ActivationOriginalJournal`. The constructor receives an already opened directory descriptor, independent device/inode/UID/GID pins, record/byte quotas, configuration digest, two distinct exact 32-byte keys, and the caller's existing work/window and optional inherited monotonic deadline. It does not read environment keys, use legacy `crypto.encrypt_secret`, open another allowance or infer a trusted configuration from stored records.

## Fixed private contract

The private methods are:

- `append(*, scope, original_bytes, live_window, work, transport_deadline_ns=None) -> str`: retain the first exact original and return its local ciphertext SHA-256 digest.
- `read(*, scope, live_window, work, transport_deadline_ns=None) -> bytes | None`: return the exact decrypted private original, or bounded local absence after inventory checks.
- `read_bound(*, scope, expected_journal_digest, live_window, work, transport_deadline_ns=None) -> bytes | None`: require the independently supplied canonical ciphertext SHA-256 locator before private decryption, then return the exact canonical original or bounded local absence.
- `_snapshot_configuration()`: return the held tuple `(source_revision, configuration_digest, journal_key, delivery_key, (device, inode, uid, gid), maximum_records, quota_bytes)` under actual PID/readiness/lock guards. It performs no unmetered inventory scan. This tuple contains private keys and must never be logged or returned publicly.
- `close()`: close only the journal's independently opened directory description; never delete retained records or unlock a borrowed descriptor.

The exact four-field storage scope is `sourceRevision`, `configurationDigest`, `requestDigest`, `planDigest`. Source and configuration must equal the independently configured owner. The request digest joins the retained typed request; the plan digest is computed from the actual signed envelope original using `catchplate.policyAuthorityOidcSessionActivationPlanIdentity/v2`. This binding is not signature verification or semantic replay.

Private `_encode_original_on_work(value, *, scope, work)` and `_decode_original_on_work(original_bytes, *, scope, work)` own/canonically encode or decode the fixed document. Their caller must preserve its existing live guard around these helpers. The journal's actual append/read paths do so. No successful verification object is accepted or returned.

`read_bound` captures the complete scope and exact digest before clock or I/O
callbacks. The expected digest comes from the actual `PreparedActivationPlan`
original, not from the file being selected or a returned success/status claim.
Under the existing readiness lock and continuity checks, the journal performs
its real stable file read and hashes those ciphertext bytes. Before `_unseal`
or AES-GCM decryption, that hash must match both the expected locator and the
retained first-record digest; the first scope and actual file identity must
also match. Authenticated opening then repeats the original scope and canonical
document checks. A mismatch poisons the journal; it is not retry permission.

The old `read` signature and behavior remain available through the same private
read path. Neither method changes files, bypasses locks or inventory checks,
or returns a verification carrier. Missing local custody returns `None`
only after the normal checks; even a valid expected locator does not prove a
record exists or establish a remote outcome. A caller exporting an
[encrypted execution bundle](oidc-session-activation-execution-bundle.md) must
keep the returned plaintext private and independently enforce bundle-key and
authority admission; this bound read is not itself a public export API.

The canonical private document has exactly sixteen fields:

| Field | Retained original |
| --- | --- |
| `schema` | `catchplate.oidcSessionActivationPrivateOriginals/v2` |
| `sourceRevision` | Exact current source revision |
| `request` | The exact seven-field typed `oidc.session.activate` request |
| `scope` | The plan's exact fifteen-field private subject/policy/configuration/key/time scope |
| `databaseNow` | Original canonical UTC database time, not a new evaluation time |
| `assertionBase64Url` | Original assertion, at most 128 KiB |
| `oldTokenBase64Url`, `newTokenBase64Url` | Original exact 64-byte URL-safe tokens |
| `deliveryEnvelopeBase64Url` | Original exact 100-byte [delivery envelope](oidc-session-activation-delivery.md) |
| `readInputs` | Exact nine-field original proof/root/head document described below |
| `writeProofBase64Url` | Original bounded write-proof bytes |
| `planEnvelopeBase64Url` | Actual signed plan envelope original, at most 16 KiB |
| `stateEnrollmentBase64Url` | Exact independently admitted root-signed state enrollment |
| `completeRootVectorBase64Url` | Exact independently configured complete vector, not just selected heads |
| `headQueryBase64Url` | Original nonce/context-bound planning query, at most 4 KiB |
| `headObservationBase64Url` | Original signed planning observation, at most 8 KiB |

`readInputs` contains only `schema`, `selectedRows`, `beforeProofs`, `readHeads`, `queryFrontiers`, `queryReads`, `businessBeforeRoots`, `authorizationBeforeRoots`, and `countedBeforeHeads`; its schema is the activation plan proof domain. These retained roots and heads are historical original values, not newly adopted independent authority. Actual replay must compare separate expected request, scope, roots and heads before using them.

The fixed encoder has no journal-key or delivery-key field. The keys are supplied independently and excluded from this original document by the actual owner. The storage codec does not claim to discover arbitrary secrets or establish the provenance of nested ordinary proof/policy graphs. Those bounded graphs and opaque write-proof bytes still require genuine downstream replay.

Keeping the actual plan envelope inside the encrypted record avoids reconstruction or re-signing after restart. A caller may not replace it with an alleged successful plan or a scalar status.

The four state originals are committed by the v2 signed plan. Actual receiving
replay compares enrollment and vector originals against independent configured
expectations, then reauthenticates the observation's signature, original query,
context, empty pending state and unchanged interval. The journal codec only
bounds and retains those originals; encryption is not state admission. V1
records without these fields are not upgraded or accepted as v2 automatically.

## Encryption and durable first originals

The journal uses AES-256-GCM with the independently supplied journal key, a fresh 12-byte CSPRNG nonce and fixed domain `catchplate.oidcSessionActivationJournal/v2` followed by NUL. This key must differ from the independently supplied delivery key; there is no fallback or automatic key rotation.

The binary frame is `SWOAJ002`, a two-byte big-endian scope length, an eight-byte big-endian plaintext length, the nonce, canonical scope bytes and ciphertext with its 16-byte tag. Associated data is the fixed domain, the first eighteen frame bytes and the exact canonical scope. Only the bounded four-field scope and framing are cleartext. The complete private document, including both tokens and the signed plan, is encrypted. Ciphertext is genuinely opened and the exact original compared before publication and again after durable readback.

The plaintext ceiling is 64 MiB (`authority.MAX_RESULT_BYTES`), not a new reduced proof bound. Scope bytes are capped at 4 KiB, so ciphertext file size is at most the plaintext ceiling plus 4 KiB plus 46 bytes. Configured count is 1–1024 records and quota is at most 8 GiB. These source ceilings do not create processing allowance: parsing, copies, hashes, crypto and storage consume the supplied cumulative work; an insufficient original allowance fails closed.

The journal reopens `.` relative to the independently pinned directory descriptor, takes its own nonblocking exclusive flock and uses the actual `WitnessJournalIO` publication primitive. The directory must be mode `0700` with the pinned nonroot ownership and identity. Records are no-follow, same-device, single-link regular files owned by that UID/GID and mode `0400`. A bounded complete inventory and file/path metadata continuity checks precede use. Startup authenticates each bounded record and performs actual file/directory durability barriers under the supplied processing window.

Publication writes only encrypted bytes to a private exclusive temporary file, fsyncs the mode-`0400` file, uses real `renameat2(RENAME_NOREPLACE)`, and fsyncs the directory. Final names are `activation-<plan digest hex>`. Unknown entries, abandoned temporary files, over-quota inventories, malformed/noncanonical records, identity changes or authentication failures reject recovery; the journal does not clean them up or choose an alternative record.

An exact repeat for the same locator reads/decrypts/compares the first original and returns its original ciphertext digest without generating a nonce or writing again. A different scope or original for that locator poisons the handle. Publication or later-check uncertainty also poisons it; a published record is never removed. Reopening requires a complete independently configured scan, not an automatic retry.

## Boundaries

Constructor, append, read and read_bound retain the supplied current window and inherited absolute deadline, including sticky rollback checks around bounded storage/crypto activity. Checks are not a hard kernel watchdog for a blocked filesystem/native call. Snapshot performs only held configuration/readiness checks; all inventory I/O is metered on constructor, append or either read path. A later local read may use a new current processing allowance, but does not renew any original plan, assertion, token delivery or execution authority.

The journal provides local first-original durability and ciphertext authentication, not an independent anti-rollback/latest-head witness. A missing record does not establish that no remote SQL effect occurred. File hashes, timestamps and successful decryptions are not authority tokens. Private reads never project plaintext tokens to public HTTP; memory erasure is not claimed.

Actual root/current-state admission, plan signature and semantic replay, protected execution, one-use delivery consumption, explicit recovery authorization, public activation and final portal/current-auth confirmation remain separate requirements. This slice alone does not complete F08 or any production acceptance gate.
