# Private consume-plan original journal

Source-only, unbuilt and unexecuted. `DeliveryOriginalJournal` retains the exact
private originals needed to replay a signed
[delivery-consumption plan](oidc-session-activation-delivery-plan.md). It is not
an execution packet, SQL outcome, consumption proof, token-release decision,
anti-rollback witness or public recovery API. Nothing here provisions a key,
directory, process role or replacement authority window.

## Fixed owner and API

[`authority_oidc_session_activation_delivery_journal.py`](../catchplate/authority_oidc_session_activation_delivery_journal.py)
constructs the exact `DeliveryOriginalJournal` with keyword-only directory FD,
independent device/inode/UID/GID pins, maximum records, byte quota,
configuration digest, `journal_key`, `bundle_key`, `delivery_key`, and the
existing `live_window`, `work`, positive `transport_deadline_ns`.
All three AES keys must be immutable 32-byte values and pairwise distinct.
Only the journal key encrypts these records; the other two are independently
held historical-purpose pins for the actual configured owner's joins, not
serialized fields or authority inferred from storage.

- `append(*, scope, original_bytes, live_window, work, transport_deadline_ns)`
  returns the first durable ciphertext's canonical SHA-256 digest.
- `read_bound(*, scope, expected_journal_digest, live_window, work, transport_deadline_ns)`
  returns the exact canonical private original bytes, or bounded local `None`.
- `read(*, scope, live_window, work, transport_deadline_ns)` is the unbound
  private original read; it is not a substitute for independent locator admission.
- `_snapshot_configuration()` returns the same held eight-tuple object:
  `(source_revision, configuration_digest, journal_key, bundle_key, delivery_key,
  (device, inode, uid, gid), maximum_records, quota_bytes)`. This contains keys
  and must never be logged or exposed publicly.
- `close()` closes only the owner's independently opened directory description.

The four-field storage scope is exactly `sourceRevision`,
`configurationDigest`, `requestDigest`, `planDigest`. The final identity is
derived from the actual consume-plan envelope in its distinct identity domain.
The scope/configuration is independent input, not learned from the selected file.

## Exact original document

`_encode_original_on_work(value, *, scope, work)` and
`_decode_original_on_work(original_bytes, *, scope, work)` handle the canonical
closed sixteen-field document. They return ordinary bytes/data, never replay
success. Their caller must retain its current processing guard around use.

| Field | Original retained |
| --- | --- |
| `schema` | `catchplate.oidcSessionActivationDeliveryPrivateOriginals/v1` |
| `sourceRevision` | Exact current-source revision |
| `request`, `scope` | Typed consume request and exact fourteen-field plan scope |
| `databaseNow` | Original canonical UTC database timestamp |
| `oldTokenBase64Url` | Exact original 64-byte pending token |
| `readInputs` | Exact nine-field consume proof/root/head graph |
| `writeProofBase64Url` | Original five-index write proof |
| `planEnvelopeBase64Url` | Exact signed consume-plan envelope |
| `stateEnrollmentBase64Url`, `completeRootVectorBase64Url` | Independently admitted original state enrollment/vector |
| `headQueryBase64Url`, `headObservationBase64Url` | Original consume-specific query and signed observation |
| `activationOriginals` | Thirteen base64url frames in the plan's fixed original order |
| `activationExpectations`, `activationScope` | Original completed-activation expectations and six independent provenance pins |

`readInputs` has the consume proof schema and only `selectedRows`,
`beforeProofs`, `readHeads`, `queryFrontiers`, `queryReads`,
`businessBeforeRoots`, `authorizationBeforeRoots`, `countedBeforeHeads` plus
`schema`. It requires ten selected rows/proofs, seventeen queries and seven
read/frontier/counted-head entries. The plan's charged normalization supplies
actual JSON lists, not tuples. These stored roots are still original data:
receiving must compare independently admitted roots/heads and genuinely replay.

The [plan guide](oidc-session-activation-delivery-plan.md) defines the raw13
order. Its actual per-frame bounds apply, including the existing transport's
closed empty uncertainty suffix grammar; such uncertainty is not completed
provenance and cannot produce a valid consume plan. No AES key is a document
field. Shape/canonical/identity joins do not verify plan or completion signatures.

### Serialization and restoration

[`authority_oidc_session_activation_delivery_retained.py`](../catchplate/authority_oidc_session_activation_delivery_retained.py)
provides `_encode_on_work(invocation, *, envelope_bytes, plan_digest, work)`,
returning the four-field journal scope and exact canonical document bytes.
It accepts the actual plan's owned original capture, not its successful replay
result, and uses the real consume-specific nine-field read projection.
All original graphs are held before charged base64/native callbacks.

`_restore_on_work(original_bytes, *, scope, work)` returns a real `KernelContext`
and an ordinary eighteen-field original-argument dictionary. It reconstructs
bounded `QueryRead`/address records, counted read heads and leaf/opaque range
frontiers, and uses the journal's actual raw13 decoder. No activation proof
domain is relabeled as a consume proof. The record supplies no key, custody
owner, current window, deadline or work allowance. Before genuine full replay,
the owning caller must compare its independent request/scope/roots/heads and
state originals, supply its independently admitted keys/custody, and retain the
same current guard through both helpers. Neither helper performs database I/O,
signing, retention mutation, semantic admission or historical lifetime renewal.

## Encryption, first-exact retention and recovery

This uses a second fixed exact-class profile of the existing
[activation journal storage](oidc-session-activation-journal.md), not arbitrary
codec injection or a caller-selected profile. Existing activation constructor,
seven-field configuration, v2 frame, filename and method signatures are unchanged.
The distinct consume format is `SWODJ001`, two-byte big-endian scope length,
eight-byte plaintext length, fresh twelve-byte nonce, canonical scope and
AES-256-GCM ciphertext/tag. AAD is
`catchplate.oidcSessionActivationDeliveryJournal/v1` followed by NUL, the first
eighteen frame bytes and the exact scope bytes. Final names are
`delivery-<consume plan digest hex>`. Plaintext is at most 64 MiB; files add at
most 4 KiB of scope and 46 framing bytes. Quotas are at most 1024 records/8 GiB;
the existing cumulative work allowance remains the actual processing limit.

The preprovisioned directory must be pinned nonroot-owned mode `0700`.
An independent no-follow directory open and nonblocking exclusive flock protect
one PID/UID/GID-bound owner. Complete bounded inventory, same-device single-link
mode-`0400` files, stable file/path identity and directory continuity are checked.
The actual storage primitive performs no-replace publication, file/directory
fsync and durable readback; ciphertext is genuinely opened and compared to the
exact original before publication and after readback.

Exact repeats return the original ciphertext digest without generating another
nonce or replacing bytes. A changed scope/original conflicts and poisons the
handle. `read_bound` checks the independently supplied ciphertext digest against
the stable file and first inventory scope/identity/digest before AES opening.
Recovery rejects unknown/orphan temporary files, over-quota contents or failed
authentication. Live continuity rejects missing/changed records against this
owner's recovered inventory; cold recovery is not an independent rollback check.
Ambiguous I/O poisons the owner;
visible publication is never removed, retried or pruned implicitly.

Recovery uses the supplied current work/window/deadline cumulatively. Old
records may remain encrypted after their original plan expires; canonical
storage admission never substitutes an old clock or renews execution permission.
Bounded absence is not evidence that SQL did not commit. Genuine retained-plan
replay, protected issuance/SQL/recovery and committed-original token release
remain separate requirements; this journal alone closes none of those boundaries.
