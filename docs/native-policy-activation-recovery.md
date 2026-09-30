# Recover a retained native publication

An interrupted HTTP reply is not permission to publish again. The actual native
journal retains `activation-request.json`, `activation-receipt.json` and
`publication.json`. When all three complete originals survive, the read-only
exporter recovers the existing portal handoff for separate authenticated receipt
inclusion and finalization. Export performs no service restart, new signature,
native contact, publication, hold release or audit completion.

This path is source-only and has not been executed. It handles lost replies with
complete retained records, not a crash before the signed receipt was durably
stored. Partial records, journal replacement and cross-boot authority changes
still require separate reconciliation; this tool cannot make them successful.

## Operator inputs

Use the original host's fixed
`/var/lib/serverware/native-policy-activation/journal` directory. No alternate
journal path is accepted. Supply exact canonical ASCII selection JSON matching
`native-policy-activation-recovery.v1.schema.json`, without a trailing newline:

| Field | Required original source |
| --- | --- |
| `apiVersion` | Literal `serverware.nativePolicyActivationRecoverySelection/v1` |
| `activationId`, `preparedSha256` | Actual consumed preparation from authenticated approval lookup |
| `initialStateSha256` | Independently signed original native activation service assignment |
| `journal.device`, `journal.inode`, `journal.uid`, `journal.gid` | Original admitted C9 `activation-journal` FD identity and final role owner |

Pins are selectors, not authority. Do not derive missing expected values from a
replacement directory or create a new journal. Use root or the actual final-role
UID with existing filesystem access; the tool grants no access. It takes the
existing lock in nonblocking shared mode. A live publication owner's exclusive
lock refuses export immediately. Do not stop that owner just to obtain a lock.

Export to a **new** file in an existing mode-0700 directory owned by the invoking
operator, outside the publication journal. The new file is mode 0600 and is
never overwritten. With actual private paths substituted:

```sh
python scripts/authority/recover_native_policy_activation.py \
  --selection-fd 3 \
  --output /absolute/private/activation-handoff.json \
  3</absolute/private/recovery-selection.json
```

No authority originals are printed. An output I/O failure may leave a partial
new export; it is not usable evidence. The journal is never modified or cleaned.

## Resume the existing protected workflow

In the operator portal's **Native policy activation** section, choose the private
recovery file and select **Import for review only**. Import retains the exact
receipt string and losslessly parses integer-valued originals in page memory.
It fills the matching approval/readiness/generation IDs and selects
`record-inclusion`; conflicting already-entered IDs refuse import. Nothing is
submitted automatically, and submitted-phase markers are never cleared.

Read the current draft, review the exact originals and explicitly submit receipt
inclusion. The protected writer verifies the assigned publication key, signature,
request/preparation hashes, consumed approval, requester and held state. It accepts
the original in-window observation without renewing the old publication window.
After real audit delivery, separately review and finalize. Neither a valid-looking
export nor portal import authenticates the receipt.

If receipt inclusion itself previously had an unknown outcome, inspect retained
state first. Import does not clear that phase's marker or permit resubmission.
A finalized effect stays finalized; export does not make it a new publication.

## Reader boundary

The reader holds the actual directory, parent chain, lock and original file FDs.
It requires the selected device/inode/final owner, protected ancestry, exact
four-file population, regular single-link mode-0400 evidence, unchanged named/held
metadata and one supported local durable filesystem. Leftover `publication.next`,
missing receipts and extra files refuse export. Bounded enumeration stops on the
first unexpected entry; fixed per-file/whole-handoff limits are unchanged.
A 30-second collection bound is an I/O limit, not renewed authority. Current
state, retained request, prepared original and signed receipt must agree on
their exact hashes and publication tuple. Cryptographic authority and settlement
remain the protected consumer's responsibility. Local file survival is not an
independent rollback witness, hardware proof or production acceptance.
