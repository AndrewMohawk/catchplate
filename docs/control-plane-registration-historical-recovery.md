# Registration completion recovery across configuration and key changes

Source `.219` connects the existing public registration recovery action to
independently cold-admitted historical authority. This is a registration
completion path under the supported source contract, not general cross-version
replay or completion of H05. Source remains unbuilt and unexecuted.

## Current permission, historical evidence

The public route still authenticates the current actor and its distinct recovery
purpose. Historical signer evidence establishes the original user/session and
operation; it is not permission for the requester. The configured current owner
still owns the fixed completion transport endpoint and inherited live deadline.
The historical inventory supplies only the old configuration/cohort/root,
original enrollments and independently authorized pending/packet pins needed to
verify the selected operation.

```text
Current actor and fresh recovery permission
                    |
                    v
Current cold owner + independently signed history inventory
                    |
       bounded association and outcome read
                    |
       authenticated historical scope resolution
                    |
       original signer + planning/grant replay
                    |
       exact user/session + pending/grant joins
                    |
   retained completion OR fixed completion-service query
                    |
       original historical completion verification
                    |
       durable outcome/reconciliation association
```

`control_plane_registration_recovery._recover_on_owner` now obtains one genuine
replay material from `_replay_material_on_owner(..., _include_outcomes=True)`.
The combined loader holds the preparation pair, reservation, SQL-attempt/result
and completion/reconciliation originals on one bounded read. It replaces the
old separate unmetered handoff reads and duplicate preparation loading.

The selected historical scope is used throughout pending admission, grant
verification and completion response verification. Admitting an old subject and
then silently returning to current keys for its completion is not supported.
Unknown selectors fail closed when history is enabled. Explicitly history-disabled
older bootstrap schemas retain the existing same-current-cohort behavior.

The completion packet digest and pending sequence/head/fence come from signed
cold material, never from unsigned SQL output or returned completion data. A
missing SQL-attempt marker or reservation is not permission to execute. Recovery
can retrieve or reconcile completion evidence; it does not issue SQL, renew an
original grant or declare a browser session active.

## Lifetime and capacity

The current runtime receipt and the historical archive both remain live through
replay, the optional completion exchange, verification, durable append and final
return. Cold admission rechecks the actual custody owner and fresh receipt after
public history validation and before reading private keys. A control-plane
receipt interval alone does not prove an authority generation/cohort interval;
the history profile carries genuinely admitted current provenance as well.

Current processing uses the original cumulative work allowance and inherited
deadline. Historical evaluation times remain original evidence, not replacement
clocks. The 64 MiB original-representation ceiling includes the selected history,
held startup material, replay headroom and a reserved completion-response lane
before the first journal body read. Transport still rejects response lengths
before allocation. These are source capacity bounds, not measured heap/RSS or
concurrency results.

Finalization/activation consumers and explicit older-source replay adapters
remain part of [H05](historical-authority-resolution.md). Frozen verification
must exercise actual key/configuration rotation, retained and queried outcomes,
mixed-cohort rejection, unknown history, expiration during processing and
interrupted reconciliation. No infrastructure, runtime behavior or production
acceptance is established by this source connection.
