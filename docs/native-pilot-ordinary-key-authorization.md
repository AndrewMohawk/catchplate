# Ordinary-service process binding and current-key authorization

The `.371` batch adds the measurements and independent checkpoint issuer needed
before ordinary-service runtime preparation. It does not add supervisor job
coverage: **7/60** jobs are implemented and startup still refuses before spawn.

## Why this precedes delivery

An ordinary C9 delivery binds a complete runtime hash. The service body inside
that runtime also needs process identity and current-key checkpoint data. The
recovery-target and current-signature services consume a complete signed
checkpoint in their signing pin; the other services bind matching checkpoint
digests, sequence, generation and revocation data. These cannot be supplied as
predicted process identities or invented history in a pre-start recipe.

The existing native code verifies current-key authorization but previously had
no corresponding pilot issuer. Its checkpoint authority is a distinct key
selected by the authenticated authority epoch, not the C9 delivery key, service
signing key or history-root key.

## Actual preparation observation

`FiveServiceLaunch.preparation_original()` measures the launcher's actual
retained children, PIDFDs and target executable descriptors under the original
boot, namespace and startup window. The operator carries the exact original as
`ordinaryPreparationOriginal` in its service-originals request.

`serverware.custodyFiveServicePreparation/v1` explicitly says `parked-pre-exec`.
It records actual PID/start and PIDFD stat identity, plus content SHA-256,
`security.ima` and fs-verity measurements of each retained target executable.
Missing mandatory measurements refuse; a content hash is not substituted for
IMA or fs-verity. Capture is retained and subsequent access rechecks the same
owners without refreshing the original deadline.

The service UID/GID and target executable are the approved fixed-exec plan.
The child is still the parked bootstrap process: this observation does **not**
claim that the target has executed, assumed its final credentials, opened a
provider connection or become ready. The existing native post-connect process
and executable verification remains mandatory.

## Independent issuer

The separate `scripts/authority/sign_native_pilot_ordinary_key.py` command takes
an independently approved complete canonical public input on `--input-fd` and
an already provisioned matching checkpoint-authority key on
`--authority-key-fd`, using the existing protected-descriptor rules. It creates
no key, history, predecessor checkpoint or revocation state.

The input selects the explicit `fresh-retained-epoch-v1` profile. It supplies the
original driver configuration/window, ordinary launch/cold configuration,
actual preparation observation, independently pinned history-root identity,
genuine authority-history original and complete approved checkpoint payload.

This initial profile accepts one genuinely signed retained epoch with empty
transition, compaction and replay-tombstone collections. It authenticates the
existing root, checkpoint and service signatures and separate key identities
before using the current checkpoint-authority key. It does not claim general
history-chain admission or silently select the last unverified history entry.
Rotated histories need a separately connected verified admission path. This
issuer produces the direct next checkpoint: its predecessor is the supplied
epoch's actual checkpoint and its sequence advances by one. The retained epoch
already binds the same intended process and service key. Initial checkpoint
and three-party retained-anchor issuance therefore remain required source work;
this successor issuer does not bootstrap them from nothing.

The existing native initial-state contract is also incomplete: it requires
nonzero checkpoint-predecessor, pruned-history-root and durable-head digests but
does not define a fresh empty-state origin for them. Completing that path needs
genuine supplied originals or an explicit authenticated initial-state profile
implemented in both producer and native consumer. Passing nonzero shape checks
with arbitrary digests is not an acceptable initialization procedure.

Output uses the unchanged native `policyCustodyCurrentKeyAuthorization/v3`
payload, signature preimage and checkpoint digest. It binds the intended fixed
exec to the measured retained child/target, independently approved generation,
checkpoint/revocation/rollback floors and original boottime domain and bounds.
The signature authorizes that binding; it is not a live-process observation or
hardware custody proof. Loss or partial output does not authorize a retry.

## Remaining integration

Implement the initial checkpoint/retained-anchor ceremony, then add explicit
checkpoint-authority capabilities and fixed coordinator jobs
before ordinary delivery, then consume their actual results in the five runtime
and C9 composers. The runtime/inspection-policy installation must preserve
service ownership, exclusive creation and retained readback. Generation and the
remaining native/bridge/release/lifetime jobs, real provisioning and connected
application acceptance remain open. No source or unit result closes production
acceptance. See [current status](production-status.md).
