# Ordinary-service process binding and current-key authorization

The `.371` batch adds process measurements and a direct-next checkpoint issuer.
The `.372` [initial-history ceremony](native-pilot-ordinary-initial-history.md)
adds the explicit initial-state/checkpoint/anchor source path. Neither adds
supervisor job coverage: **7/60** jobs are implemented, **53** remain unsupported
and startup still refuses before spawn. Production acceptance remains **0/6**.

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

`catchplate.custodyFiveServicePreparation/v1` explicitly says `parked-pre-exec`.
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

This fresh-retained-epoch profile accepts one genuinely signed retained epoch with empty
transition, compaction and replay-tombstone collections. It authenticates the
existing root, checkpoint and service signatures and separate key identities
before using the current checkpoint-authority key. It does not claim general
history-chain admission or silently select the last unverified history entry.
Rotated histories need a separately connected verified admission path. This
issuer produces the direct next checkpoint: its predecessor is the supplied
epoch's actual checkpoint and its sequence advances by one. The retained epoch
already binds the same intended process and service key. This successor issuer
does not bootstrap them from nothing.

The separate [initial-history ceremony](native-pilot-ordinary-initial-history.md)
uses the actual parked-child preparation and retained empty-directory observation,
then independently approved initial state. It issues checkpoint one, signs the
same retained anchor in three separate one-key calls, and assembles the opt-in
wrapper only after verification. Distinct typed INITIAL commitments define the
predecessor, pruned-root and durable-head meanings; they are not fabricated past
receipts. Native admission authenticates the wrapper and checks the real process
and still-empty directories before any state-writing gate. The existing raw v3
history formats and this direct-next issuer remain unchanged.

Output uses the unchanged native `policyCustodyCurrentKeyAuthorization/v3`
payload, signature preimage and checkpoint digest. It binds the intended fixed
exec to the measured retained child/target, independently approved generation,
checkpoint/revocation/rollback floors and original boottime domain and bounds.
The signature authorizes that binding; it is not a live-process observation or
hardware custody proof. Loss or partial output does not authorize a retry.

## Remaining integration

Connect the initial ceremony through independently approved supervisor policy,
explicit authority capabilities, fixed coordinator jobs and output publication
before ordinary delivery, then consume its actual results in the five runtime
and C9 composers. The runtime/inspection-policy installation must preserve
service ownership, exclusive creation and retained readback. Generation and the
remaining native/bridge/release/lifetime jobs, real provisioning and connected
application acceptance remain open. No source or unit result closes production
acceptance. See [current status](production-status.md).
