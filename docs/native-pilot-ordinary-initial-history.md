# Ordinary initial checkpoint and retained-anchor ceremony

The `.372` source adds an explicit initial-state path for the five ordinary
services. It does not invent a prior checkpoint, durable receipt or history to
satisfy a nonzero-digest check. Independent authorities approve the complete
inputs, issue checkpoint one, separately sign its retained anchor, and assemble
an opt-in wrapper which the native service checks before state-writing gates.

This is source implementation, not an executed ceremony or pilot result. The
supervisor still implements **7/60** fixed jobs; **53** remain unsupported and
its coverage guard refuses startup. Production acceptance remains **0/6**.

## Actual preparation and empty resources

`FiveServiceLaunch.preparation_original()` retains the actual parked-pre-exec
child/PIDFD and target-executable measurements described in the
[current-key guide](native-pilot-ordinary-key-authorization.md). It does not claim
that a service has executed.

`GenerationInputs.initial_resources_original()` adds a cached, rechecked
`serverware.custodyFiveServiceInitialResources/v1` observation with exactly
`apiVersion`, `preparationSha256`, `issuedAtBoottimeNs` and `services`. Each of the
fixed five services has a `directories` map. Each entry contains exactly
`identity` and `entryCount: 0`; identity is the existing seven-field
`mountId/deviceMajor/deviceMinor/inode/uid/gid/mode` record.

| Service | Retained empty directories |
| --- | --- |
| `durable-recovery-store` | `journal`, `generation-journal`, `dispatch-journal`, `spool-head-journal` |
| `cleanup-authorization-consumer` | `state`, `journal`, `generation-journal`, `active-effect-cleanup-journal` |
| `recovery-target-provider` | `journal`, `generation-journal` |
| `current-signature-authority` | `generation-journal`, `dispatch-journal`, `spool-current-journal` |
| `bounded-cleanup-helper` | `journal`, `generation-journal` |

The observer uses all 15 actual owner-held descriptors, verifies persistent
filesystem/identity, service ownership, `0700`, read-only access and emptiness,
and captures one original issue time. It creates no resources or records. It
is available only while all five children remain parked and before delivery or
grant attempts. Failure fences the attempt and leaves cleanup with the existing
owners; rereading never renews the timestamp. The operator includes the literal
`ordinaryInitialResourcesOriginal` alongside `ordinaryPreparationOriginal` in
its service-originals observations. Neither observation is independent approval.

## Explicit initial state

The independently approved `serverware.custodyOrdinaryInitialState/v1` has
exactly these 19 fields:

```text
apiVersion                    serviceRole
preparationSha256             resourcesSha256
launchSha256                  endpointProcessIdentitySha256
bootIdBase64url               timeNamespaceDevice
timeNamespaceInode            issuedAtBoottimeNs
startupDeadlineBoottimeNs     lifetimeDeadlineBoottimeNs
invocationId                  deploymentGenerationSha256
endpointGeneration           serviceGeneration
operationGeneration          durableEpoch
directories
```

The directory map is the selected role's exact observed map, not caller-chosen
paths. State issue time equals the empty-resource observation's original time;
the signed driver window, ordinary launch, preparation and state must share
the selected original boot/time namespace, invocation and startup/lifetime.
This fixed initial profile does not alter older launch profiles. The four
generation values are independently approved positive `u64` values, not forced
to one. No revocation fact is generated.

Three distinct framed commitments over the complete canonical state define
INITIAL boundaries in existing v3 fields:

| Existing field | Domain |
| --- | --- |
| Checkpoint `predecessorCheckpointSha256` | `serverware.custodyOrdinaryInitialCheckpointPredecessor/v1` |
| Anchor `prunedHistoryRootSha256` | `serverware.custodyOrdinaryInitialHistoryRoot/v1` |
| Epoch `durableEpochHeadSha256` | `serverware.custodyOrdinaryInitialDurableHead/v1` |

Each uses the existing `p.framed(domain, (canonical(state),))` construction.
These are authenticated typed initial-state commitments, **not evidence of a
past checkpoint, pruned record or durable operation**. Their meaning is admitted
only by the explicit wrapper contract.

## Separate authority steps

`scripts/authority/sign_native_pilot_ordinary_initial.py` has five fixed
operations. Every call receives a separately approved complete input; dependent
calls include the actual prior public output, not a prediction of it.

| Operation | Private capability | Output |
| --- | --- | --- |
| `checkpoint` | Checkpoint-authority key only | Existing signed current-key/v3 checkpoint one |
| `root-anchor` | History-root key only | Detached signature over the derived existing anchor preimage |
| `checkpoint-anchor` | Checkpoint-authority key only | Detached signature over that same preimage |
| `service-anchor` | Service-signing key only | Detached signature over that same preimage |
| `assemble` | None; key FD forbidden | Verified initial-history wrapper |

The three key identities, SPKIs and underlying materials must be distinct and
must not reuse the selected C9 or driver-authority keys. Each signing call loads
one sealed key, never all three. Anchor calls first authenticate the actual
checkpoint. Assembly verifies all three anchor signatures and the complete
shared wrapper contract; it does not sign a substitute success result.

The canonical input is `serverware.nativePilotOrdinaryInitialAuthorityInput/v1`,
at most 8 MiB, with these exact common 11 fields:

```text
apiVersion                    operation
driverConfigurationOriginal   driverWindowOriginal
launchOriginal                configurationOriginal
preparationOriginal           resourcesOriginal
initialStateOriginal          authorities
payloadOriginal
```

Originals are literal canonical ASCII strings. `authorities` is exactly
`root`, `checkpoint`, `service`, each an existing public-key record
`{keyId,keySpkiSha256,publicKeySpkiBase64}`. `payloadOriginal` is the complete
independently approved checkpoint payload, including revocation facts and
validity. Anchor operations add `initialCheckpointOriginal`; assembly also
adds `anchorSignatures`, the three literal detached originals under those same
key-role names. A detached record has exactly `apiVersion`, `signer`,
`anchorPayloadSha256`, `keyId`, `keySpkiSha256`, `signatureBase64`, using
`serverware.custodyOrdinaryInitialAnchorSignature/v1`. Its signature still uses
the existing retained-anchor signature preimage.

Checkpoint sequence and checkpoint/consumer floors are one; endpoint floor is
the approved endpoint generation. Epoch sequence is one, with no predecessor
epoch. Pruned-through, record and compaction sequences are zero; historical
lists are empty and retention capacities are one. The epoch binds the actual
signed checkpoint and preserves the approved generation/deployment values.
Checkpoint, epoch, anchor and manifest retain their existing v3 wire formats.

The final wrapper is exactly:

```text
{apiVersion: "serverware.custodyOrdinaryInitialHistory/v1",
 initialState, initialCheckpoint, history}
```

Checkpoint output is bounded to 65,536 bytes, a detached signature to 4,096,
and the wrapper to the existing 4 MiB history ceiling. The checkpoint alone is
not a standalone initial-history admission.

Use the [protected authority FD and pipe contract](native-pilot-authority-commands.md).
Signing operations require distinct `--input-fd` and `--authority-key-fd`;
`--operation assemble` accepts only `--input-fd`. Input is reread before output,
and stdout contains one literal original without LF. Every stage preserves the
original startup/lifetime and clips output to the original deadline. There is
no key generation, installer, window renewal or automatic retry.

## Native admission and digest meanings

The opt-in receiver authenticates the complete history/root pins and initial
checkpoint, joins the typed state to the actual signed guest/runtime, and
checks the executing process and executable, including actual IMA and fs-verity
measurements. Before the first generation/dispatch/spool gate can write, it
checks every exact role directory against the held activation descriptor,
runtime/state identity, service ownership, persistent filesystem and bounded
empty-directory census. Missing evidence or a nonempty directory refuses.

Later gate-owned credential rereads authenticate the same wrapper and static
bindings; they do not repeat initial emptiness after a gate legitimately writes.
The existing legacy raw-history path and post-connect verification remain
unchanged. This source contract is not proof of a successful native execution.

C9 pins the SHA-256 of the **complete outer wrapper bytes**. The runtime and
generation scope retain the **inner framed manifest digest**. These are distinct
commitments; neither is substituted for the other or recomputed to bless an
unapproved original. The wrapper requires the actual signed guest credential
owner, not an arbitrary raw-history file.

## Remaining connection

Supervisor policy, fixed jobs/key capabilities and output-publication wiring
must still connect this ceremony to the five ordinary runtime, inspection-policy
and delivery composers. Private service provisioning, later generation/native/
bridge/release/lifetime jobs and actual application acceptance remain open.
The authority implementation is not approval automation. No tests, ceremony or
service execution have been run for this source batch at the time of this guide;
see [production status](production-status.md) for separately recorded evidence.
