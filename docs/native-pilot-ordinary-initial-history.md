# Ordinary initial checkpoint and retained-anchor ceremony

The `.372` source adds an explicit initial-state path for the five ordinary
services. It does not invent a prior checkpoint, durable receipt or history to
satisfy a nonzero-digest check. Independent authorities approve the complete
inputs, issue checkpoint one, separately sign its retained anchor, and assemble
an opt-in wrapper which the native service checks before state-writing gates.

The `.373` source connects the ceremony to the independent supervisor through
explicit commissioning policy/v4. Coverage at that checkpoint was **32/85** fixed
jobs. The subsequent [ordinary delivery connection](native-pilot-ordinary-deliveries.md)
brings coverage to **37/85**, with **48 jobs** still unsupported,
so the coverage guard still refuses before spawn. This is source implementation,
not an executed ceremony or pilot result; production acceptance remains **0/6**.

## Actual preparation and empty resources

`FiveServiceLaunch.preparation_original()` retains the actual parked-pre-exec
child/PIDFD and target-executable measurements described in the
[current-key guide](native-pilot-ordinary-key-authorization.md). It does not claim
that a service has executed.

`GenerationInputs.initial_resources_original()` adds a cached, rechecked
`catchplate.custodyFiveServiceInitialResources/v1` observation with exactly
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

The independently approved `catchplate.custodyOrdinaryInitialState/v1` has
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
| Checkpoint `predecessorCheckpointSha256` | `catchplate.custodyOrdinaryInitialCheckpointPredecessor/v1` |
| Anchor `prunedHistoryRootSha256` | `catchplate.custodyOrdinaryInitialHistoryRoot/v1` |
| Epoch `durableEpochHeadSha256` | `catchplate.custodyOrdinaryInitialDurableHead/v1` |

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

The canonical input is `catchplate.nativePilotOrdinaryInitialAuthorityInput/v1`,
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
`catchplate.custodyOrdinaryInitialAnchorSignature/v1`. Its signature still uses
the existing retained-anchor signature preimage.

Checkpoint sequence and checkpoint/consumer floors are one; endpoint floor is
the approved endpoint generation. Epoch sequence is one, with no predecessor
epoch. Pruned-through, record and compaction sequences are zero; historical
lists are empty and retention capacities are one. The epoch binds the actual
signed checkpoint and preserves the approved generation/deployment values.
Checkpoint, epoch, anchor and manifest retain their existing v3 wire formats.

The final wrapper is exactly:

```text
{apiVersion: "catchplate.custodyOrdinaryInitialHistory/v1",
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

## Supervisor connection

`catchplate.nativePilotSupervisorCommissioningPolicy/v4` adds the closed
`ordinaryInitialHistories` policy to v3. Its five role entries independently
select the three public authorities, endpoint role, generations, deployment and
revocation facts. Actual preparation and empty-resource observations supply
identity and original time bounds; neither observations nor prior job results
grant approval. Older policy versions keep their exact scope and 42 selectors;
they cannot bind the expanded coordinator's **57 key selectors**.

At the start of `service-originals`, each role in the fixed five-role order runs
`ordinary-initial-<operation>-<role>` for `checkpoint`, `root-anchor`,
`checkpoint-anchor`, `service-anchor`, then `assemble`. Checkpoint and its anchor
share that role's checkpoint selector; root and service anchors use their own
selectors, and assembly uses no key. The composer checks the genuine pending
process request and reauthenticates actual prior results against the exact
approved input. The executor separately retains those inputs, requires unchanged
context/payload across each role's ceremony, and joins each anchor to the actual
checkpoint and assembly to all three actual detached records.

Only assembly publishes, at the fixed root-owned slot
`/etc/catchplate/native-pilot-inputs/ordinary-initial-history-<role>.json`.
Publication checks wrapper grammar and commitments, not independent authority.
That root-owned file is not a service-owned C9 credential. Downstream delivery
requires a separately installed public copy at
`/etc/catchplate/custody-<role>-initial-history.json`, owned by the actual cold
service UID/GID with mode `0400`. The executor retains and reads that file,
requiring the exact assembled bytes, digest and length and `signing: null`;
generic credential owner checks remain unchanged. Its approved runtime must
match the inner history digest and root pins. Later ordinary grant inputs carry
the same literal wrapper. No new guest-delivery digest is predicted.

The original startup window and byte limits are unchanged; partial failure
retains owners and does not authorize a retry. The fixed service-owned history-copy,
runtime and inspection-policy installer and ordinary delivery composition remain
missing. Private provisioning, later generation/native/bridge/release/lifetime
jobs and actual application acceptance remain open. The
[supervisor coverage guard](native-pilot-supervisor.md) prevents an incomplete run.

## Focused verification

Exact `.373` source `21eef81b` passed one network-isolated Python 3.11.15 run:
35 focused controls, eleven changed-file grammar/both Make inventory checks,
and 40 relative documentation links. The eight new controls cover job/key
selection, closed policy and v4-only u64 counters, exact prior results,
independent synthetic signatures, publication shape/pins and approval
serialization. They do not execute protected owners, signers, installers or
services. The original native source is unchanged and was not rebuilt.
Commands, exact source archive and logs are retained at
`codex-offload/catchplate/engineering-builds/21eef81b-initial-commissioning-QZ3L75`.
The `.374` source adds the service-owned copy installer; its live execution and
connected pilot acceptance remain open.

The following is historical **`.372` verification**.

Native source `c2542acb` passed one cached Rust 1.88 offline/frozen/locked
`cargo check --bin catchplate-decision-gate -j1` in 52.67 seconds, with no network,
one CPU, an 8 GiB memory bound and a 20-minute outer limit. It reported 312
library and 2,438 binary warnings; this is compilation, not native runtime proof.

Test commit `977d1f38` changes only the new test and its two Make inventory
entries; runtime/native/schema/authority source is identical to `c2542acb`.
Its single isolated Python 3.11.15 run passed 27 controls: seven existing endpoint,
eight existing key-wire, four existing history and eight new initial-state
controls. Eleven changed Python files passed grammar/both inventory checks and
15 relative documentation links resolved. No DB/app/authority-store imports,
protected owner, issuer entrypoint, CLI, installation, live signing, service or
cloud operation ran. Cryptographic fixtures use synthetic in-memory test keys.

Exact source archives, commands, logs and checksums are retained under
`codex-offload/catchplate/engineering-builds/c2542acb-initial-history-wdWcbZ`
in the operator home. See [production status](production-status.md); no acceptance
gate or additional supervisor composer is claimed by these checks.
