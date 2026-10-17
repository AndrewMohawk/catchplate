# Cold-core custody and adoption signing

This connects two previously missing boundaries in [cold commissioning](native-pilot-genesis-commissioning.md):
retaining the actual immutable core across service retirement, and running native
adoption validation before a signing authority reads its key. These are distinct
operations. Receiving a file descriptor does **not** authorize operational use.

## Retain, retire, transfer

The explicit `--run-native-genesis-handoff` command selects
`catchplate.nativePilotGenesisExecution/v2`. The original v1 command remains a
64-job, Bundle-only flow. V2 has **66 jobs and the same 36 signing purposes**.
Its final sequence is:

1. Complete the real coordinator and consume its successful native result.
2. Acquire the core through the still-retained Retrieval ledger directory.
3. Retire the actual coordinator, endpoints, ordinary services and helpers.
4. Transfer the retained core and receive an authenticated custody acknowledgement.

Acquisition opens only `core-00000000000000000001.json` relative to the actual
`ledger-spool-store` directory capability. It is not in `retrieval-objects`.
The retained owner checks canonical core bytes, Prepared/Stored signatures and
their actual admitted roots, literal object hash, domain-separated core hash,
measured fs-verity, fixed sequence one, original guest UID/GID, regular-file
`0400`, one link, and named-inode/directory identity. It never copies, recreates,
changes ownership of, or re-enables verity on the core.

The v2 configuration adds exactly:

```json
"coreHandoff": { "peerPid": 12345, "peerUid": 0, "peerGid": 0 }
```

The PID is an illustrative placeholder. An independent operator must approve
the actual peer. The command also requires `--core-handoff-fd`, distinct from
its configuration, inventory and key descriptors. This inherited, connected
Unix `SOCK_SEQPACKET` capability is separate from the approval pipes. Actual
`SO_PEERPIDFD`, peer credentials and per-message credentials must match; there
is no numeric-PID fallback or inherited-socketpair credential substitution.

One `SCM_RIGHTS` packet transfers the readonly core FD and a sealed public
originals container. The acknowledgement binds the exact request and original
hashes. An ambiguous send or missing acknowledgement authorizes no retry;
custody stays retained until acknowledged or the actual held peer PIDFD proves
terminal process state. Original boot/time namespace and UNIX/BOOTTIME bounds
remain in force. Receiver-provided or newly sampled time cannot renew them.

The v2 request, approval, reply and terminal profiles are explicitly selected;
legacy v1 approvals cannot authorize v2 jobs. Complete inputs still require the
independent supervisor and fixed protected installation described in the
[commissioning contract](native-pilot-genesis-commissioning.md#separate-invocation-and-approval-exchange).
No approver is provisioned by this command.

The receiver constructs `ReceivedGenesisCore` only from actual `recvmsg`
resources. Its checked borrowed descriptor is intended for the native v6
Retrieval activation's fifth slot, `publication-genesis-core` (FD10). The Python
operational activation, C9/grant producers and full adoption commissioning
graph still need to consume this retained owner; a descriptor number or JSON
observation cannot substitute for that integration.
Native inspection already understands the fifth slot, but the actual cohort
role/configuration/release admission still rejects the adopted roles. That join
requires an explicit native-and-Python cohort successor, not just an FD list.

## Native validation before signing

The supervisor package's existing publication entrypoint adds the explicit
`--sign-publication-adoption` mode. In canonical order it requires:

- the independently pinned supervisor inventory FD/hash;
- the complete native validation input FD/hash;
- a separate protected validator-control FD/hash;
- the independently provisioned sealed authority-key FD.

The closed control is `catchplate.nativePublicationAdoptionAuthorityControl/v1`
with `validatorExecutableSha256` and `inputSha256`. It pins the fixed executable
`/opt/catchplate/catchplate-native-publication-adoption-validator`; it cannot
select another path, module, command or environment.

The retained authority executes those exact static ELF bytes, supplies the
original input, reads the full bounded result and EOF, and consumes successful
exit zero from that same child's PIDFD. **All of that precedes the private-key
read.** Pure Python shape checks, a supplied success packet, process exit alone,
or a caller-supplied validator result cannot unlock signing.

Only then does it match the provisioned key and sign the native Authorization
envelope under the matching v1/v2 domain. The literal payload, original clocks,
input and installed runtime remain checked through bounded output and cleanup.
Unknown child cleanup retains the owner and runtime; no automatic retry or
fresh cleanup grace is granted. Known no-child/reaped cleanup may close its
descriptors after expiry, but cannot release successful expired output.

This is a Python/OpenSSL signing authority, not demonstrated hardware custody.

## Verification

Exact source `8fb767acd9f8c49bf40023539dd99d1f718a00bd` passed **all 80 controls
in nine suites**, with zero failures, errors or skips, in **2.510 seconds**.
The single frozen batch also passed 21-file Python grammar and both Make
inventories; the actual six new/updated owner and executor modules imported
from that snapshot. Six documents resolve 629 local file targets (not URLs
or anchors). No corrective rerun was required.

The run used cached Python 3.11.15, an empty environment, private user/network
namespaces, one CPU and a 240-second bound. Exact source archive, harnesses,
commands, logs, file hashes and results are retained under
`codex-offload/catchplate/engineering-builds/8fb767ac-core-handoff-2p5pkO/`.

Controls cover synthetic framing/signatures, closed CLI/protocol compatibility,
package fixtures, and real anonymous pipe/memfd/socket/PIDFD primitives. The
narrow packet tests use explicitly synthetic context, not successful core
owners. They do not run the complete protected cold ceremony or prove live
fs-verity acquisition/transfer, native adoption validation/signing, operational
launch, Nitro/KMS or independent approval. No native/full-artifact rebuild,
dependency change, cloud call or paid operation occurred.

## Remaining pilot and production work

The next integration is the receiving owner through operational v6 Retrieval
activation/C9, adoption authorization production, grants, closure, launch and
actual recovery/transition ownership. The independent cold supervisor must
compose and approve the entire graph using real provisioned inputs.
The acyclic order is current assignment/configuration/proof scope plus DRS/CSA
Runtime/v12 target histories, adoption authorization, endpoint C9/key pairs,
Publication grant, RetrievalGrant/v6, then matching cohort launch/release.
Neither adoption nor C9 may pin a future grant that depends on itself.

An immutable reviewed dependency snapshot, independently operated Nitro/KMS,
signing and witness services, and connected application/provider/YubiKey and
lifecycle acceptance remain required. Source **36/46** and production **0/6**
are unchanged. This is not yet a deployed pilot or production release.
