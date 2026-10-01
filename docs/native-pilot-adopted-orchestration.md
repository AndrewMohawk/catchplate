# Adopted pilot orchestration

The `.412` integration connects the explicitly selected adopted conductor,
authority executor and independently operated supervisor. It also supplies the
real cold sender's listener rendezvous and the receiver's own authenticated
connection. This is implementation work, not a deployed or accepted pilot.
Source remains **36/46**; independent production acceptance remains **0/6**.

## Actual custody handoff

The cold process creates the fixed root-protected UNIX sequence-packet listener
at `/run/serverware/native-pilot-core-handoff/core.sock`. It reports its actual
process/start identity and socket observation over the protected approval channel.
The independent operator uses that observation to approve and launch the actual
receiver, then approves the existing cold execution/v2 configuration naming that
receiver's actual PID. The pre-job approval retains exactly the listener's
original window and UNIX expiry; waiting for this approval does not renew them.

The receiving conductor creates its own client socket. Inheriting a parent's
connected socket or socketpair would identify the wrong creator and cannot
substitute. Kernel peer credentials, the actual peer PIDFD, process start ticks
and per-message credentials bind the connection. The existing cold core owner
transfers the original fs-verity descriptor after its cold services retire;
the existing receiver checks and retains it before acknowledging custody.
Only that real `ReceivedGenesisCore` enters `Operator.run_adopted`.

The independent rendezvous operator remains a deployment prerequisite. The new
source does not provision it, synthesize its approval, guess a future PID or
reconstruct the core from the public observation. Unknown cleanup keeps actual
owners reachable; it does not authorize a retry or deletion of existing paths.

## Selected operational sequence

The legacy catalogue and its approvals remain separate. The adopted catalogue
uses OperatorRequest/Reply v2, AuthorityJobRequest/Reply v2 and Approval v2 under
`/etc/serverware/native-pilot-adopted-authority`. Request2 and Approval2 carry the
original UNIX expiry as a canonical decimal string. The independently approved
intake configuration carries the original signed-integer expiry. Each owner
checks the original BOOTTIME and UNIX ceilings while waiting and performing I/O.

Early ordinary initial histories and the actual runtime/history installation
precede ordinary C9 and native-validated adoption approval. Endpoint inputs and
the four composite C9 deliveries follow. Ordinary generation grants wait until
the conductor has produced its actual driver generation recipe; no future
receipt is invented to fill that dependency. The remaining eleven-endpoint,
ordinary publication, launch and five-file material jobs then feed current heads,
Runtime14, the bridge authorization chain and Launch10.

Selected precreation publishes the exact Config8/Launch7 bundle's twenty files.
Public slots for Wrapper3, the two ordinary publication grants and the adoption
authorization are explicit opt-ins. Ordinary publication/runtime installation
does not overwrite existing files or interpret public metadata as live custody.

## Independent decisions and packaging

The packaged `--run-adopted-native-pilot` entry takes a protected intake
configuration FD and its independently approved hash. Parent and child retain
their own copies; no private authority key is forwarded to the conductor.
The same pinned packages contain both source-fixed modes. Inventory default
commands remain legacy defaults, not proof of adopted runtime execution.

The selected supervisor retains complete protected input plus an independent
Approval2 for each pending job. It authenticates the source associations before
exclusive installation and replies only to that original live request. It does
not turn successful validation into an approval or generate one from a policy
fragment. Automatic composition of every independently approved input, deployment
of the approval operator and actual protected rendezvous are not claimed here.

## Verification and remaining work

Source is being assembled before one focused frozen Python batch. New controls
cover selected protocol/CLI boundaries, fixed publication slots, intake and
listener framing and exact catalogue/source binding. Actual protected services,
signers, native validator ceremonies and full core-to-operational lifecycle
remain to be exercised. No native/dependency changes or unchanged native/artifact
rebuild is planned; no cloud or paid operation is included in this batch.

Full completion still needs immutable reviewed dependencies, independent signing
and witnesses, Nitro/KMS custody, release provenance, provider/YubiKey ceremonies,
application flows and full lifecycle/error/recovery evidence. Neither a complete
job roster nor successful synthetic controls closes those production gates.

See [the preceding authorization integration](native-pilot-adopted-authorizations.md).
