# Connected cold-to-adopted lifecycle

The `.414` batch connects actual cold-process ownership, independently approved
pair installation and the existing adopted supervisor. It does not generate
decisions, provision keys, install a runtime or claim an accepted pilot. The
existing 66 cold jobs, 176 adopted jobs and approval wire formats stay unchanged.

## Ownership and ordering

`serverware.native_pilot_lifecycle` exposes a staged owner for an independently
operated caller. Late inputs are supplied only after their actual predecessors
exist; no future receiver PID, core or successful child result is fabricated.

1. Prepare and launch the one fixed cold authority from its independently
   pinned installed supervisor inventory. Retain its actual child, PIDFD and
   pipes; join the sender observation to that child's PID and start identity.
2. Supply independently approved adopted policy, measured recipe, intake and
   runtime inventories. Start the existing adopted supervisor/authority and
   nested receiving conductor, but do not call its blocking first job yet.
3. Receive the real receiver-bound rendezvous request. Join the receiver to the
   retained adopted authority's actual child lineage and retain its own PIDFD.
   These associations do not themselves approve the action.
4. Supply the independent Execution/v2 and rendezvous approval. A separately
   owned fixed installer publishes input first and approval last. Buffer its
   stdout through both EOFs, exact successful exit and consuming same-PIDFD
   reap; only then forward the existing reply to the cold authority.
5. Drive all 66 cold jobs using their genuine requests and independently
   supplied input/approval originals. Each fixed installer also receives the
   exact admitted Execution/v2 original, which supplies the UNIX ceiling absent
   from the old job wire. No job configuration or approval is synthesized.
6. Accept the literal cold Bundle only after core custody acknowledgment,
   actual cold-authority cleanup, successful exit and consuming reap. Continue
   the existing 176 adopted jobs and their normal terminal cleanup.

Original boot/time namespace, BOOTTIME and UNIX limits apply across waits,
publication, reply forwarding and cleanup. Filesystem stalls still require an
external watchdog. No restart, replacement, unbounded wait renewal or unknown
cleanup is treated as success. Actual partial owners remain reachable.

## Fixed installer packaging

The supervisor inventory and Docker target now include
`native_pilot_genesis_install_runtime_entrypoint.py` and both installer CLIs.
The entrypoint admits that installed runtime before selecting exactly one of:

- `--install-rendezvous`: supervisor inventory plus request/input/approval FD
  and SHA-256 pairs.
- `--install-job`: the same pairs plus the original Execution/v2 configuration.

There is no arbitrary module, executable or destination argument. Cold job
destinations come only from the existing catalogue under
`/etc/serverware/native-genesis-authority`. Input and approval names must be
absent; no parent creation, overwrite, rollback or deletion is performed.
The parent creates seals only for literal public observations, not approvals.

## Verification and deployment boundary

This source batch is being assembled before one focused frozen check run.
Pure association/argument controls and real local descriptor controls are not
evidence of the full protected listener, installer, fs-verity custody, signer
or service lifecycle. The preceding `.413` raw exports do not contain this code.

The staged lifecycle API still needs an independently operated caller supplying
real late inputs/approvals and installed approved inventories. This batch does
not supply that operator's policy, a hosted approval service or an interactive
deployment frontend. Immutable dependencies and independently operated release,
Nitro/KMS, signing and witness infrastructure remain unprovisioned. Live provider,
YubiKey, ordinary application allow/deny and recovery acceptance remain open.
Source checkpoints remain **36/46** and production acceptance **0/6**.

See [observation-first rendezvous](native-pilot-genesis-rendezvous.md) and
[adopted orchestration](native-pilot-adopted-orchestration.md).
