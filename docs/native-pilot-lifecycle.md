# Connected cold-to-adopted lifecycle

The `.414` owner and `.415` fixed executable connect actual cold-process ownership,
independently approved pair installation and the existing adopted supervisor. They do not generate
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

## Fixed executable caller (.415)

The completed source batch adds the explicit `--run-native-pilot-lifecycle` mode to
the existing packaged supervisor entrypoint. It selects only
`/supervisor/app/scripts/run_native_pilot_lifecycle.py`; legacy operational and
adopted-only modes keep their own argument contracts. The isolated interpreter
and fixed import roots remain unchanged.

An operator must supply, in source order, supervisor-inventory and original
listener-configuration FD/SHA-256 pairs, a preconnected approval socket and its
expected peer PID/UID/GID, then all 36 `--cold-authority-key purpose=fd` and 123
`--adopted-authority-key purpose=fd` selectors. These are descriptor numbers,
not secret values. Public and channel descriptors cannot alias keys. Existing
runtime and policy admissions still decide whether the actual keys are allowed.

The independent peer uses an explicitly selected lifecycle mode on the existing
approval channel. Bounded, ordered packets carry actual public originals;
kernel peer PIDFD and packet credentials authenticate the sender. Every response
is bound to the exact request and transfers real descriptors with `SCM_RIGHTS`.

| Stage | Actual request | Independently supplied descriptors |
| --- | --- | --- |
| Bootstrap | Cold sender observation and original listener configuration | Policy, recipe, intake configuration, conductor inventory, authority inventory: five FD/hash pairs |
| Rendezvous | Receiver-bound request from the real cold authority | Protected input and approval: two FD/hash pairs |
| Cold jobs | Each of the 66 genuine cold requests, in order | Protected input and approval for that request |
| Adopted jobs | Each of the 176 genuine adopted pending requests, in order | Protected input and approval for that request |

The receipt confirms descriptor delivery, not authorization or execution. The
existing owners admit those originals and drive the fixed installers. The
caller checks original BOOTTIME/UNIX limits and actual owners while waiting;
it neither creates approvals nor renews a deadline. Startup requires a prepared
machine-speed independent peer, not an unbounded manual prompt.

The lifecycle transport has a fixed 384-MiB aggregate wire ceiling: cold's
separately bounded raw dialogue needs base64/chunk framing in addition to the
existing adopted transport and bootstrap originals. Legacy modes retain their
128-MiB wire limit. Peer PID/UID/GID are explicitly selected; the peer need not
run as root merely to transfer already opened root-owned protected originals.
The caller itself retains its existing root requirement.

Polling checks retained identities instead of rereading the entire completed
cold transcript per packet. Both sides of each lifecycle operation still use
full original-content readback; clock and current-owner checks remain in waits.

Frozen `.415` source `508ea68e` passes all **95 checks in ten focused suites** in
**3.399 seconds**, with no failures, errors, skips or corrective rerun. All
twelve changed Python files pass syntax and both Make inventories; five actual
modules import from the exact archive. Real local controls cover a forked peer,
five-descriptor bootstrap, rendezvous pair, chunked cold request, malformed
rights, original BOOTTIME/UNIX refusal and observed child cleanup. These use
synthetic public observations, not independent production approvals or the full
244-exchange commissioning ceremony.

Only the changed supervisor export was rebuilt: build and exact-source
observation exited **0** in **62.244210958 seconds** overall. Its 6,227 entries
contain 1,387 exact source files: 1,374 in `/app`, six in `/authority` and seven
in `/supervisor`. This is an inert engineering export, not an installed or
independently approved package. The older conductor/authority exports remain
historical and do not form a matching-source package set with this supervisor.
Exact receipt details and the evidence destination are in the
[build results](native-pilot-build.md#current-engineering-assembly).

This command does not supply the peer's decision policy, keys, approved runtime
installation, protected resource parents, external services or production acceptance.

## Observed startup input composition (.416)

`native_pilot_lifecycle_inputs.bootstrap()` accepts the literal first-frame
sender/listener observations plus explicitly selected recipe, runtime inventories,
key bindings, policy mode and absolute UNIX limits. It composes the adopted
intake with the **observed** sender PID/start identity, then binds that exact
intake into the adopted supervisor policy. All three inventories must name the
recipe's same source; the recipe pins the conductor and authority inventories.
The signed bootstrap window, assignment, trust and closure set are checked,
and original startup/lifetime/UNIX limits are intersected, never renewed.

The result contains exactly the five candidate original byte strings expected
by bootstrap transport, their hashes and the intersected bounds. Existing
recipe/inventory bytes are preserved. Package association is not installed-tree
admission: the real runtime owners still perform that check.

`rendezvous()` composes the existing Execution/v2 from an independently selected
request hash and exact expected receiver PID/start/UID/GID. It preserves the
request's original window and expiry and emits no rendezvous approval.

Both functions are pure candidate compilers, not an approval provider. Their
caller must independently authorize the resulting bytes before delivering
protected descriptors. No signing keys, owners, files, approvals or services
are created. Complete cold66/adopted176 per-job composition and operation of
that independent provider remain required.

Explicit adopted policy/v2 additionally selects a
[bounded interactive interval](native-pilot-interactive.md#adopted-lifecycle-selection-416).
Policy/v1 remains stop-only; the existing lifecycle already waits for actual
interval completion before cleanup. Focused verification of this batch is pending.

## Verification and deployment boundary

The preceding `.414` source `90e10cbb` passes all **119 checks in twelve focused suites** in
**3.827 seconds**, with no failures, errors or skips. All sixteen changed Python
files pass syntax and both Make inventories; six new modules import from the
exact archived source. There was one run, with no corrective rerun. The four new
suites cover literal joins, catalogue/order/bounds, fixed installer arguments,
actual sealed public memory files and one bounded real child/PIDFD identity
check. They do not exercise the complete protected installer or lifecycle.

Pure association/argument controls and real local descriptor controls are not
evidence of the full protected listener, installer, fs-verity custody, signer
or service lifecycle. Current runtime export verification is recorded in the
[build results](native-pilot-build.md#current-engineering-assembly).
All three historical `.414` Python exports built and passed exact-source observation in
156.890 seconds, with identical source manifests and no retry. They contain
6,206 / 6,216 / 6,225 entries respectively. The exact source archive, focused
log, export archives, observation logs and checksums are retained at
`codex-offload/serverware/engineering-builds/90e10cbb-connected-lifecycle-FdUpzn/`
under the operator's home directory. These remain engineering-only exports,
not approved packages or installed runtimes. The `.415` supervisor-only refresh
above supersedes that supervisor export, not the conductor/authority snapshots.
No native rebuild, cloud action, paid test or live commissioning occurred.

The staged lifecycle API and fixed caller still require independently supplied
real late inputs/approvals and installed approved inventories. They do not
supply the operator's decision policy, a hosted approval service or an
interactive deployment frontend. The caller must not approve its own requests.
The original short startup window needs an independently
operated machine-speed provider; a manual approval prompt cannot silently renew
that window. Immutable dependencies and independently operated release,
Nitro/KMS, signing and witness infrastructure remain unprovisioned. Live provider,
YubiKey, ordinary application allow/deny and recovery acceptance remain open.
Source checkpoints remain **36/46** and production acceptance **0/6**.

See [observation-first rendezvous](native-pilot-genesis-rendezvous.md) and
[adopted orchestration](native-pilot-adopted-orchestration.md).
