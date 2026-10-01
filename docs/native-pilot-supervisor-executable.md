> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Commissioning supervisor executable

The `.392` source adds the missing outer executable and a separate runtime
package around the existing 164 commissioning jobs. It is not a self-provisioning
demo: protected policy, keys, resources and independent currentness decisions
must already exist. Focused verification and a new engineering export are pending.
Source checkpoints remain **36/46** and independent production acceptance **0/6**.

## Three distinct runtimes

| Runtime | Fixed namespace | Role |
| --- | --- | --- |
| Supervisor | `/supervisor/app` | Admit explicit v18 policy, compose fixed jobs and receive independent late approvals |
| Authority coordinator | `/authority/app` | Execute approved jobs with the exact 113 purpose-key selectors |
| Conductor | `/app` | Own the real native launch sequence and its cleanup |

The supervisor package includes the two existing child layouts without changing
their exact script populations. Its source inventory additionally covers the
supervisor namespace. Each inventory is independently pinned; the supervisor
inventory does not manufacture or replace either child approval. The CLI checks
its own installed runtime and original descriptor before reading purpose keys
or creating a child. All three source identities must match.

The fixed entry is `scripts/native_pilot_supervisor_runtime_entrypoint.py`,
which invokes `scripts/run_native_pilot_supervisor.py` using the packaged isolated
Python interpreter. Required inherited descriptors select the supervisor,
conductor and authority inventories, explicit policy/v18, measured recipe,
approval socket and exact purpose keys. Inventory, policy and recipe originals
also require independent SHA-256 pins. No secret belongs in command-line text.

## Independent approvals after real observations

Eight current-head decisions cannot be predicted by static policy. At each real
pause, the supervisor sends the actual pending request and observed originals
over a preconnected Unix `SOCK_SEQPACKET` channel. The peer's kernel credentials
and live PIDFD are checked; packet credentials bind the actual sender as well.
Bounded ordered packets carry large public originals without assuming that a
multi-megabyte record fits one socket packet.

The independently operated peer returns request-bound hashes plus exactly two
`SCM_RIGHTS` descriptors: the already approved input and approval originals.
Numeric descriptors in JSON are not accepted as a substitute. The existing
current-head owner validates and consumes those originals; only the supervisor
then installs them at its exclusive destinations. The peer must not run the
competing approval installer first.

A request-bound receipt acknowledges descriptor delivery, not policy acceptance
or execution. The peer waits for that receipt before retiring after its eighth
reply; ordinary post-approval jobs do not require the peer to remain alive.
Termination signals are deferred only across short descriptor-ownership
transfers, never across the socket's polling wait.

This transport is not an approval service. It creates no currentness decision,
signature, key, renewed deadline or approval provenance. The peer's adapter
receives requests and sends independently prepared originals; its actual policy,
protected signing services and resource provisioning remain external work.

## Build only

With the existing strict clean-source and reviewed dependency prerequisites:

```sh
make build-native-pilot-supervisor-runtime \
  NATIVE_PILOT_OUTPUT=/srv/catchplate-fast/tmp/NEW-SUPERVISOR-OUTPUT
```

The fixed `native-pilot-supervisor-artifact` target reuses the pinned Python,
vendor and distroless base, existing network-disabled build steps and bounded
TAR materializer. It writes a separate supervisor inventory, portable package
and `supervisor-runtime.json` only after exact source/readback checks. The report
selects supervisor policy/v18, bridge launch/v7 and RPC runtime/v11 explicitly;
it does not relabel the legacy aggregate build preparation's v5/v9 profiles.

The existing engineering-only raw export can select the new fixed target with
its separate dirty-tree/bounded-build flags. Such an export remains
`production_release_eligible=false`, is not a strict-source package and cannot
be passed off as approved installation or deployment. No build command launches
the supervisor or provides its protected descriptors.

## Cleanup and acceptance boundaries

Signals stop normal progression and enter the real owner's cleanup path.
Partial construction retains separately acquired owners. Runtime and approval
handles are released only after known terminal cleanup; ambiguity retains the
process and handles instead of reporting success or retrying authority.

The distinct operational cleanup gap described in
[final continuations](native-pilot-final-continuations.md#remaining-pilot-and-production-work)
remains: genuine effect intents, fresh-helper registration and compatible worker
parent/reap ownership still need connection. This launcher does not turn shutdown
observations into cleanup receipts.

Complete constructed Nitro/census authentication, startup performance, actual
connected allow/deny/cleanup execution, dependency publication, protected
provisioning and all independent production gates remain unverified.
