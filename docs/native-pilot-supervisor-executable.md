> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Commissioning supervisor executable

The `.392` source adds the missing outer executable and a separate runtime
package around the existing 164 commissioning jobs. It is not a self-provisioning
demo: protected policy, keys, resources and independent currentness decisions
must already exist. All 29 focused controls passed; the engineering artifact
built, materialized and passed exact source-byte observation.
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

## Focused verification

Exact source `bd69e925f1fd1adb15cc8cef0e0476a8caf00053` passed **29/29 controls
in five selected suites**, **12-file Python 3.11.15 grammar/both Make inventories**
and **59 relative documentation links**, in **1.831 seconds** (exit **0**).
The run used an exact Git archive, an empty environment, one CPU, a separate
network namespace and a 240-second cap. Database/app/authority-store modules
were not imported.

Eight controls use real local Unix sockets, kernel credentials, PIDFDs and
descriptor transfer: all eight ordered exchanges, multi-packet originals,
request/reply refusals, expired deadlines, extra/truncated descriptor cleanup,
retained reply ownership and final peer retirement after a receipt. Their
observations and descriptor contents are synthetic, not genuine currentness
approvals. The packaging controls use a small synthetic ELF/source tree, not a
running installed interpreter. CLI ordering checks are source assertions, not
a privileged 164-job execution. Signal-ownership guards were source reviewed;
no asynchronous termination fault-injection campaign was run.

Two initial preflights stopped before any controls: the harness first counted
Make command uses as inventory entries, and the corrected exact-entry check
then exposed the shared image builder missing from both inventories. Commit
`bd69e925` adds that registration; no authority or runtime guard was weakened.
The complete focused pass above ran once after that correction.

Exact source archives, commands, harnesses, logs and checksums are retained at
`codex-offload/serverware/engineering-builds/bd69e925-supervisor-executable-Qj6hRl/`.
The tested Git archive SHA-256 is
`cc1534255c99a846d90fd1b2b66b8bd7e641d778e0e57c663b3ff95cf5ca0ed9`.

## Engineering artifact result

The `.414` refresh from `90e10cbb` supersedes the Python export below: all three
runtime targets built and passed exact-source observation with identical source
manifests. The supervisor has 6,225 entries and 1,385 exact source files
(1,373 in `/app`, six in `/authority`, six in `/supervisor`). This includes both
cold installer CLIs and their fixed admitted entrypoint. It remains an inert
engineering export, not an installed runtime or executable lifecycle caller.
See [current assembly and retained evidence](native-pilot-build.md#current-engineering-assembly).

One raw supervisor build from frozen base `bd69e925` exited **0** in **29.682
seconds**. It reused the unchanged unpublished dependency candidate in an
isolated checkout: exactly three manifest substitutions and six cache artifacts,
all nine byte/hash checked. The canonical dependency pins were not changed.
The existing fixed bounds were eight CPUs, 24 GiB and zero swap per RUN, not an
aggregate worker cap. Build steps used `network=none`; the BuildKit daemon also
performed pinned base-image registry metadata/auth requests.

The **169,449,472-byte** archive materialized successfully into **6,150 entries**
with **164,894,893 regular-file bytes**. Archive SHA-256:
`4ab79a5629877e65ca38d38ea2cce088f59978c70698e0ea24b9db258882b86f`.
The corrected read-only observer then verified **1,310 exact source files**:
1,303 in `/app`, five in `/authority`, and two in `/supervisor` (exit **0**, **1.163
seconds**). All source files were 0444; `/app` was 0755 and the other ten source
namespace directories 0555.

The original combined harness exited **1** after successful materialization
because its extra observer incorrectly required `/app` to be 0555. That was
stricter than the existing runtime profile. Its failure remains preserved;
only the read-only observer was corrected, with no rebuild, rematerialization
or production-validator change.

These remain engineering bytes with `production_release_eligible=false`.
No strict-source inventory/package, installed runtime, dynamic-loader execution,
164-job supervisor, native service, signing, provider or paid cloud acceptance
was produced. The raw artifact, both observer outcomes and checksums are retained
beside the focused-check evidence above.
