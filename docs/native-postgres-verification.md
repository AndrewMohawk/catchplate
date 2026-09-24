# Native PostgreSQL verification inventory

## Status and boundary

The source includes a closed inventory and fixture-result contract layer. The
separate [v12 runner-bounds checkpoint](coder-runner-bounds-v12.md) makes
nonroot execution and resource/storage bounds part of the admitted runner
identity, with fresh output ownership and exact pre-start container checks.
The source now also includes a fixed, cooperative PostgreSQL cluster runner,
described below. It has not been executed, does not install a PG16 test image,
and is not wired to the controller's native output consumer. None of these
source checkpoints provides native execution evidence.
The current source remains unbuilt and unexecuted. The fourteen suites remain in
`CODER_EXCLUDED_TEST_SCRIPTS`; their standalone entrypoints and result files do
not remove that exclusion or satisfy changed-test coverage admission.

The workflow in [goal.md](../goal.md) still requires all mandatory clean-room,
browser/Node/npm and response-proof controller prerequisites, an exact clean
source freeze, one approved preparation, and sequential no-build verification.
An independently approved coverage baseline is not a caller-chosen parent
commit. Repository-authored manifests or cooperative fixture reports cannot
supply independent approval, installed controller identity or cleanup proof.

## Closed source inventory

[native_postgres_inventory.py](../serverware/native_postgres_inventory.py)
defines `serverware.nativePostgresInventory/v1`, fourteen ordered frozen
`NativePostgresSuite` records and `TOTAL_TESTS = 289`. Each record contains an
exact script path, an explicit sorted tuple of `Class.test_method` IDs, its
disposable-cluster CLI acknowledgement requirement and its timeout in seconds.
The IDs are authored source declarations, not dynamically discovered or
executed results. The total includes the pure representation and source-linkage
methods contained in these fixtures; it is not a count of 289 native SQL tests.

| Order | Script under `scripts/` | Methods | Timeout | Extra disposable CLI flag |
| --- | --- | ---: | ---: | --- |
| 00 | `test_webauthn_trust_projection_postgres.py` | 12 | 300 s | No |
| 01 | `test_postgres_trigger_manifest.py` | 5 | 300 s | No |
| 02 | `test_authority_mutation_postgres.py` | 14 | 300 s | No |
| 03 | `test_authority_root_transition_postgres.py` | 54 | 300 s | No |
| 04 | `test_authority_primary_tree_postgres.py` | 9 | 300 s | No |
| 05 | `test_authority_audit_initialization_postgres.py` | 31 | 300 s | No |
| 06 | `test_authority_audit_initialization_store_postgres.py` | 36 | 900 s | Yes |
| 07 | `test_authority_global_audit_capacity_postgres.py` | 25 | 300 s | No |
| 08 | `test_authority_verifier_read_postgres.py` | 21 | 300 s | Yes |
| 09 | `test_authority_wire_json_postgres.py` | 14 | 300 s | No |
| 10 | `test_authority_counted_hash_postgres.py` | 10 | 300 s | No |
| 11 | `test_authority_counted_projection_postgres.py` | 16 | 300 s | No |
| 12 | `test_authority_counted_store_postgres.py` | 10 | 300 s | No |
| 13 | `test_authority_counted_maintenance_postgres.py` | 32 | 300 s | No |

Three issuer transaction components extract the real connector's first
application SQL statement without importing its facade. Different initial
connection defaults must become SERIALIZABLE READ WRITE NOT DEFERRABLE before
reads/writes; a late change after a read must fail. The third control exercises
nested savepoint denial and outer rollback, not the actual service handler or
a top-level commit. Random fixture schema/data disappear on rollback. There is
no full-connector, mTLS, role/ACL, issuance or deployment proof. All 286 earlier
IDs, fourteen suites, sixteen children and deadlines remain; root suite54 and
total289 are authored inventory counts, not executed results. No new native
import/source dependency is added.

Four capability-custody methods use the exact base writer table, v9 extension,
post-table guards and actual immutable attachment in a rollback-owned schema.
Independent opaque 36/12/28/44/20-column planner/retained-plan/execution/writer/
sidecar rows cover both deferred-cycle orderings, missing or mismatched links,
protocol and canonical transport constraints, every immutable field, frozen
reservation identity, status-only reconciliation and later-failure rollback.
The opaque bytes are explicitly not cryptographic evidence. Simple execution
identity and retained-plan foreign keys do not prove mutable execution fields
or the planner's capability identity. No installed issuer, ACL, migration,
top-level commit or execution is established. The original serializer method
also checks historical credential-binding length-domain framing with the real
SQL helper and an independent oracle, preserving that method's prior ID.
All 282 prior IDs remain; fourteen suites, sixteen children and deadlines are
unchanged. These additions are authored and unexecuted.

Eight counted-transition component methods start from the same genuine retained
fixture and binder, seed full independent populations for all eleven counted
profiles, and run real counted SQL maintenance between the private before/after
guards. They check the exact six-role/five-read-profile plus actual-write union,
membership-dependent revisions, unchanged read-only heads, complete leaf/node
stores, and rollback after an actual after-head mismatch. DDL-admitted stale or
missing heads deny without repair. Explicitly corrupted component documents are
injected only after the original binder to isolate source-closure and phase
guards; they are not claimed to be valid signed plans. The preceding caller's
primary live-root validation/locking, business writes, full executor admission,
historical retries and atomic terminal publication remain outside this lane.
These additions are authored and unexecuted; suite/child counts and deadlines
are unchanged.

Eight retained-binding methods use independently constructed, genuinely
signed v4 fixture bytes and a real Python raw-replay sanity check, then invoke
the separate production SQL binder against caller-locked parent and actual
sidecar rows under full v9 DDL. They compare original envelope/context/payload
bytes, the mixed transition and its primary subdocument, the retained header,
and the nine-frame Snapshot/v4 digest. Fresh byte anchors do not hide aliases,
duplicate decoded keys, changed closed fields, parent/context mismatches or
stale transition/header commitments. Malformed codecs and small context inputs
exceeding the post-parse node/depth ceilings also deny. A canonical false
signature deliberately passes integrity-only SQL and still fails the genuine
signed verifier: the binder supplies no cryptographic authority. The active
legacy v3 loader still rejects v4. These eight controls are authored and
unexecuted, not evidence of current roots/time, public activation, SQL proof
replay or committed execution.
All 266 previous IDs remain; fourteen suites, sixteen children and deadlines
are unchanged. The native source closure includes the genuine revocation
fixture/verifier imports as well as the new SQL renderer.

Four earlier custody methods cover the existing thirty-five-column assertion
and twenty-one-column authorization-projection tables under the same actual
v9 DDL and source-extracted immutable attachments. They pin primary/unique
identity conflicts, every column's UPDATE denial and DELETE denial, then force
a later immutable-row failure after all four custody rows were inserted and
the parent/sidecar deferred constraints closed. Savepoint rollback preserves
the prior rows. The fixture explicitly records that projection-to-evidence
foreign-key enforcement is absent; it does not invent a custody-chain FK.
These are authored, unexecuted structural controls, not crypto admission, the
production storage-helper call path, live ACLs or top-level commit evidence.
All 262 previous IDs remain; fourteen suites, sixteen children and deadlines
are unchanged. No new native import/source dependency is introduced.

Six added retained-record custody methods use the full production v9 DDL,
post-table retention guard and actual immutable-row function/trigger in a
random, rollback-owned PostgreSQL schema. They exercise the versioned
parent/sidecar constraints and immutable reservation/retained fields. Deferred
foreign-key failures are forced with `SET CONSTRAINTS ALL IMMEDIATE` inside
savepoints, not observed at a real commit. These are constraint components,
not original-envelope/signature verification, installed ACLs, migration,
coordinator/service integration or execution authority. All 256 previous IDs
remain; fourteen suites, sixteen children and every timeout are unchanged.
The six methods are authored and unexecuted.

Four added credential-policy methods use the fixed expression interpolated into
the active v9 executor, the actual wire serializer and domain-digest function,
and an independent sixteen-field policy oracle. They compare SQL and Python
documents/digests, distinguish nullable and textual AAGUID values, and check that
an AAGUID-only change invalidates the old claim in the component equality
predicate. Missing and nonstring values explicitly demonstrate the expression's
boundary: it is not full-row admission or a substitute for the executor's locked
row comparison. These methods do not execute the full executor or prove CAS,
independent roots, live credentials or deployment. All 252 previous method IDs,
fourteen suites, sixteen children and deadlines remain; none has been run.

The six appended counted-reader methods execute the unchanged production-qualified
SQL against an independently seeded `serverware_metadata` schema. They reject
any pre-existing canonical namespace, even empty, before a plain CREATE inside
the fixture-owned SERIALIZABLE transaction. All new objects and rows disappear
by rollback; no namespace adoption, SQL rewriting or DROP is permitted. The
cases cover all eleven profiles, partition moves, no-target profiles, future or
mismatched stored records, missing/corrupt evidence and preservation of an
existing sentinel namespace. Their current status is authored and unexecuted.
Suite/process counts and deadlines are unchanged; the existing 300-second suite
ceiling is not a measured performance claim or permission to skip cases.

Eight further counted-maintenance methods exercise the actual primary row-trigger
renderer and counted installer. Six cover all six indexed source tables and
eleven profiles, full-row/equal updates, membership and partition moves,
primary-key DELETE/INSERT normalization, later-failure rollback and retry, and
missing-head denial. Two exercise fresh empty installation, unchanged populated
restart, populated fresh-store refusal and missing-head refusal. Synthetic
business tables use the real primary/count storage and function definitions;
they are not a complete production schema or foreign-key integration test.
Independent primary and counted tree oracles check the results without invoking
the counted dispatcher a second time. All previous 244 method IDs remain;
fourteen suites, sixteen child processes and deadlines are unchanged. These
eight methods are authored, not executed or passing evidence.

All fourteen require a prepared disposable local environment. A `False`
`disposable_cluster` field means that the particular fixture has no extra
`--disposable-cluster` switch; it does not permit a production or shared
database. The frozen records are data, not capabilities. The no-argument
`validate_inventory()` checks the fixed inventory's exact metadata, bounds,
ordering, uniqueness and total without importing fixtures, reading files or
running tests. It does not prove that fixture discovery or observed execution
matches those declarations.

The two newly authored primary-tree cases use the actual batched `VALUES`/`CASE`
reader through a psycopg dictionary-row cursor. Seventeen trigger-maintained
rows support four selected identities covering presence and absence across
outbox and non-global aggregate relations. Expected proofs come from independent
small-tree reconstruction and are also compared with the existing singleton
reader. A forced cross-table batch and rollback-scoped oversized-node/stale-node
controls cover the native query shape without disabling schema constraints.
These cases are unexecuted; they do not establish current roots, complete
predicate ranges, production planner execution or passing native admission.

The appended counted-hash and row-projection suites retain all 184 previous
method identities and their order/deadlines. Their 26 new component methods
install only real function definitions in rollback-owned random schemas and
compare native results with independent framing, tree and row-codec oracles.
They do not install counted storage, maintenance triggers, heads, grants or
bootstrap authority. Native parity remains unexecuted.

The appended ten-method counted-store suite preserves all 210 previous method
identities, suite order and deadlines. It exercises fresh table definitions and
catalog constraints only, in a rollback-owned random PostgreSQL namespace. The pure
renderer accepts one exact quoted namespace and creates no heads, defaults,
privileges or maintenance triggers. It deliberately has no `IF NOT EXISTS`
path: the component is not an installer or a populated-store migration. Future
activation must coordinate qualified PostgreSQL DDL with the real and scratch
schema programs without changing their SQLite path or treating an absent head
as authenticated empty state. See the
[storage integration contract](authority-index-storage-integration.md).

The appended eighteen-method maintenance suite preserves all 220 prior method
identities, suite order and deadlines. It installs the real path and all-profile
dispatch definitions over independently seeded component trees, invokes explicit
OLD/NEW events, and compares every resulting head, leaf, node and revision with
an independent model. Corruption and late-profile failure controls remain within
savepoints in the rollback-owned transaction. No business-row trigger is
attached: fixture-supplied images and seeded roots do not establish authenticated
row provenance, bootstrap, whole-transaction work bounds, concurrent lock-order
behavior, currentness or production writer admission. These cases remain unrun.

## Fixed future invocation profile

[native_postgres_batch.py](../serverware/native_postgres_batch.py) constructs
only the fourteen source-fixed command tuples. `prepared_fixture_argv(index)` rejects
non-integer, boolean and out-of-range indices; it accepts no caller-selected
script, selector, DSN or executable. Its fixed profile is:

- Python: `/usr/local/bin/python3.11`.
- Read-only source: `/opt/serverware/src`.
- DSN: `host=/run/serverware-native-postgres port=5432 dbname=postgres user=serverware_fixture_admin`.
- Reports: `/opt/serverware/output/native-postgres/reports/00.json` through
  `13.json`, supplied with `--prepared-result`.
- The two inventory-marked scripts receive `--disposable-cluster`; every script
  receives `-v`.

These tuples alone do not execute anything or create the named paths. The
source-owned lifecycle below creates fresh canonical mode-0700 Unix-socket and
report directories and a disposable database cluster before using them. An
independently admitted image, command and resource profile remain required. A fixture
acknowledgement flag is not evidence of that ownership. Tests retain their real
connection-admission and cleanup checks; the result contract is not a registry
bypass or replacement database facade.

## Required result and preparation closure

[native_postgres_results.py](../serverware/native_postgres_results.py) provides
`run_native_fixture(script, *, argv, result_path)`. Without a result path it
retains ordinary standalone `unittest` behavior. Prepared mode admits only the
source-owned script, its actual `__main__` file/classes, exact loaded method
inventory and the remaining `-v` argument. It records method and subtest
callbacks, bounded fixture/protocol errors and normal runner completion in a
canonical ASCII `serverware.nativePostgresFixtureResult/v1` document, bounded
to 256 KiB. The actual fourteen fixture CLIs expose `--prepared-result`; the helper
does not create a database or grant fixture permission to access one.

The pure `reconcile_native_postgres_batch(observations, *, source_sha256)`
consumer joins exactly fourteen ordered reports to separately supplied prepared
script digests and process/log observations. `PASS` means complete successful
test accounting; `FAIL` means a completed negative result; `INCOMPLETE` covers
missing/interrupted accounting, protocol failures or inconsistent process
termination. After report writing, prepared fixture exits are respectively
0, 1 and 2. A timeout, lost process, absent report/log or mismatched terminal exit cannot become
`PASS`; malformed inputs raise rather than being repaired. Neither the
consumer's frozen summaries nor the fixture reports are authority tokens.

A complete successful batch must account for each exact inventoried method
once, with no missing, extra, duplicate, skipped, expected-failure, unexpected-
success, failed or errored case. Partial execution, setup failure, timeout,
missing terminal reports or unsuccessful cleanup must not become a passing
batch. Case identities and process results must be reconciled, not inferred
from exit zero or a final text summary alone. Fixture-authored JSON is
cooperative evidence; independently observed exit status, bounded exact logs
and the admitted runtime/source identity remain separate inputs.

Future preparation must bind the inventory, fixture files and full transitive
Python/source closure to the clean commit/tree and approved coverage baseline.
It must also bind the exact command tuples, recorder/consumer, report schemas,
PG16 server/client binaries, Python/psycopg/libpq, shared libraries, locale and
UTF8 configuration, runner/courier, OCI/rootfs and source/artifact manifests.
The existing engineering Dockerfile's unversioned `postgresql` package install
does not establish this PG16 runtime closure. A separate pinned PostgreSQL
service image does not automatically become the Python fixture runner image.

The Makefile explicitly requires the four counted fixtures' repository dependency
closure through `CODER_COUNTED_NATIVE_SOURCE_DEPENDENCIES`: the hash, projection
and fresh-store/path/maintenance renderers, existing canonical/wire SQL, source profile and proof code, imported
independent tree/partition oracles, package-import dependencies, and `db.py` read
as source by the existing native digest helper. These are frozen-file presence
and nonsymlink checks, not a separate per-dependency digest protocol. The whole
approved frozen archive still binds their bytes;
`serverware.nativePostgresPreparedSources/v1` remains the unchanged script-digest
object below.

The retained-record additions reuse that existing closure: the real v9 schema
and retention-guard renderer are in `v9_schema_source.py`, and the immutable
function/trigger are read from bounded `db.py` source without importing its
runtime facade or the blocked registry. No extra runtime dependency or lane
timeout is introduced.

## Fixed cluster lifecycle source

[run_native_postgres.py](../scripts/run_native_postgres.py) is a no-argument,
no-build component entrypoint. It invokes
[native_postgres_runner.py](../serverware/native_postgres_runner.py), not a
generic shell or database service. It accepts no caller-selected DSN, script,
SQL, executable, output directory, environment or timeout. Its source profile
requires Linux/amd64, Python 3.11, UID/GID `10001:10001`, read-only root-owned
source/artifacts/executables, and no ambient `PG*` configuration. These local
checks complement rather than authenticate the external signed plan.

The new required toolchain prefix is `/opt/serverware/postgresql-16/bin` with
`initdb` and `postgres` at those exact paths. This is a source contract, **not an
already prepared or pinned toolchain**. The future image must provide the
same-ABI PostgreSQL server, shared data, executable/library closure, Python and
psycopg/libpq, and the operating-system account for UID/GID 10001. Copying an
Alpine server into a glibc Python image does not provide that closure. The
existing engineering image also inherits ports rejected by the closed runner
inspection profile; it is not implicitly compatible.

The entrypoint reads the fixed read-only artifact
`/opt/serverware/artifacts/native-postgres-sources-v1.json`. Its exact canonical
ASCII JSON object has only `schema: serverware.nativePostgresPreparedSources/v1`
and `scripts`, with fourteen ordered objects containing only `path` and `sha256`.
Paths follow the inventory above and hashes are canonical `sha256:` strings.
The independently admitted artifact CAS must bind these prepared expectations
and the entire transitive source/runtime closure. Generating this small JSON
from the current checkout is not source approval. All fourteen fixture files are
remeasured against the supplied expectations before and after execution.

The lifecycle:

1. Exclusively creates `/var/lib/serverware-runner/native-postgres/pgdata`,
   `/run/serverware-native-postgres`, and fresh `native-postgres/reports` and
   `native-postgres/logs` children of the private lane output. Existing paths
   are rejected, never adopted, repaired or removed.
2. Runs fixed `initdb` as nonroot with UTF8, libc `C` locale, page checksums,
   the disposable bootstrap superuser, local trust and host rejection. `--no-clean`
   preserves incomplete initialization for outer teardown; no `--no-sync`,
   alternate WAL directory or retained cluster is permitted.
3. Starts foreground PostgreSQL with no TCP listener, the private Unix socket,
   durability settings enabled, explicit conservative server settings, and
   `restart_after_crash=off`. A fresh cluster is essential: the fixtures create
   actual LOGIN roles, committed databases and privileged catalog/ACL state.
4. Uses deadline-driven nonblocking libpq readiness and repeated identity
   checks while continuing to drain the server log. The fixed query verifies
   PG16, UTF8, actual current/session admin identity, direct superuser, Unix
   transport, no recovery, the exact configuration and observed cluster system
   identifier. This is not independent server or image authentication.
5. Starts exactly the fourteen fixed fixtures sequentially. Every child has an
   independent deadline and live-bounded combined stdout/stderr capture.
   Reconciliation uses actual retained exit state, bounded report bytes and
   complete log hashes. Failure, timeout, log loss, unexpected server exit,
   cancellation, report mismatch or source drift stops further scheduling;
   attempted processes never become `not-started`, and remaining fixtures
   cannot become passing omissions. No fixture or cluster is retried.
6. Stops remaining direct fixture children, requests a bounded PostgreSQL fast
   shutdown, and reaps retained direct children. A forced kill, an already-dead
   server, incomplete logs or remaining socket prevents observed clean shutdown.
   Every signal normally uses the retained pidfd, never a PID file. The only
   setup fallback targets the exact still-unreaped `Popen` child if pidfd
   acquisition fails immediately after spawn.

[native_postgres_process.py](../serverware/native_postgres_process.py) retains
at most sixteen direct children and 8 MiB of combined log bytes per child
(128 MiB aggregate in-memory prefixes). An overflow prefix is preserved but
cannot qualify as a complete log. Missing pipe EOF has a finite drain window;
cleanup continues after cancellation or selector failure. The component does
not use Docker's rotating log as complete fixture evidence.

The runner exclusively publishes a bounded canonical
`native-postgres/runtime-result.json` using
`serverware.nativePostgresRuntimeResult/v1`. It contains exact fixture process
states, cooperative test accounting, source expectations/readback, cluster
observation, per-process log hashes/sizes/completeness and local cleanup
observations. Exit zero requires `runtimeStatus: COMPLETE`; every other outcome
exits 2 or fails before publishing a usable result. A missing or partial result
is not completion. `externalDestructionRequired` is always true: the runner
neither deletes PGDATA nor claims descendant/cgroup/container destruction.
PostgreSQL children may have separate sessions; killing/reaping the postmaster
is not proof that those descendants are gone. The final independent controller
must still destroy the complete namespace, mounts, cgroup and storage and issue
its authenticated `DESTROYED` receipt. The native document does not fabricate
`BodyExecutionResultV12`, courier/runtime evidence or release authority.

This implementation follows the documented
[PG16 initialization](https://www.postgresql.org/docs/16/app-initdb.html) and
[fast-shutdown semantics](https://www.postgresql.org/docs/16/server-shutdown.html).
The source-owned test scripts use synthetic process, clock, libpq and filesystem
boundaries; they have not been run and do not establish real cluster behavior.

## Remaining image and controller work

The v12 protocol can carry a fixed no-build runner command without adding a
general-exec operation or giving repository code Docker authority. A local
PostgreSQL child and Unix socket can live inside that runner. The existing
network service contract, which uses endpoint authorities/ports and HTTP health
checks, is not a Unix-socket transport for these fixtures. Do not weaken the
fixture DSN restrictions or expose a host socket to make it fit.

The fixed cluster lifecycle and bounded local log capture are source-implemented
but unverified. PG16 image construction, admitted deadlines, output quota,
controller-bound native result consumption and authenticated controller
cleanup are still incomplete. `RunnerIdentity.executionBounds` requires
an admitted nonroot user/group, CPU, memory with no swap, PID, open-file,
shared-memory and private writable-mount bounds. It does not choose or run a
native-PG profile by itself. The actual Docker create/inspect/start boundary
and fresh per-lane output ownership are described in
[the runner-bounds contract](coder-runner-bounds-v12.md).

The fixed private workload-data mount is `/var/lib/serverware-runner`; the
cluster manager places its fresh `PGDATA` child and WAL there. The native
example assigns it a 2 GiB tmpfs within a 4 GiB no-swap memory limit, alongside
64 MiB shared memory, 64 MiB `/run` and 256 MiB `/tmp`. Its other bounds are
UID/GID `10001:10001`, 2 CPUs, 128 PIDs and `nofile` 1024. This is not a
measured capacity result, a host-backed database allocation, or a blanket
user change for other runner profiles; Rust retains its own `65532:65532`
identity. There is no host `/tmp` or unbounded private-data fallback. The
separate writable lane-output bind is not aggregate-byte-quota-limited in
this checkpoint; result-file read limits and tmpfs caps do not constrain
arbitrary output writes. An independently enforced output-storage quota is
still required before this can be a fully bounded native profile. Existing
runtime images are not already admitted: inherited environment, labels,
ports, healthcheck, shell or volumes can cause the closed inspect guard to
deny them. Future component tests on tmpfs must not claim physical power-loss
durability.

The fourteen fixed per-suite ceilings sum to 4,800 seconds, before
startup and cleanup, whereas the current Unit deadline profile is 900 seconds.
The source-only native sub-job proposes a 5,400-second ceiling with 120 seconds
for initialization, 60 for readiness, 60 for shutdown and additional bounded
overhead. This explicit 300-second increase and one additional direct-child slot
retain the old 360-second slack and all prior per-suite limits; they do not
authorize a controller deadline change. It reserves cleanup time before
scheduling a fixture and never shortens the declared fixture ceilings. This is not an override of the signed
Unit deadline: the selected lane still needs an explicit bounded deadline/resource
reconciliation including its other work and outer cleanup. This inventory neither increases that deadline nor permits
silently dropping suites to fit it. An installed controller must enforce the
selected profile and retain source/runtime/artifact/result bindings, then prove all task-owned
processes, sockets, mounts and storage are gone. A report from a fixture or a
pure batch consumer cannot manufacture that terminal proof.
The existing Docker runner `StopTimeout` is also still 10 seconds; it has not
been silently widened to the native component's 60-second PostgreSQL shutdown
budget. Cancellation/deadline admission must reconcile those limits and retain
forced outer destruction for any incomplete cooperative shutdown.

The actual v12 body is supplied in the externally signed
`executor-invocation-inputs-v12.json` logical-plan template. Future admission
must explicitly bind the new image, exact no-argument Python entrypoint,
source/artifact destinations, environment, resources, timeout and result
consumer. A Makefile phase name or a locally authored manifest is not that
signed invocation. No such external input was created or reissued here.

Keep all fourteen exclusions and all mandatory prerequisite gates until the real
prepared lane is implemented, independently admitted and reviewed. Even a
future successful native component batch would establish only its exact
component behavior, not production installation, external authority enrollment,
rollback resistance or release acceptance.
