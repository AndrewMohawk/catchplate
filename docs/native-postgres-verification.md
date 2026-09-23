# Native PostgreSQL verification inventory

## Status and boundary

The source includes a closed inventory and fixture-result contract layer. The
separate [v12 runner-bounds checkpoint](coder-runner-bounds-v12.md) makes
nonroot execution and resource/storage bounds part of the admitted runner
identity, with fresh output ownership and exact pre-start container checks.
Neither checkpoint implements a PostgreSQL cluster runner, installs a PG16
test image, wires the controller's native output consumer, or provides native
execution evidence.
The current source remains unbuilt and unexecuted. The ten suites remain in
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
defines `serverware.nativePostgresInventory/v1`, ten ordered frozen
`NativePostgresSuite` records and `TOTAL_TESTS = 182`. Each record contains an
exact script path, an explicit sorted tuple of `Class.test_method` IDs, its
disposable-cluster CLI acknowledgement requirement and its timeout in seconds.
The IDs are authored source declarations, not dynamically discovered or
executed results. The total includes the pure representation and source-linkage
methods contained in these fixtures; it is not a count of 182 native SQL tests.

| Order | Script under `scripts/` | Methods | Timeout | Extra disposable CLI flag |
| --- | --- | ---: | ---: | --- |
| 00 | `test_webauthn_trust_projection_postgres.py` | 8 | 300 s | No |
| 01 | `test_postgres_trigger_manifest.py` | 5 | 300 s | No |
| 02 | `test_authority_mutation_postgres.py` | 14 | 300 s | No |
| 03 | `test_authority_root_transition_postgres.py` | 21 | 300 s | No |
| 04 | `test_authority_primary_tree_postgres.py` | 7 | 300 s | No |
| 05 | `test_authority_audit_initialization_postgres.py` | 31 | 300 s | No |
| 06 | `test_authority_audit_initialization_store_postgres.py` | 36 | 900 s | Yes |
| 07 | `test_authority_global_audit_capacity_postgres.py` | 25 | 300 s | No |
| 08 | `test_authority_verifier_read_postgres.py` | 21 | 300 s | Yes |
| 09 | `test_authority_wire_json_postgres.py` | 14 | 300 s | No |

All ten require a prepared disposable local environment. A `False`
`disposable_cluster` field means that the particular fixture has no extra
`--disposable-cluster` switch; it does not permit a production or shared
database. The frozen records are data, not capabilities. The no-argument
`validate_inventory()` checks the fixed inventory's exact metadata, bounds,
ordering, uniqueness and total without importing fixtures, reading files or
running tests. It does not prove that fixture discovery or observed execution
matches those declarations.

## Fixed future invocation profile

[native_postgres_batch.py](../serverware/native_postgres_batch.py) constructs
only the ten source-fixed command tuples. `prepared_fixture_argv(index)` rejects
non-integer, boolean and out-of-range indices; it accepts no caller-selected
script, selector, DSN or executable. Its fixed profile is:

- Python: `/usr/local/bin/python3.11`.
- Read-only source: `/opt/serverware/src`.
- DSN: `host=/run/serverware-native-postgres port=5432 dbname=postgres user=serverware_fixture_admin`.
- Reports: `/opt/serverware/output/native-postgres/reports/00.json` through
  `09.json`, supplied with `--prepared-result`.
- The two inventory-marked scripts receive `--disposable-cluster`; every script
  receives `-v`.

These tuples do not execute anything or create the named paths. A future
admitted runner must own the canonical mode-0700 Unix-socket and report
directories and the disposable database cluster before using them. A fixture
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
to 256 KiB. The actual ten fixture CLIs expose `--prepared-result`; the helper
does not create a database or grant fixture permission to access one.

The pure `reconcile_native_postgres_batch(observations, *, source_sha256)`
consumer joins exactly ten ordered reports to separately supplied prepared
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

## Remaining runner and controller work

The v12 protocol can carry a fixed no-build runner command without adding a
general-exec operation or giving repository code Docker authority. A local
PostgreSQL child and Unix socket can live inside that runner. The existing
network service contract, which uses endpoint authorities/ports and HTTP health
checks, is not a Unix-socket transport for these fixtures. Do not weaken the
fixture DSN restrictions or expose a host socket to make it fit.

The actual cluster lifecycle, PG16 image construction, deadlines, log capture,
controller-bound native result consumption and authenticated controller
cleanup are still incomplete. `RunnerIdentity.executionBounds` now requires
an admitted nonroot user/group, CPU, memory with no swap, PID, open-file,
shared-memory and private writable-mount bounds. It does not choose or run a
native-PG profile by itself. The actual Docker create/inspect/start boundary
and fresh per-lane output ownership are described in
[the runner-bounds contract](coder-runner-bounds-v12.md).

The fixed private workload-data mount is `/var/lib/serverware-runner`; a later
cluster manager can place a `PGDATA` child and its WAL there. The native
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

The ten fixed per-suite ceilings sum to 3,600 seconds, before
startup and cleanup, whereas the current Unit deadline profile is 900 seconds.
The selected lane therefore needs an explicit bounded deadline/resource
reconciliation; this inventory neither increases that deadline nor permits
silently dropping suites to fit it. An installed controller must enforce the
selected profile and retain source/runtime/artifact/result bindings, then prove all task-owned
processes, sockets, mounts and storage are gone. A report from a fixture or a
pure batch consumer cannot manufacture that terminal proof.

Keep all ten exclusions and all mandatory prerequisite gates until the real
prepared lane is implemented, independently admitted and reviewed. Even a
future successful native component batch would establish only its exact
component behavior, not production installation, external authority enrollment,
rollback resistance or release acceptance.
