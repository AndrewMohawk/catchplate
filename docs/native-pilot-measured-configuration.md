# Measured legacy production configuration

`native_pilot_measured_configuration.MeasuredConfigurationRecipe` derives the
current native production configuration hash from independently approved static
originals and a real process-owned bootstrap observation. It is a callable
prerequisite, not a connected full commissioning supervisor or authority issuer.

The protected recipe has exactly ten fields:

| Field | Required input |
| --- | --- |
| `apiVersion` | `serverware.nativePilotMeasuredConfigurationRecipe/v1` |
| `source` | Existing exact five-field runtime source identity |
| `conductorInventorySha256`, `authorityInventorySha256` | Independently approved installed-runtime inventory hashes |
| `bootstrapOriginals` | Exact literal `control`, `configuration`, `window`, `deliveryConfiguration` originals |
| `assignmentOriginal` | Existing complete signed custody-bearing assignment |
| `trustOriginal`, `trustSha256` | Independently approved and pinned public trust original, selecting the assignment and role verification keys |
| `closureManifestOriginal` | Existing single bridge `nativeCustodyExecutionClosure/v2`, measured-bootstrap-late-runtime profile |
| `production` | Existing eight static backend/protocol/limit fields, without an expected configuration hash |

The eight production fields are `signerBackendSha256`,
`persistenceBackendSha256`, `retrievalBackendSha256`,
`dispatcherProtocolSetSha256`, `maximumRpcNanos`, `cleanupReserveNanos`,
`maximumInFlightCalls`, and `maximumAsyncDurabilityNanos`. Existing bounds are
unchanged: RPC 250 ms–1 s, cleanup at most 5 s, 1–64 calls, and positive async
durability no longer than the RPC interval.

`open(recipe_fd=..., recipe_sha256=...)` retains a bounded 8 MiB root:root 0400
public original using the existing protected-FD rules. It requires the actual
root main thread under isolated Python with bytecode writes disabled. File
protection and a hash do not themselves prove independent approval; the operator
must approve and provision the complete recipe beforehand.

`bind(process)` is one-shot and must run before that actual
`AuthorityCoordinatorProcess` starts, after its bootstrap originals are opened.
It compares the actual source/runtime inventory identity and all four retained
bootstrap originals. `derive(process=..., request=...)` accepts only that owner's
genuine pending `endpoint-precreation` / `cohort-precreation` request. It checks
the actual prior approved input and returned bootstrap signature, then validates
the original observation, window, assignment, trust, key set and bridge manifest.
Malformed input or failure cannot be retried on a replacement owner or a renewed
deadline.

The derived transcript preserves all 24 existing `ConfigurationBinding` fields
and the native `serverware.policyShadowProductionCustodyConfiguration/v1` framed
hash recipe. The supervisor instance is SHA-256 of the original invocation ID's
ASCII bytes; the boot hash uses the decoded original boot ID. The driver identity
is the actual original bootstrap observation's measured identity—not a predicted
PID or a later fabricated descriptor census. The later constructed-driver census
is not needed for this hash and remains required by its separate native owner.

The six-field result is unsigned data: `apiVersion`, `recipeSha256`,
`configurationBindingOriginal`, `configurationBindingSha256`,
`proofScopeOriginal`, and the existing nine-field `production` object with its
derived `expectedConfigurationBindingSha256`. The proof scope preserves the
existing eleven-value framed digest and independent Store/Retrieval key bindings.
No receipt, nonempty retrieval object, journal, key, admission, trusted-time proof,
deployment authorization or successful pilot is produced. Local freshness checks
do not replace the native receiver's trusted-time/currentness checks.

This profile is explicitly **legacy single-closure only**. A closure-set root or
seccomp-set root must not be inserted into the old single-manifest fields. A
future versioned assignment/scope admission must select and authenticate that
different meaning before a corresponding derivation can be connected. Therefore
this helper does not resolve the current multi-endpoint/bridge closure conflict.

`close()` releases its retained public descriptor only after the bound process
reports genuine completed cleanup. Unknown cleanup retains it. Source grammar
and host import checks do not exercise this protected owner; no runtime,
signing, installation or build was executed. An external watchdog must still
bound filesystem stalls.
