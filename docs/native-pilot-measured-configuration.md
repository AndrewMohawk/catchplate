# Measured production configuration

`native_pilot_measured_configuration.MeasuredConfigurationRecipe` derives the
version-selected native production configuration hash from independently approved static
originals and a real process-owned bootstrap observation. The .368 source batch
connects this retained owner to the partial commissioning supervisor. It is not
a complete supervisor or authority issuer; coverage remains 3/60, with no new
build or runtime evidence.

The legacy protected recipe has exactly ten fields. Explicit recipe/v2 has
those same fields plus the required `closureSetOriginal`:

| Field | Required input |
| --- | --- |
| `apiVersion` | `serverware.nativePilotMeasuredConfigurationRecipe/v1` or explicit `/v2` |
| `source` | Existing exact five-field runtime source identity |
| `conductorInventorySha256`, `authorityInventorySha256` | Independently approved installed-runtime inventory hashes |
| `bootstrapOriginals` | Exact literal `control`, `configuration`, `window`, `deliveryConfiguration` originals |
| `assignmentOriginal` | Complete signed custody-bearing assignment; its explicit version must match the recipe |
| `trustOriginal`, `trustSha256` | Independently approved and pinned public trust original, selecting the assignment and role verification keys |
| `closureManifestOriginal` | Existing single bridge `nativeCustodyExecutionClosure/v2`, measured-bootstrap-late-runtime profile |
| `production` | Existing eight static backend/protocol/limit fields, without an expected configuration hash |
| `closureSetOriginal` | Only in recipe/v2: complete canonical eleven-member closure set, matching both roots signed by assignment/v2 |

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

## Supervisor-owned derivation

Explicit commissioning policy/v2 independently pins the complete recipe/v2 in
`measuredRecipeSha256`. `CommissioningSupervisor.prepare(policy=..., process=...,
measured_recipe=...)` retains and checks that actual owner before bootstrap
preparation, then binds it to the same process before spawn. Policy/v1 rejects
a supplied recipe and preserves its existing behavior.

At the actual pending `endpoint-precreation` / `cohort-precreation` job, the
supervisor calls `policy.derive_measured(process=..., request=...)` exactly once.
`policy.measured_configuration(process=..., request=...)` subsequently returns a
deep copy of the retained six-field result described below. Access requires the
same actual process and pending startup request, an unchanged retained precreation
request, and the original startup allowance; it never recomputes the result or
renews a deadline. The accessor does not authorize an endpoint job. Full-run
startup still refuses before spawn while the remaining 57 composers are missing.

## Binding and result

Legacy derivation preserves all 24 existing `ConfigurationBinding` fields and
the `serverware.policyShadowProductionCustodyConfiguration/v1` framed hash.
Recipe/v2 adds `nativeClosureSet`, exactly `setRootSha256` and
`seccompSetRootSha256`, as the 25th field and selects the `/v2` hash domain.
The old manifest and seccomp fields remain the actual bridge leaf, never set
roots. Full set validation checks all eleven members, both signed roots and
the exact bridge manifest before the real observation is used.

The supervisor instance is SHA-256 of the original invocation ID's
ASCII bytes; the boot hash uses the decoded original boot ID. The driver identity
is the actual original bootstrap observation's measured identity—not a predicted
PID or a later fabricated descriptor census. The later constructed-driver census
is not needed for this hash and remains required by its separate native owner.

The six-field result is unsigned data: `apiVersion`, `recipeSha256`,
`configurationBindingOriginal`, `configurationBindingSha256`,
`proofScopeOriginal`, and the existing nine-field `production` object with its
derived `expectedConfigurationBindingSha256`. The result's explicit version
matches its recipe. Legacy proof scope preserves the exact fourteen fields,
eleven-value framed digest and independent Store/Retrieval key bindings.
Proof scope/v2 adds exactly `api_version` equal to
`serverware.policyShadowProductionCustodyProofScope/v2`,
`execution_closure_set_root_sha256`, and
`structurally_verified_seccomp_set_root_sha256`. Its `/v2` framed digest appends
the two roots to the old eleven-value tuple. The corresponding authority receipt
array is `[domain/v2, scopeBinding, bridgeManifest, bridgePolicy, setRoot,
seccompSetRoot, signerRole, receiptSha256]`; legacy bytes remain unchanged.
No receipt, nonempty retrieval object, journal, key, admission, trusted-time proof,
deployment authorization or successful pilot is produced. Local freshness checks
do not replace the native receiver's trusted-time/currentness checks.

The v2 retrieval/persistence and spool artifact paths require the complete
assignment payload original. Its exact hash must match the real signed key
authorization; roots and bridge anchors must match that original. Endpoint leaf
membership remains a separate check by the actual native closure owner. The
conductor passes its already pinned assignment into the retained endpoint owner
and then the existing persistence signed-original intake; it does not reconstruct
an assignment from hashes or silently treat an endpoint leaf as the bridge.
Opening/checkpoint receipt verification uses the same explicit transcript.

No closure-set root may be inserted into a legacy single-manifest field. These
connected data/receiver changes do not add independent commissioning decisions,
create retrieval receipts, raise the supervisor's supported job count, or make a
full pilot runnable by themselves. Generic legacy assignment DB admission is not
expanded by this native-only successor.

The policy retains the recipe through cleanup. `close()` releases its public
descriptor only after the bound process reports genuine completed cleanup;
unknown cleanup retains it. Cleanup does not depend on the startup window still
being live. This .368 owner connection has source review only, not protected-owner
execution, signing, installation or build evidence. An external watchdog must
still bound filesystem stalls.
