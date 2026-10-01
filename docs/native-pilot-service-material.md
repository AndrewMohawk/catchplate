# Native pilot service material

The `.383` source connects the final `service-originals` job, `service-material`
(job120), to publication of four existing public originals. It does not initialize
a service journal, create a receipt, sign a grant, release a child or compose the
bridge. Verification for this batch is pending.

## Exact sources and fixed destinations

[Service material](../serverware/native_pilot_service_material.py) copies literal
bytes from the actual approved Persistence and GenerationInstall authority
inputs, after revalidating those complete inputs and their actual signed grants.
The earlier fresh-only service policy already selected initialization; this step
does not manufacture a different genesis or accept restored records.

All four destinations are below `/etc/serverware/native-pilot-inputs/`:

| Filename | Existing input field | Maximum |
| --- | --- | --- |
| `native-persistence-configuration.json` | Persistence `configurationOriginal` | 512 KiB |
| `native-persistence-genesis.json` | Persistence `genesisOriginal` | 16 KiB |
| `native-persistence-journal.json` | Persistence `journalOriginal` | 1 KiB |
| `native-generation-install-genesis.json` | GenerationInstall `genesisOriginal` | 512 KiB |

The configuration is the complete public verifier configuration, not the cold
configuration or a role-key wrapper. Persistence genesis binds its actual guest
and proof-scope binding; journal metadata is sequence zero with genesis and head
digests equal. Generation genesis binds its actual guest, assignment and complete
service-set digest. Its previously approved `recordOriginals` must be exactly
`[]`; there is no new record-publication or recovery fallback.

## Policy, bundle and result

Supervisor policy/v13 adds the literal `serviceMaterialOriginal` to v12, with
purpose `initial-driver-bootstrap-precreation-endpoints-generations-and-service-material`.
The nested policy is bounded to 4 KiB and has exactly:

```json
{"apiVersion":"serverware.nativePilotServiceMaterialPolicy/v1","initialization":"fresh-persistence-and-generation"}
```

It adds no signing selector or new key. Earlier policy versions do not acquire
this publication authority.

The canonical bundle is `serverware.nativePilotServiceMaterialBundle/v1`, with
exactly `apiVersion`, `serviceContexts` and `endpointLaunches`. Both maps contain
only `persistence` and `generationInstall`. Each service context contains literal
ASCII `inputOriginal` and `grantOriginal`; each launch entry is the actual fixed
launch pin. The complete bundle limit is 64 MiB, not a filesystem-write allowance.
Existing 128 MiB retained-owner and 128-original/32 MiB public-file bounds remain.

The new result is `serverware.nativePilotServiceMaterialInstallation/v1`, with
exactly `apiVersion`, `bundleSha256`, `startupDeadlineBoottimeNs`,
`lifetimeDeadlineBoottimeNs`, `material` and `pins`. `pins` is the exact four-slot
map. `material` retains the conductor's existing contract:

```text
persistence: {configuration: pin, genesis: pin, journal: pin}
generationJournal: {genesis: pin, records: []}
```

The old separately supplied pin-only job remains bounded to 32 KiB and returns
`publicPinsOpened`; it does not gain publication authority. The versioned path
instead invokes the installer, then opens the resulting material through the
existing restricted public reader before completing the phase.

## Pure checks versus actual publication

`validate_policy`, `build`, `prepare_bundle` and `checked_result` validate public
grammar, exact byte/signature associations and supplied clock data. They do not
establish process provenance, filesystem ownership, successful publication,
Nitro admission or resource emptiness. Publication-profile `shape` checks alone
are not signature or authority admission.

The live `install` path requires root UID/GID, the main thread, an approved bundle
digest and one process attempt. Before writing, it retains the real protected
service-grant and endpoint-launch originals and checks the launch's cold, C9,
role-key, admission and grant associations. It exclusively creates all four
absent fixed root-owned `0400` files, retaining publisher readback and original
BOOT/BOOTTIME/UNIX checks throughout. It never reads private credentials or
ciphertext. Existing or partial paths are not adopted, overwritten or removed;
failure consumes the attempt and partial public files remain.

## Retained job120 and the next phase

[The material owner](../serverware/native_pilot_supervisor_service_material.py)
accepts only the real policy, coordinator and opaque pending job120 request.
It first verifies the completed ten-launch and eleven-service handoffs, retains
the selected two actual input/result pairs and launch records, and derives one
deterministic bundle. Subsequent checks compare exact approved bytes/results,
the original phase, unchanged policy and original deadlines. Failures fence the
attempt; retained data is released only after actual terminal cleanup.

`require_material` is a read-only handoff at the genuine next
`bridge-runtime` / `install-bridge-runtime` request. It verifies the next phase
sequence and actual previous material result, rechecks its retained source bytes,
rebuilds the identical bundle, and returns `{inputOriginal, result}`. It does not
call old service owners under an invented request or grant bridge installation
authority. No bridge composer or additional bridge coverage is included.

Actual durable initialization remains later in
[`admit_services`](../serverware/native_pilot_service_inputs.py):
the retained generation owner checks the supplied genesis/record chain against
the installed grant before exclusive journal writes; the retained persistence
owner validates and installs its exact genesis, then admits its operational
grant. Their real ownership, freshness, exclusive-create and readback checks
remain authoritative. A public installation result is not evidence that those
later writes, service startup or readiness succeeded.

The [bridge assembly plan](native-pilot-bridge-assembly.md) records the separate
current-head issuer, peer-binding, history-adapter and external-service
prerequisites. Four material files do not satisfy them.

## Focused verification

Pending the assembled batch check. No tests, signing entrypoints, protected
owners, journal initialization, services, hardware or cloud operations were run
to establish the claims in this source-only guide.
