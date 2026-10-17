# Native pilot endpoint commissioning

The `.370` source connects four additional fixed supervisor jobs. Coverage is
7/60 at that checkpoint. The `.373` initial-history connection expands the graph
to 32/85; startup still refuses before spawning while the other 53 are missing.
This is not a launched pilot, production approval or verified hardware custody.

## Independently selected policy

`catchplate.nativePilotSupervisorCommissioningPolicy/v3` has the existing
measured/v2 nine fields plus `endpointPreparation` and `endpointDeliveries`.
Its purpose is `initial-driver-bootstrap-precreation-and-endpoint-commissioning`.
Legacy v1/v2 policies retain their original fields, purposes and behavior.

The preparation fragment is exact four fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `catchplate.nativePilotSupervisorEndpointPolicy/v2` |
| `initialization` | Exactly `fresh-ledger` |
| `objectDirectory` | Independently selected existing empty root:root0700 directory under protected ancestors |
| `peerExpectations` | Separate `cgroupPathSha256`, `securityLabelSha256` and `configurationGenerationSha256` pins |

Path syntax does not prove that the directory exists or is safe. The real
installer and retained directory checks establish those properties. No process
identity, expected production binding, proof scope or retrieval receipt is
selected in advance. The same approved [recipe/v2](native-pilot-measured-configuration.md)
supplies the authenticated assignment/trust/closure set and derives the measured
configuration from the actual earlier bootstrap observation.

`endpointDeliveries` has exactly `retrieval`, `persistence` and `trustedTime`.
Each selects `runtimeOriginal`, its source-fixed `runtimeConfig` pin and complete
nonempty `credentials` metadata. These public declarations do not contain secret
key bytes or prove that credential files exist. The policy also binds each
delivery authority to its existing purpose-key binding.

## Actual preparation and delivery

The endpoint-input composer admits the actual coordinator's pending request,
checks prior complete installed inputs and signed results, and verifies the
cohort/external-driver association under the original window. It combines
observed driver process/executable/cgroup identity with the three independent
peer expectations; it never substitutes a proc-file digest for a cgroup-path hash.

The checked retained recipe supplies the configuration/proof scope and original
signed assignment. The composer constructs only the explicit empty
[fresh-ledger manifest](native-pilot-fresh-ledger-startup.md), not receipt history.
After complete validation and fixed-destination preflight, the existing installer
prepares the actual empty directory as 0555. The composer retains its real
identity and publishes four originals exclusively at fixed paths beneath
`/etc/catchplate/native-pilot-inputs/`: `endpoint-peer.json`,
`endpoint-proof-scope.json`, `endpoint-retrieval-manifest.json` and
`endpoint-assignment.json`. Its seven-field input joins those pins to the actual
cold configurations, directory and measured production settings.

Each of the three delivery composers uses genuine observed activation arrays
and the original cohort window. Runtime markers and hashes must match the
assignment-approved closure-set member for that role. A later delivery verifies
the complete earlier approved input, exact returned original and its C9 signature.
Only the existing separate authority coordinator signs the approved C9 payload.

The next-phase helper verifies all three actual delivery results and retains the
conductor's actual guest/journal report. Sequence-zero genesis is checked against
that report; it is never calculated from predicted C9 values or converted into
an operational receipt. The native storage owner must still admit its real files.

Every failure consumes the attempt. Partial files and changed directory mode are
retained; no overwrite, adoption, deletion, retry or deadline renewal is provided.
Cleanup closes retained public handles only after the real coordinator's cleanup
is known complete. Unknown cleanup retains the owners. The external watchdog and
unchanged native signature, resource, trust and currentness checks remain required.

The remaining ordinary-service, native-grant, launch, bridge, release and lifetime
composers, executable packaging, genuine provisioning and connected application
acceptance are still open. See [current status](production-status.md).
