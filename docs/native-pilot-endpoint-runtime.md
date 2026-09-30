# Native pilot endpoint runtime marker

The .368 source batch gives the ten fixed native endpoints an explicit runtime
original. It is canonical ASCII JSON with exactly two fields:

```json
{"apiVersion":"serverware.nativePilotEndpointRuntime/v1","role":"retrieval"}
```

The role must match the actual source-selected endpoint: `retrieval`,
`persistence`, `trustedTime`, `generationInstall`, `commitRequest`,
`ingressAdmission`, `terminalAppend`, `dispatchBarrier`, `activeEffectBarrier`, or
`activeEffectCommit`. Unknown fields, another role or a bridge RPC configuration
are not accepted as this marker. There are no process IDs, journal identities,
credentials, settings or future-observation placeholders to invent.

The fixed launch publisher validates `native-runtime-<role>` and installs its
original before the selected launch. Signed C9 delivery binds its exact path and
byte hash; the selected execution-closure leaf also binds the runtime hash.
The native parent, parked cohort transfer and admitted child check the marker
against the actual selected service. A matching role string does not replace
the signed delivery, closure membership or service-grant checks.

The marker identifies source-fixed endpoint behavior; operational permissions and
settings remain in the independently authorized service grants. The production
bridge is excluded and still requires its complete operational RPC runtime.
This contract avoids passing bridge-only dynamic configuration fields to an
endpoint that does not consume them. Set roots remain separate commitments, not
substitutes for a leaf or runtime hash.

This is source wiring, not runtime acceptance. No new compilation, launch,
service request or cleanup evidence accompanies this batch. Supervisor coverage
remains 3/60 and full-run startup still refuses; endpoint commissioning composers
and genuine provisioned objects/originals must still be connected and verified.
