# Explicit native capture-retirement startup

Native startup v16 retains all v15 owners and requires the separately selected
`measuredCaptureRetirement` configuration. This is cleanup for a captured OAuth
issuance whose authenticated subject is not yet established, not an alias for
staged-pending retirement, refresh cleanup or reconnect.

The image selector is `--measured-capture-retirement-v16`; the gate selector is
`--native-measured-capture-retirement-startup-v16`. The existing four
configuration/launch artifact flags and optional public-identity output flag
are unchanged. No environment, incoming request or returned marker selects this
purpose. The default image startup remains v6, and older decoders do not accept
the new field or acquire capture-retirement authority.

## Cold configuration and actual ownership

The [closed v16 schema](../schemas/native-startup-configuration.v16.schema.json)
requires exactly the prior v15 fields plus `measuredCaptureRetirement`.
All six parent plaintext bearer slots remain explicit null. Configuration and
launch originals stay separately pinned, so the new field is committed by the
same actual configuration-byte hash rather than a self-referential digest.

The new field uses the dedicated
[`configuration` schema](../schemas/native-oauth-capture-retirement.v1.schema.json#/$defs/configuration).
Its root, deployment/instance scope, original application enrollment/material/TLS
pins and exact targets are validated before handing the real value to
`GateStateInputs.measured_capture_retirement`. The gate's separate purpose
owner must still acquire its actual retained broker, native identity/signing
owner and unchanged launch deadline. No cold object is a ready owner or a
permission to contact a provider.

Setup remains the one selected browser/helper issuance purpose. The v15 closed
shadow alternatives, optional explicit native-staging selection, genuine cohort,
role-key provisioner and gate-only cgroup ownership remain available under their
existing independent admission. Capture retirement adds neither a second browser
listener nor an alternate shadow/staging authority.

## Cleanup authority and remaining evidence

Without an authenticated subject, this profile requires explicitly opted-in
provider-wide retirement authority covering possible external related-grant
impact. Complete bounded local inventories, genuine holder drains, protected
provider fences and one-use contact claims remain mandatory before effects.
Unknown or incomplete populations and unresolved other provider contacts refuse.
Neither expiry nor a successful identity query supplies cleanup permission.

Recovery retains exact old grants/originals and cannot renew the window, repeat
provider contact or reopen the provider scope. A transport observation is not
proof that every related provider credential became invalid.

This startup connection joins the actual purpose implementation, but targets one
exact retained capture while permanently fencing the complete local provider.
It does not discharge other retained captures, permit a second independent claim
or reopen the provider. Multi-capture succession, migration, larger populations,
cross-deployment coordination, independently provisioned grants/keys/assignments,
release/EIF evidence and end-to-end interruption/recovery verification remain
required. No native runtime acceptance follows from this source integration.
