# Native role-key startup v12

`catchplate.nativeStartupConfiguration/v12` explicitly adds required
`guestRoleKeyProvisioner` to the eighteen v11 fields. The gate selector is
`--native-guest-role-keys-startup-v12`; the fixed image entrypoint selector is
`--guest-role-keys-v12`. Configuration and launch originals keep their existing
independent pins and original bounds. The [v12 schema](../schemas/native-startup-configuration.v12.schema.json)
describes data, not permission to obtain keys.

## Actual startup connection

The closed decoder validates the provisioner configuration and retains it with
the actual v11 issuance, refresh, cleanup, inspector, cohort and encrypted
service-token owners. All six plaintext bearer slots must still be null.
Guest response-client admission still depends on the actual pending encrypted
service-token source, not the version label.

Startup rejects provisioner selection without a real cohort before launching
children. The existing cohort/inspector requirements remain mandatory. Under
the same original root `Prepared` owner, startup launches and retains the real
inspector, checks its response-client association, and calls
`StartedGuestCohort::launch_with_role_keys` with that exact preparation and
inspector owner. The cohort admits the seven actual signed delivery originals
and performs its dedicated provisioning phase before starting role services.

The returned cohort enters the existing unshared native lifetime before later
startup work. Only then do the ordinary native NSM/broker preparation and
permanent gate privilege drop proceed. This does not promote the late serving
broker into a pre-drop role-key provisioner or recreate a lifetime with an
equal timestamp. See [the cohort lifetime](native-guest-cohort-lifetime.md).

During serving and cleanup, the existing cohort checks and role-before-inspector
stop/reap ordering remain. Provisioning errors return through the same outer
cleanup owner; a failed startup does not select an older profile. Partial output
evidence is not automatically removed or treated as permission to retry.

## Compatibility and acceptance

Profiles v1 through v11 pass no provisioner and continue to use the existing
cohort constructor where selected. Their closed schemas reject the new field.
The image default remains the explicit encrypted v6 path; missing key files,
environment values or an equal configuration digest never select v12.

This source connection does not provision independent KMS policies, grant roots,
encrypted role inventories, current-boot delivery signatures, durable backends
or fresh generation quotes. Those originals must satisfy the dedicated
provisioner and all existing role readers. It also does not implement target
response capture/persistence, broader OAuth lifecycle or EIF release acceptance.

No build, test, parser execution, cloud/provider contact, paid resource or
runtime acceptance accompanies this source integration.
