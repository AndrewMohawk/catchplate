> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Use the running instance or install your own

## Use the current instance

**Administrator:** open the [running console](https://serverware.example.com/)
with the homelab login and follow [first-client setup](wiki/Getting-started.md).
You can save a credential first, then give a client a scoped permission.
Opening the console does not build the proxy, start a pilot or require a
security-key ceremony.

**Developer:** if you already have a private client JSON and its public CA,
go straight to the [developer quickstart](developer-quickstart.md). You do not
need to install Catchplate, sign in as an administrator or obtain the provider key.

The main instance still uses the Serverware hostname and runtime identity while
this repository is named Catchplate. Keep its downloads with the matching client
release until the operator completes the [rename](catchplate-rename.md).
Do not manually substitute hostnames, protocol markers or private configuration.

The [current deployment record](project-completion.md#current-live-deployment)
identifies this instance's exact source, proxy binary and retained Compose
command. Those paths describe an existing installation, not a portable installer.
Do not recreate its state, regenerate its keys or run a historical rollout script.

## Install a new instance

Use the [standalone installation guide](../docker/catchplate-standalone/README.md)
only when you want to operate a **new, empty instance**. It packages the console,
Rust proxy and Nginx edge with one JSON configuration; it does not depend on
the homelab login or retained deployment paths. You supply a Linux
Docker host, two HTTPS hostnames, a certificate covering both, and a dedicated
empty state location. The console uses a separate administrator password.

The intended flow is **build once → initialize → start**, with separate status
and stop commands. Later starts reuse the same images and retained private state;
opening the app does not build anything. There are no seeded provider credentials,
clients or permissions. Read the guide's current renewal/maintenance limitations
before treating initial startup as a complete operational handoff.

The deployment trusts its server administrator. Hardware verification is a
separate assurance option, not a prerequisite for this installation model.
For tested-version boundaries, see the [installation record](standalone-installation-verification.md)
and [renamed build/startup evidence](catchplate-rename.md#rename-evidence).

Do not use the root developer Compose stack or the old homelab operator Compose
layers as a substitute installer. The latter's `.env.example` contains only
supplemental notification options. Existing instances must retain their current
keys, CA, data and deployment ownership; `init` is for a genuinely new instance.

## Activate a prepared configuration

**Prepare is not Apply.** A preparation records reviewed settings but does not
change the running processes or contact a provider. Keep its operation reference;
if a response is lost, use **Check operation result**, not another Prepare.

After a confirmed preparation, **Download activation handoff** exports only
public operation/review pins and destination origins for the deployment owner.
It contains no provider secret, client token, custody contents or executable
command. It is an informational snapshot, not authorization to apply changes;
the owner must recheck that exact operation against current saved state.

| Prepared change | Deployment-owner action |
| --- | --- |
| Proxy destinations | Review the exact pending operation and target list. Stop old app/proxy writers, take a stopped-consistent backup, and set the same reviewed destination list on both app and proxy before the controlled paired restart. |
| Managed Google application | The secret is already encrypted in Catchplate. Recheck the exact pending operation, then perform the controlled app/proxy restart with existing managed-provider custody preserved. Startup selects that prepared configuration and publishes the matching Google destination/profile. Do not copy its secret into environment files or add the legacy Google layer. |
| X application | Saving managed X configuration is immediate; it does not need this restart handoff. Account consent and destination readiness remain separate. |

For either restart, use the deployment's current reviewed configuration and
backup procedure, not a command generated from the downloaded JSON. Keep ingress
closed until retained-state checks and matching app/proxy policy readiness pass.
Return to **Proxy setup → Administrator settings**, refresh the exact operation, and distinguish
**activation recorded**, **proxy ready** and **provider request succeeded**.
Changing credentials, clients or permissions after Prepare can stale its review;
do not force activation or silently prepare it again.

See [destination changes](operator-proxy-destinations.md),
[managed Google configuration](operator-provider-configuration.md#operator-configuration-workflow)
and [retained-state maintenance](../docker/catchplate-operator-demo/README.md#approval-and-state-preservation-gate).
