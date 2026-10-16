> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Use the running instance or install your own

## Use the current instance

Open [Serverware](https://serverware.example.com/) with the homelab login.
It is already running: opening it does not build the proxy, start a pilot or
require a security-key ceremony. Follow [Getting started](wiki/Getting-started.md)
to save a provider credential, create a client and grant a permission. Developers
can use an administrator-provided [private client configuration](wiki/Clients-and-recipes.md)
without installing the server or receiving provider keys.

The [current deployment record](project-completion.md#current-live-deployment)
identifies this instance's exact source, proxy binary and retained Compose
command. Those paths describe an existing installation, not a portable installer.
Do not recreate its state, regenerate its keys or run a historical rollout script.

## Install a new instance

**A supported turnkey fresh-install package is not available yet.** The ordinary
host-trusted startup code can initialize a genuinely empty store, local keys,
CA and deny-all policy, but the checked-in operator Compose files assume this
homelab's existing artifacts, private files, network and authentication edge.
The root Compose file is a separate developer stack, not the operator product's
installation recipe. The operator `.env.example` contains supplemental
notification options only; it is not a complete environment template.

A new host-trusted installation needs these explicit inputs:

| Input | What must be supplied |
| --- | --- |
| Addresses and TLS | Console and HTTPS proxy hostnames, certificates and routing. The current operator profile expects an HTTPS proxy hostname on port 443; HTTP, localhost and literal IPs are not supported substitutes. |
| Administrator access | An authenticated, operator-restricted edge that strips client-supplied admin headers and injects the private server credential only after authentication. The retained edge is specific to the homelab login. |
| Runtime artifacts | A matching application source/image and normal Rust proxy artifact with its verified digest; not paths copied from someone else's deployment receipt. |
| Private storage | Dedicated empty, owner-only data/custody directories and distinct private service tokens, with the correct process ownership. Never adopt an unmarked nonempty store or overwrite retained state. |
| Network policy | An explicit ordered HTTPS destination list and separate console/proxy reachability. Allowing a destination grants no client permission. |
| Provider use | Least-privilege provider credentials and any required OAuth application setup, consent or provider-side permissions, entered privately after startup. |

The missing packaging is one self-contained Compose profile, complete nonsecret
configuration template and no-clobber bootstrap command. It must prepare private
inputs, start the app to generate its CA/policy/publication, then start the matching
proxy and authenticated edge. Reuse built artifacts on subsequent starts; do not
seed synthetic credentials or rebuild on every launch. This work does not require
TEE custody, but authentication, secret isolation and retained-state checks are
still essential. No executable fresh-install recipe is implied by this checklist.

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
| Managed Google application | The secret is already encrypted in Serverware. Recheck the exact pending operation, then perform the controlled app/proxy restart with existing managed-provider custody preserved. Startup selects that prepared configuration and publishes the matching Google destination/profile. Do not copy its secret into environment files or add the legacy Google layer. |
| X application | Saving managed X configuration is immediate; it does not need this restart handoff. Account consent and destination readiness remain separate. |

For either restart, use the deployment's current reviewed configuration and
backup procedure, not a command generated from the downloaded JSON. Keep ingress
closed until retained-state checks and matching app/proxy policy readiness pass.
Return to **Proxy setup**, refresh the exact operation, and distinguish
**activation recorded**, **proxy ready** and **provider request succeeded**.
Changing credentials, clients or permissions after Prepare can stale its review;
do not force activation or silently prepare it again.

See [destination changes](operator-proxy-destinations.md),
[managed Google configuration](operator-provider-configuration.md#operator-configuration-workflow)
and [retained-state maintenance](../docker/serverware-operator-demo/README.md#approval-and-state-preservation-gate).
