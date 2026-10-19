> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Proxy setup and CA trust

[Home](Home.md) · [Client recipes](Clients-and-recipes.md) · [Troubleshooting](Troubleshooting.md)

## Configure a client, not the console URL

Open **Proxy setup → Connect a client** and select the client and permission. For a supplied example, use the complete private configuration and CA downloads; the file already contains the proxy endpoint and client login. **Proxy connection details and manual setup** contains those settings when configuring your own HTTP client. **Administrator settings** is a separate view for destination and OAuth application configuration; it is not part of running a client. The retained browser console at `https://serverware.example.com/` and the forward proxy are different services. The Catchplate hostname cutover is pending; follow [rename status](../catchplate-rename.md) and do not rewrite an existing private configuration. Do not invent a port or use a private management address as the proxy.

Before a client and permission are selected, the page explains what is missing
instead of showing an empty request template. **Add a permission for …** carries
that exact client into guided setup without creating access. Expired clients
need explicit lifecycle review; nothing is renewed automatically. The public
CA download and manual proxy endpoint remain available before client setup.

For **standard client login**, the username is the Catchplate client ID and the password is its expiring proxy token. Retained Bearer-only clients must use their advertised mode or be explicitly changed in **Clients**; a recipe does not silently migrate them. The token authenticates to Catchplate, not to GitHub, Google or npm.

Use the [provided client recipes](Clients-and-recipes.md), which separate proxy authentication from the provider's public dummy header. Avoid hand-assembling credential-bearing URLs or echoing private configuration in logs. Some stock-client compatibility wrappers necessarily build such URLs internally; their documented isolation and redaction rules still apply.

## Download and scope the public CA

1. Sign in to the console and choose **Proxy setup → Connect a client → Download CA certificate**.
2. Save `catchplate-ca.pem` with the client configuration.
3. Set the recipe's interception-CA path to that file.
4. Verify the certificate with your operator and scope trust to the intended client. Keep TLS verification enabled. Do not use `curl -k`, disable SDK verification or install the interception CA system-wide.

There are two TLS checks:

| Connection | Trust required |
| --- | --- |
| Client → HTTPS proxy | Normally system/default trust for the proxy hostname; a separate private proxy CA only when the selected recipe supports it |
| Client → provider inside the proxy tunnel | The downloaded Catchplate public interception CA |

The download contains no private CA signing key. Correct trust does not make an unreachable proxy reachable, and downloading a CA does not grant access. Follow each project's trust implementation: GitHub Python and npm use combined/additive trust rather than independent per-hop root sets. [UI and client setup](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/index.html), [GitHub Python](https://github.com/AndrewMohawk/catchplate/blob/main/examples/github-issues-python/README.md), [npm client](https://github.com/AndrewMohawk/catchplate/blob/main/examples/npm-registry/README.md).

## Let the proxy reach a new provider

The operator owns the approved destination list. A client permission cannot add an arbitrary host.

1. Open **Proxy setup → Administrator settings → Destinations** and review the effective origins.
2. Enter the proposed complete list and review additions/removals. Public entries are canonical HTTPS origins on port 443, without paths, URL credentials, queries, wildcards or literal IP addresses.
3. Choose **Prepare change**. This records a reviewed target; it does not contact the provider or apply it live.
4. Have the deployment owner perform the controlled paired restart using the exact prepared settings and retained-state procedure.
5. Confirm the effective settings and matching loaded policy, then create the intended client permission and test the provider job.

Origins referenced by active rules cannot simply be removed. Revoke the affected permissions first. A stale review must be reviewed again; do not reset the catalog or assume an environment-variable edit will replace its retained destination list. See the [destination procedure](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-proxy-destinations.md).

## Configure the proxy's Google OAuth application

This is operator configuration, not an individual user's account connection:

1. Open **Proxy setup → Administrator settings → Google provider settings → Review Google provider settings**. Expand the acquisition guide if you still need an OAuth application.
2. Register the displayed exact callback URI in your Google OAuth application and review the fixed Gmail read-only scope/destination.
3. Enter the OAuth client ID and write-only application secret, then choose **Prepare Google configuration**.
4. Preparation stores inactive encrypted configuration. The deployment owner must perform its separate controlled cold restart and confirm the matching app/proxy readiness.
5. Once available, use **Credentials** to connect a person's Google account. Assign a client and permission separately.

The page does not create a Google project, restart services or start consent on your behalf. This first-configuration workflow is not provider-secret rotation. A lost response is recovered with **Check operation result**, not a second Prepare. [Managed Google configuration](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-provider-configuration.md#operator-configuration-workflow).

## Configure the proxy's X OAuth application

When the feature is offered, open **Proxy setup → Administrator settings → X (Twitter) application → Review X application settings**. Expand its acquisition guide if needed. Register the exact displayed callback in X and enter the OAuth **Client ID and Client secret**, not an app-only bearer token. Review the fixed permissions, then save.

Unlike Google preparation, this settings save is immediate and does not require a restart. It still does not contact X, connect an account, approve a destination or grant posting permission. Replacing a saved X application is not currently offered. Continue only when the instance reports the matching provider/policy readiness. [Current configuration UI](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/index.html), [X readiness checks](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_x_readiness.py).

## What remains deployment-managed

Listener bindings, public DNS/TLS, routing, retained storage and coordinated application/proxy updates are deployment tasks, not editable client-template settings. The [public proxy checkpoint](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-public-proxy-verification.md) records a successful authenticated synthetic-route request and revocation check; it does not verify every real provider or SDK job. Use the [deployment runbook](https://github.com/AndrewMohawk/catchplate/blob/main/docker/catchplate-operator-demo/README.md) for changes to the running services.
