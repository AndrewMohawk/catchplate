> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Retained synthetic sandbox

This directory holds the renamed edge template for the existing, separate
synthetic sandbox. It is not the ordinary product instance or a fresh-install
recipe. Use the [standalone installer](../catchplate-standalone/README.md) for a
new ordinary installation.

The template is the retained sandbox ingress configuration with Catchplate
hostnames, service names and private-header paths. Its actual-peer, authenticated
operator and browser-origin checks are unchanged. It requires the existing
deployment's reviewed `TRAEFIK_IPV4` and a private
`/run/secrets/catchplate-edge/admin-header.conf`; neither value is generated here.
It publishes no forward-proxy listener or host port.

The planned console is `https://catchplate-sandbox.example.com/`, with
`https://catchplate-sandbox.lab.example.com/healthz` for protected lab health.
These names are not a deployment claim. Until the coordinated migration is
verified, keep using the retained Serverware sandbox and its existing endpoints.

The sandbox has its own three-database store, signed policy and nonce history.
Use the [explicit sandbox migration](../../scripts/migrate_catchplate_sandbox.py)
on a stopped private copy; do not run the ordinary migrator or initialize empty
replacement state. Preserve the old recovery configuration and original data.
The effective renamed Compose model must pin the accepted image, migrated
mounts, secrets and network ownership before this template is used.

See the [rename checklist](../../docs/catchplate-rename.md) for accepted artifacts,
remaining deployment work and immutable historical evidence.
