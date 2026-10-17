> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Retained synthetic sandbox

This directory holds the renamed deployment model and edge template for the
existing, separate synthetic sandbox. It is not the ordinary product instance or a fresh-install
recipe. Use the [standalone installer](../catchplate-standalone/README.md) for a
new ordinary installation.

The template is the retained sandbox ingress configuration with Catchplate
hostnames, service names and private-header paths. Its actual-peer, authenticated
operator and browser-origin checks are unchanged. It requires the existing
deployment's reviewed `TRAEFIK_IPV4` and a private
`/run/secrets/catchplate-edge/admin-header.conf`; neither value is generated here.
It publishes no forward-proxy listener or host port.

The console is `https://catchplate-sandbox.example.com/`, with
`https://catchplate-sandbox.lab.example.com/healthz` for protected lab health.
The retained sandbox migrated on October 17, 2026. Both TLS routes, the public
login redirect, private health and the internal proxy/audit flow are verified.
The main ordinary installation is a separate, still-pending cutover.

The sandbox has its own three-database store, signed policy and nonce history.
Use the [explicit sandbox migration](../../scripts/migrate_catchplate_sandbox.py)
on a stopped private copy; do not run the ordinary migrator or initialize empty
replacement state. Preserve the old recovery configuration and original data.
The [Compose model](docker-compose.yml) pins the accepted paired image and
expects already-migrated private state under
`/srv/catchplate-fast/homelab_data/catchplate-sandbox`. It uses a separate internal
subnet and a dynamically assigned edge address on the shared Traefik network,
so the stopped original containers/network can remain available for rollback.
The exact trusted Traefik peer is unchanged.

The model now targets the verified migrated state. Its `x-catchplate-migration`
metadata records the migration identity and evidence, not a Docker-enforced
startup guard. The app's incomplete-migration checks are separate. Do not use
this deployment-specific model to initialize another installation or start the
old and new sandbox writers together.

The accepted paired image and Rust binary are unchanged. One read-only bind
mount supplies the versioned sandbox checker with the current post-dispatch
error contract; it verifies the reflection-block response's no-retry metadata.
The full mounted checker passes against the running app and proxy. Original
state and stopped resources remain preserved; rollback after new activity needs
an explicit audit-lineage review, not a blind restart of the old containers.

See the [rename checklist](../../docs/catchplate-rename.md) for accepted artifacts,
remaining deployment work and immutable historical evidence.
