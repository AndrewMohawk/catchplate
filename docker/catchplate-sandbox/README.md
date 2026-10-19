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
The main ordinary installation is live separately at
`https://catchplate.example.com/`.

On October 19 the sandbox CA was replaced with a fresh Catchplate CA, without
retaining the old CA for recovery. Its certificate fingerprint is
`0bcb5a4fda8b42c1c9719f9f8b3ef4dfad69174bf18d1a07ab046e6d383ff9ae`.
The eight-check real proxy/audit flow passed after replacement. Obtain the
current `/ca.pem`; do not reuse an older CA or disable TLS verification.

The sandbox has its own three-database store, signed policy and nonce history.
Use the [explicit sandbox migration](../../scripts/migrate_catchplate_sandbox.py)
on a stopped private copy; do not run the ordinary migrator or initialize empty
replacement state. The migration has already completed: do not replay it.
Saved records remain intact, but retired CA copies were explicitly removed.
The [Compose model](docker-compose.yml) pins the accepted paired image and
expects already-migrated private state under
`/srv/catchplate-fast/homelab_data/catchplate-sandbox`. It uses a separate internal
subnet and a dynamically assigned edge address on the shared Traefik network.
Retired containers and the empty original network have been removed.
The exact trusted Traefik peer is unchanged.

The model now targets the verified migrated state. Its `x-catchplate-migration`
metadata records the migration identity and evidence, not a Docker-enforced
startup guard. The app's incomplete-migration checks are separate. Do not use
this deployment-specific model to initialize another installation or start the
old and new sandbox writers together.

The accepted paired image and Rust binary are unchanged. Read-only bind mounts
supply the current sandbox UI and versioned checker with the current post-dispatch
error contract; it verifies the reflection-block response's no-retry metadata.
The full mounted checker passes against the running app and proxy. Original
database/audit records remain historical evidence, not a ready-to-start rollback
installation. The old CA was also removed from the two retired data locations
and four previously retained migration copies; no old-CA backup was made.

See the [rename checklist](../../docs/catchplate-rename.md) for accepted artifacts,
remaining deployment work and immutable historical evidence.
