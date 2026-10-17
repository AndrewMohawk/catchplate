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

The planned console is `https://catchplate-sandbox.example.com/`, with
`https://catchplate-sandbox.lab.example.com/healthz` for protected lab health.
These names are not a deployment claim. Until the coordinated migration is
verified, keep using the retained Serverware sandbox and its existing endpoints.

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

The model is still **unarmed**: do not run `up` before the stopped-copy migration
and its receipt have been verified. The `x-catchplate-migration` metadata is an
operator checklist, not a Docker-enforced startup guard. The app's incomplete-
migration checks are separate. Compose validation alone does not prove that
state is migrated or that the new routes are serving.

See the [rename checklist](../../docs/catchplate-rename.md) for accepted artifacts,
remaining deployment work and immutable historical evidence.
