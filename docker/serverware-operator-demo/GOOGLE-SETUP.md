> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Optional Google profile: retained operator deployment

This is an opt-in configuration and rollout guide, not evidence that Google is
enabled or that real consent has passed. It does not initialize a new database,
replace retained data, register a Google client, or authorize a deployment.

Use `docker-compose.yml`, exactly one reviewed immutable app/gate source
override, then `docker-compose.google.yml`, in that order. The Google layer does
not select application source or a binary. The existing accepted override pins
`c4611550`/`e7529b44`; do not assume that older application implements the new
retained-store first-enable transition. Freeze and review the integrated source
and matching gate identity before selecting the pair.

## Required operator inputs

Provide these through a separately protected deployment environment, retaining
the original environment unchanged. Never put a client secret in YAML, Git,
command arguments, logs or chat.

| Variable | Required value |
| --- | --- |
| `SERVERWARE_GOOGLE_OAUTH_CLIENT_ID` | The reviewed Google OAuth web-client ID ending in `.apps.googleusercontent.com`. |
| `OPERATOR_GOOGLE_CLIENT_SECRET_FILE` | An existing absolute host path to the private client-secret file; not the secret value. |
| `SERVERWARE_OPERATOR_GOOGLE_UPSTREAMS` | The exact JSON origin list reviewed by the first-enable preparation: retain every current origin and add `https://gmail.googleapis.com`. There is deliberately no default. |

For the recorded fixture-only deployment, the intended origin set is the old
`https://demo-upstream:8443` plus `https://gmail.googleapis.com`; the live stored
settings and prepared transition are authoritative, including canonical order.
Do not replace a larger retained list with this example. Preserve the existing
fixture CIDR and `OPERATOR_DEMO_SDK_SOURCE`; the latter still selects the old
synthetic fixture, not the new application.

Register this exact redirect URI on the reviewed Google client:

`https://serverware-demo.example.com/api/oauth/callback/google`

The secret file must be a single-link regular file, owned by UID `10001`, mode
`0400` or `0600`, with no symlinks in its path. The profile accepts 1–4096 bytes
and rejects malformed contents. Ancestors must be traversable by the app.
Compose must not create a missing source path. Only the app receives this one
read-only bind at `/run/secrets/serverware-google/client.secret`; the gate,
edge and fixture receive neither its mount nor the secret-file variable.
Include an outside-data-root secret file in the separately protected recovery
plan without printing its contents. Profile admission pins its identity and
contents; replacing the file is not a supported silent rotation.

## Configuration boundaries and preflight

- The app retains its existing sandbox address and gains only the existing
  outbound network, using Docker's dynamic address allocation. No network is
  recreated. This provides network egress, not a hostname-filtering firewall.
  OAuth destinations remain fixed in the profile.
- The app's inherited `dns: [127.0.0.1]` is removed with `dns: !reset []` so normal
  container DNS can resolve Google's endpoints. This requires an installed
  Compose implementation supporting `!reset`. A synthetic-variable render with
  installed Compose v5.3.1 verified its removal, matching public profile/origin
  values, app-only secret mount and no host ports. This is configuration-parser
  evidence, not a deployment: the rollout owner must still render the exact
  reviewed source pair and private deployment inputs successfully. Do not
  replace the tag with a plain empty list and assume inherited DNS was cleared.
- Inspect a nonsecret projection of that model: both services must have the
  same reviewed origin list, client ID, profile and callback; app DNS must not
  retain `127.0.0.1`; only the app gains the outbound attachment and secret bind.
  Check the selected app source, expected gate digest and actual executable
  together. No provider request is implied by a successful render.
- Preserve every existing writable mount, service token, CA/key, database,
  policy/high-water file and publication-lock inode. Keep cached image pins,
  resource limits and read-only/capability settings. Do not add host ports,
  Traefik labels, a public app route, or a new service.
- Keep the edge's Authelia middleware, exact operator/peer checks, Origin checks,
  admin-header injection and header scrubbing unchanged. The callback uses the
  existing protected console host; no SSO bypass or public callback exception
  is introduced. The proxy's TLS/workload authentication is unchanged.

## Retained-state enablement sequence

If the running app lacks the setup API, first deploy the reviewed candidate
implementation with Google still unselected and the old settings unchanged,
under the existing retained-state maintenance checks. The Google layer is not
part of that preparatory application update.

1. On the reviewed candidate implementation, read
   `GET /api/operator-demo/oauth/google/setup` and review its current-state-bound
   transition. Stage it using `POST` to that same path with only `operation_id`
   (canonical UUID), `client_id`, `expected_settings_digest`, `expected_revision`
   and `expected_policy_hash` (maximum 4096-byte body). The existing admin and
   exact-Origin mutation guards apply. Recover a lost response using
   `GET /api/operator-demo/oauth/google/setup/{operation_id}`, not a blind retry.
   A pending operation has a separate `POST .../setup/cancel` route with only
   `operation_id`, `expected_revision` and `expected_policy_hash` (maximum
   2048-byte body). Merely adding an origin to Compose is insufficient: the old
   store rejects allowlist drift.
   Preparation is not consent and must not replace old credentials, applications,
   rules, token verifiers or signed policy. Use the returned review and operation
   status; staging does not yet enable Google.
2. Quiesce writers using the existing maintenance procedure: stop the same edge,
   stop the gate while the app can acknowledge audit, then stop the app. Confirm
   authoritative process termination and preserve a fresh, verified consistent
   private backup, including SQLite sidecars, deployment inputs and secret-file
   recovery coverage. Keep the fixture running. Do not run an initializer.
3. Recheck the reviewed transition against retained state and the new pair plus
   Google configuration before startup. Preserve the publication lock and use
   only the explicit supported transition; no manual settings edit, data reset,
   or automatic rollback to old source/state is permitted by this guide.
4. Start the selected app and then gate using bounded, selective recreation with
   `--no-deps --no-build --pull never`. Before restarting the same edge, verify
   retained rows and files, the expected transition-only changes, actual binary
   identity, matching profile binding and loaded policy, audit health, and
   unchanged console/proxy authentication. Stop at the first failed boundary.
5. Only after deployment verification and separate authorization, perform real
   browser consent through the normal SSO session; verify the intended account,
   approved Gmail read assignment and unattended refresh using bounded provider
   requests. Synthetic fixture success, health and source checks are not this
   acceptance. Application-token expiry remains separate from provider refresh.

After activation, simply unsetting the Google flag, changing the client/callback,
or restoring part of a backup is not a safe rollback: the profile and retained
authority are pinned. Use an explicitly reviewed forward-repair or recovery
procedure. Real Google, public-Internet reachability and native/production
authority remain separate acceptance boundaries.
