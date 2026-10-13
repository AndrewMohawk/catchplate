# Optional managed X on the existing instance

`docker-compose.managed-x.yml` enables the managed-X capability on the app and
gate and adds one private app-only mount. It does not deploy anything by itself,
select a source/binary pair, configure an X application, or contact X. The ordinary
local-key security mode is unchanged; this is not native or verified-production
admission.

## Prerequisites

- Use the reviewed, matching X-capable app source and normal gate binary, with
  the app's expected binary digest updated together. Retain the complete current
  Compose layer list, environment file, auth, CA, policy, high-water, notifications
  and other custody mounts. Do not select historical artifact pins from an older
  optional override merely to enable X.
- Keep the existing curated-gate publication layer. The app publishes the public
  `gate-runtime/operator-x-configuration.json`; the gate reads that projection
  through its existing read-only `/data` mount, never the X custody directory.
- Supply `OPERATOR_MANAGED_X_CUSTODY_DIR` as an explicit absolute, canonical,
  existing host directory owned by app UID/GID `10001:10001`, mode `0700`. It must
  have no symlink components and be disjoint and nonnested with app data, gate
  data, Google custody, notification custody and every other service's mounted
  roots. Check resolved paths **and bind aliases/inode identity**: no other service
  may mount this directory or an ancestor exposing it. The app alone mounts it
  read-write at `/x-custody`; `create_host_path: false` prevents silent creation.
- For a genuinely first, unconfigured enablement, independently confirm no
  retained X configuration/lifecycle state and use an empty custody directory.
  On subsequent starts retain the original directory and key; never empty it,
  regenerate a missing key, or substitute a fresh directory for retained state.
- Existing runtime admission must already select the ordinary dev/SQLite owner,
  explicit no-seed/no-dev-authenticator settings, gate publication and canonical
  public HTTPS origin. No native/enrolled owner or `SERVERWARE_X_OAUTH_*` /
  `SERVERWARE_TWITTER_OAUTH_*` environment selections may be present, even empty.

Append `-f docker/serverware-operator-demo/docker-compose.managed-x.yml` to the
exact reviewed Compose command before its `config --format json` arguments.
Keep rendered models private: other layers can contain sensitive settings.
Compare the full result: only two app environment entries, one gate flag and
one app bind should change. Compose requires a nonempty input but cannot establish
host ownership or alias separation; that host review remains an activation gate.
The runtime independently rejects missing, nonprivate, symlinked and
container-visible data/Google-overlapping custody paths.

Use the existing fresh-state capture and fenced paired-rollout procedure; this
file supplies no alternate restart or rollback path. Start/admit the app's public
projection before admitting the gate. Preserve all original private state.

## Initially unconfigured

No X client ID or secret is required to expose the unconfigured setup panel.
Authenticated discovery must report unconfigured without initializing a key or
contacting the provider. The operator later enters their confidential OAuth
application in the authenticated UI, using the canonical
`/api/oauth/callback/x` callback. First save retains encrypted configuration;
configuration replacement is not enabled by this layer. Never put credentials
in this override, an environment file, test fixture, or chat.

Account consent and posting remain separate, explicit actions. They require
the configured application, an approved `https://api.x.com` destination, genuine
account consent and an application permission. This override does **not** add
that destination, consent an account, grant access, post, or enable daily quotas.

## Focused verification

`TMPDIR=/tmp python3 -B scripts/test_operator_managed_x_deployment.py` checks the
closed layer, actual Compose rendering when available, exact preservation of
existing settings and real filesystem custody refusals with synthetic admission
context. It starts no containers and creates no real host custody. It does not
establish deployed startup, native admission or provider success. The deployment
owner must separately verify the rendered model against the live instance and
check unconfigured discovery/UI plus actual paired startup after authorization.
