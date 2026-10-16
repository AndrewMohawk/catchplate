# Run your own Serverware instance

Use this package when you want a new, empty Serverware installation on your own
Linux server. It runs the console, Rust proxy and an Nginx TLS edge without
Authelia, Traefik or the original homelab deployment. The console uses an
administrator username/password; applications use their own Serverware client
tokens through the separate proxy hostname.

**Isolated installation and lifecycle verified.** Both build paths and fresh
starts passed; browser, saved-state restart and TLS replacement checks also
passed. No host ports or provider calls were used. See the [verification record](../../docs/standalone-installation-verification.md)
for exact boundaries; this is not proof of your public deployment or provider access.
These steps are not a migration recipe for the existing running instance. Host administrators
remain trusted: control of the server can bypass its policies. No TEE or hardware
approval guarantee is claimed.

## What you need

- A Linux/amd64 host with root access, local rootful Docker, Docker Compose v2,
  Python 3, Git and OpenSSL. Remote/rootless Docker and other image architectures
  are not supported by this package.
- A clean, committed checkout of this repository. The commands below run from
  its root. Commit intended source changes before an explicit build; the builder
  refuses uncommitted edits and untracked files. Keep installation configuration,
  passwords, certificates and runtime state outside the checkout.
- Two distinct DNS hostnames pointing to this host: one for the console and one
  for the HTTPS forward proxy. Both use port 443. HTTP, localhost and literal-IP
  origins are not supported substitutes.
- A currently valid PEM certificate chain covering **both** hostnames in its DNS
  subject alternative names, server certificate first, plus its matching
  **unencrypted** PEM private key. Obtain and renew these through your certificate
  provider; the installer does not provision DNS or ACME certificates.
- Regular, non-symlink TLS files. Keep the private key owner-only, mode `0600`.
  If your certificate manager uses symlinks, provide protected regular copies.
- A dedicated new state location and at least one intended provider HTTPS
  origin. Allowed destinations alone grant no application permission.

Port 443 must be available on the chosen interface. The sample explicitly binds
`0.0.0.0:443`; review your host firewall and exposure before using it. Only the TLS
edge publishes a port. The application and proxy internals stay on the stack's
private Docker network. This package does not modify the host firewall.

## First installation

1. Copy [config.example.json](config.example.json) outside the checkout, for
   example to `/etc/serverware/serverware.json`, and edit the hostnames, TLS paths,
   state directory and destination list. Keep the configuration directory private.
   It contains paths and public settings, **not passwords or provider keys**.

2. Build the application/proxy image once:

   ```bash
   sudo python3 scripts/serverware_standalone.py build
   ```

   This explicit command builds the normal Rust proxy and matching application
   image, using available build caches. It also obtains the pinned Nginx image
   if absent. Building may take several minutes on a fresh machine; opening the
   console, `start` and `status` never build or pull images.

3. Initialize the empty state directory:

   ```bash
   sudo python3 scripts/serverware_standalone.py init --config /etc/serverware/serverware.json
   ```

   Enter the administrator password twice at the private terminal prompt. Use
   12–1024 UTF-8 bytes without newlines or NUL. For automation, supply an
   owner-only password file with `--admin-password-file /private/password-file`;
   never put a password in JSON, a command argument or this repository.

   Initialization pins image identities, copies TLS material, and creates
   private service credentials and an installation manifest. It refuses an
   existing nonempty state directory rather than adopting or overwriting it.
   The default console username is `admin`.

4. Start and inspect the instance:

   ```bash
   sudo python3 scripts/serverware_standalone.py start
   sudo python3 scripts/serverware_standalone.py status
   ```

   These commands use the sample's `/var/lib/serverware-standalone` state path.
   If you chose another path, add `--state-dir /your/state/path` to lifecycle
   commands. Startup brings up the application
   first, waits for its policy/CA publication, then starts the proxy and finally
   the edge. It does not seed fixture credentials, clients or permissions.

Open your configured console hostname and sign in. Follow
[Getting started](../../docs/wiki/Getting-started.md): save a credential, create a
client, grant a specific permission, then download that client's private config
and the public proxy CA. The administrator password is **not** a proxy credential;
provider secrets stay in Serverware. A healthy empty instance is not proof that
a provider request has succeeded.

## Configuration choices

The JSON has a closed `serverware.standaloneInstall/v1` schema. Use a unique project
name beginning with `serverware-`; the sample uses `serverware-standalone`, not
the existing homelab project's name. Use exact canonical
HTTPS origins with no path, credentials or query. `allowed_upstreams` contains
1–32 distinct origins, such as `https://api.github.com`; choose only destinations
you intend to use. It is not a credential or policy import.

`publish_address` is an IPv4 address followed by `:443`, or a bracketed IPv6
address followed by `:443`. Set it to `null` only for an isolated deployment with
no published host port; this does not create an alternative public route.
`admin_username` defaults to `admin`. Advanced `paired_image` and `edge_image`
overrides select already available images; initialization records their immutable
identities. The default paired image is `serverware-standalone:local` and the
default edge image is pinned by the package, not a floating `latest` tag.

For advanced hosts whose Docker automatic address pools are exhausted,
`network_subnets` may explicitly select the `control` and `outbound` network
CIDRs. Supply both as distinct, nonoverlapping private IPv4 networks, each
between `/16` and `/28`. Choose ranges that also avoid your existing Docker,
host and routed networks; this option does not reserve or repair address space.
Omit it, or use `null`, for Docker's normal automatic allocation. Make this
choice **before initialization**, not by editing the retained Compose file.

After initialization, lifecycle commands use the retained installation manifest,
not the original JSON file. Editing that JSON does not reconfigure a running or
stopped installation. Do not edit the generated manifest or Compose file to
bypass a mismatch. Image updates, configuration activation and certificate
renewal must preserve the retained identity and state; see the limitations below.

## Stop, recover and back up

```bash
sudo python3 scripts/serverware_standalone.py stop
```

`stop` preserves the state directory. `status` is read-only and never starts a
service. Reuse `start` after an ordinary stop; no rebuild or reinitialization is
needed. If startup fails, inspect its fixed diagnostic and `status`, correct the
reported prerequisite, and retry that same installation. Do not delete state,
regenerate keys or rerun `init` to repair a failed start.

For a backup, stop **all three services**, confirm that they are stopped, and copy
the **entire state directory** with ownership and file modes preserved to a
private backup destination. Also retain the original configuration and matching
immutable images. Copying only SQLite files is not sufficient: provider custody,
policy/signing keys, the proxy CA, client state and audit evidence belong together.
Keep backups encrypted and access-restricted; they contain secrets.

Restore is a deliberate offline operation, not an automatic installer command.
Restore a complete matching snapshot at its original absolute path with preserved
ownership/modes, while all original writers are stopped. Never run two writers
against the same store. Do not merge partial snapshots or initialize over a
restore. Credentials and client tokens may expire while stopped; inspect their
current state after restarting.

The root state directory is private. Its service data/custody directories use
UID/GID `10001`; do not recursively change them to your login user. Generated
edge settings and service files may contain authentication material. Do not paste
them into issues, commit them, or make the state directory world-readable.

## Troubleshoot a failed build or start

If the CLI reports **Private diagnostic file**, inspect that exact file locally.
The same path appears as `diagnostic_path` with `--json`. Captured build output
may contain sensitive details: do not publish the file or paste its contents into
an issue without reviewing and redacting it. Not every refusal creates a file.

For an initialized instance, first run `status`, then read only the last 100 log
lines per service using its retained Compose file:

```bash
sudo docker compose --project-name serverware-standalone \
  --file /var/lib/serverware-standalone/compose.json \
  logs --no-color --timestamps --tail 100 serverware decision-gate-rs edge
```

Use the original project name and state path if you changed the sample defaults.
This command neither starts nor rebuilds services. Keep logs local and redact
private details before sharing them. An ownership or manifest mismatch needs
inspection, not a guessed project name, a new `init`, or manual hash edits.

## Replace the HTTPS certificate

TLS certificates are copied into private state at initialization. Updating the
original certificate paths does **not** update the installed copies. Obtain a
renewed certificate/key pair, protect it as above, then explicitly install it:

```bash
sudo python3 scripts/serverware_standalone.py replace-tls \
  --certificate /etc/serverware/tls/fullchain.pem \
  --private-key /etc/serverware/tls/privkey.pem
```

Add `--state-dir` if you use a nondefault state location. The command validates
current validity, both configured hostnames and the matching key. It keeps a
private `tls-backups` entry and updates the copied TLS files and their manifest
pins. If the edge was running, only the edge restarts and its served certificate
is checked for both hostnames; a stopped edge stays stopped. The application,
proxy, provider credentials and proxy CA are not replaced. Existing identical
material is a no-op. Certificate issuance and scheduled renewal remain your
responsibility; run this before expiry.

If replacement fails and reports that the previous certificate/key/manifest
were restored, the private backup remains for inspection. If recovery cannot be
confirmed, preserve the `tls-backups` entry and any `tls-replacement.json` marker.
A retained marker blocks ordinary `start` and another replacement; a hard
filesystem failure may also prevent recording it. Use `stop` to stop the instance
and have the deployment owner restore and validate the recorded
certificate/key/manifest together before resolving recovery. Do not delete the
marker to force startup, edit hashes by hand or retry an uncertain replacement.
There is no automatic crash-recovery command.

## Current maintenance limits

The console can prepare destination or managed Google settings, but preparation
is not activation. Use its public activation handoff and
[activation guide](../../docs/self-hosting.md#activate-a-prepared-configuration).
Ordinary `start` refuses pending destination/managed Google preparations; it does
not silently activate them. A general standalone activation/update command is
not yet provided. Resolve or cancel a preparation through its existing reviewed
workflow **while the console is still running**, before stopping the instance.
If it is already stopped with a pending change, retain its state and seek an
explicit deployment recovery; do not edit the manifest to bypass this boundary.
X application configuration is saved immediately, with account consent separate.

No automatic image upgrade, migration, backup scheduling, DNS management, TLS
automation or hosted provider acceptance is implied by these commands.
