# npm registry through Serverware

A small stock-client project: **read metadata by default**, select a specific
manifest with pacote, or deliberately publish a reviewed local tarball. The
client never receives the real npm provider token. This is example source, not a
claim that this project has contacted the public npm registry successfully.

The transport/configuration follows the existing isolated fixture for Node
**25.5.0**, npm **11.8.0**, pacote **21.0.4**, and npm-registry-fetch **19.1.1**.
The project requires those versions and POSIX process groups (Linux/macOS); the
existing fixture was verified on Linux. Other versions/platforms are unverified.
Run as a normal OS account with a resolvable home directory (as on a GitHub-hosted
runner), not an arbitrary numeric container UID with no passwd entry.

## Prepare the application

In Serverware, save an npm-token connection, create an application whose proxy
authentication supports **Basic** (Basic-only or Basic and Bearer), and grant
either **Read package metadata** (`npm_metadata_read_v1`) for your exact package
or **Publish package** (`npm_publish_v1`) for your exact package and tag. Publishing
also grants metadata reads for that same package. Only one active npm metadata
or publishing permission is supported per application; this example does not
change permissions or merge grants. The operator must also approve
`https://registry.npmjs.org` as an upstream.

The stock clients use the application ID/token for Basic CONNECT proxy
authentication; a Bearer-only application is not compatible with this example.

Install the pinned example dependencies in a trusted preparation environment,
before injecting any application token:

```sh
cd examples/npm-registry
npm ci --ignore-scripts --no-audit --no-fund
node --test client.test.mjs
```

Dependency installation is **not** authorized by the metadata/publish permission
and is not part of the proxied example. Direct versions are pinned and a genuine
generated `package-lock.json` is checked in. Review that lock and deliberate
dependency updates; `npm ci` installs its recorded dependency tree without
rewriting it. The mocked tests need only Node built-ins and can run without
installing dependencies.

Use [.env.example](.env.example) as an environment-variable reference; the program
does not automatically load it. Supply real values through your secret manager
or shell environment without committing them:

| Variable | Meaning |
| --- | --- |
| `SERVERWARE_PROXY_URL` | HTTPS proxy origin, no credentials, path, query or fragment |
| `SERVERWARE_APP_ID` | Serverware application UUID |
| `SERVERWARE_PROXY_TOKEN` | That application's Serverware token, **not** an npm token |
| `SERVERWARE_CA_FILE` | Trusted interception CA PEM obtained from your deployment |
| `SERVERWARE_PROXY_CA_FILE` | Optional trusted private CA for the outer HTTPS proxy |
| `SERVERWARE_NPM_PACKAGE` | Exact lowercase package name, for example `@your-scope/your-package` |
| `SERVERWARE_NPM_VERSION` | Specific `major.minor.patch` release, needed by manifest/publish |

Verify the CA through your trusted deployment/operator channel. This example
does not bootstrap trust by downloading an unverified CA or disabling TLS.
`serverware-npm-placeholder-v1` is intentionally public provider-dummy data; the
proxy matches it before replacing it with its saved npm credential.

## Read metadata

```sh
node client.mjs            # Stock npm view; read-only default.
node client.mjs manifest   # Stock pacote.manifest for SERVERWARE_NPM_VERSION.
```

Both operations print only a bounded package/version summary of the SDK result.
The proxy still validates the complete metadata response. They do not download
package tarballs, install dependencies, run scripts, or follow dependency graphs.
The example deliberately accepts ordinary `major.minor.patch` release versions,
not prereleases, arbitrary specs, URLs, aliases or Git/file requests.

## Explicit public publication

This changes the registry. Read the full [publishing policy](../../docs/operator-npm-publish.md)
and review the package contents and version first. Build/package preparation is
outside this project; only an already reviewed local tarball is accepted.

Set these additional environment variables deliberately:

```sh
export SERVERWARE_NPM_TAG=latest
export SERVERWARE_NPM_TARBALL=/absolute/reviewed/package.tgz
export SERVERWARE_NPM_TARBALL_SHA256='REPLACE_WITH_REVIEWED_64_CHARACTER_LOWERCASE_SHA256'
export SERVERWARE_NPM_PUBLISH_CONFIRM=publish-publicly
node client.mjs publish
```

Replace the placeholder hash before executing; use the tag saved in your
permission. No publish command runs by default or from the sample CI workflow.
The launcher verifies the hash and copies at most 8 MiB to a private file. Stock
pacote reads the local tarball's manifest with offline/script-disabled options
(it may unpack into the private cache). The name and version must match your
explicit environment, `private: true` is refused, and **any `publishConfig` is
refused** so it cannot override this example's settings. This is not a malicious
archive sandbox or content-safety scan: use only your reviewed archive.

It then runs the stock npm CLI exactly once, with the dedicated npmrc and:

```text
publish <private-reviewed-copy.tgz> --access=public --tag=<saved-tag>
--ignore-scripts=true --provenance=false --force=false --dry-run=false
--workspaces=false --json
```

The server enforces the package, tag and optional daily UTC publishing window.
The registry's own permissions and noninteractive publishing requirements still
apply. Companion metadata reads are allowed outside the PUT window. Install,
tarball downloads, unpublish, standalone tag changes, provenance, provider 2FA,
trusted publishing and token renewal are not provided by this permission.

A successful result means npm returned a matching name/version/tarball receipt;
it is **not** an independent registry-state or audit proof. Stock npm can swallow
preflight metadata errors before attempting PUT. The separate integration
fixture verifies the prerequisite GET independently; this example does not.
After a timeout or any failed publish, the write may have reached the registry.
Inspect registry metadata and Serverware audit evidence before deciding what to
do. Never automatically retry; a missing version in one observation does not
prove an in-flight write cannot still complete.

## Trust, deadlines and CI

Each invocation creates a private npmrc, empty global config, project and cache.
The npmrc stores a literal `${SERVERWARE_PROXY_TOKEN}` reference, not the token.
Only the child's curated environment contains the application token; ambient
`NPM_TOKEN`, npm/proxy configuration, `NODE_OPTIONS` and TLS overrides are not
forwarded. `HOME` is not reassigned or forwarded. npm can resolve the OS user's
home but receives explicit user/global configuration paths. Pacote receives
explicit cache/TUF-cache paths and the public dummy auth option; it does not load
the user's npmrc to discover credentials. Do not enable shell tracing or
inspect/log child environments.

The launcher combines the explicit private outer CA (if needed) and interception
CA into `NODE_EXTRA_CA_CERTS` **before** starting Node. npm/pacote use this additive
trust for both TLS layers while retaining default public roots; unlike clients
with separate per-layer TLS settings, this is one combined trust bundle. TLS and
hostname verification stay enabled; there is no `cafile` replacement.

HTTP timeout is 10 seconds, retries are zero, npm's subprocess timeout is 12
seconds, and the whole worker process group is killed after 15 seconds. Local
tarball inspection shares that worker budget. Scratch data is removed after the
worker exits; original CA/tarball files and the caller's environment are unchanged.
Errors are fixed, redacted messages, never raw npm output, stacks or proxy URLs.

[workflow.example.yml](workflow.example.yml) is an **inactive**, manually
triggered, read-only GitHub Actions sample for an Ubuntu GitHub-hosted runner.
Checkout/setup actions use the same exact official commit pins as the GitHub
issues example. Review the checked-in dependency lock before enabling it. The
dependency installation step receives no Serverware secrets, and only the final
read step receives the application token. No provider token, automatic publish
or unverified CA download is included. Review the protected `serverware-demo`
environment before deliberately copying it into `.github/workflows/`.

## Offline verification boundary

`node --test client.test.mjs` exercises validation, configuration, dummy/token
separation, mocked stock SDK/CLI calls, local review refusal, receipt/error
handling and process-group setup. It opens no network connections or real child
processes and performs no registry writes. These tests do not establish proxy,
TLS, current deployment or public-provider acceptance. A separately authorized
integration run must establish those boundaries with the real client and audit
evidence; tests alone do not do so.

On 2026-10-10, all **11 mocked test groups passed**, and `verifyVersions()` passed
against the actually installed pinned packages, including npm's bundled pacote
and npm-registry-fetch. The version-only check is:

```sh
node --input-type=module -e "import { verifyVersions } from './client.mjs'; verifyVersions();"
```

This checks installed package metadata, not a registry request.

## Isolated proxy verification

On 2026-10-11 UTC, this unchanged launcher and worker passed all 21 integration
cases through the actual Serverware application, Rust gate and HTTPS proxy
against an isolated synthetic registry. The run verified metadata reads, both
scoped and unscoped publications, permission/time-window/revocation denials,
missing-root TLS failures and local publication guards. Stored tarball bytes
and the durable audit chain were checked independently.

See [the acceptance record](../../docs/operator-npm-example-acceptance.md),
including the retained first failure and its checker correction. This is not
public npm, GitHub Actions, dependency-installation or current-deployment
acceptance. The project still never publishes by default.
