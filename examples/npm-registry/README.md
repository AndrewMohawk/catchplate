# npm registry through Serverware

A small stock-client project: **read metadata by default**, select a specific
manifest with pacote, deliberately publish a reviewed local tarball, or install
a reviewed consumer project into a new retained directory. The
client never receives the real npm provider token. This is example source, not a
claim that this project has contacted the public npm registry successfully.

The current dependency pins are Node **25.5.0**, npm **11.20.0**, pacote
**21.5.1**, and npm-registry-fetch **19.1.1**. The project requires those
versions and POSIX process groups (Linux/macOS). Earlier isolated proxy
acceptance used npm 11.8.0/pacote 21.0.4. The current pinned graph separately
passed all 25 isolated proxy phases on October 13 after a narrow publish-receipt
compatibility fix; see the current verification record below. Other
versions/platforms are unverified.
Run as a normal OS account with a resolvable home directory (as on a GitHub-hosted
runner), not an arbitrary numeric container UID with no passwd entry.

## Prepare the application

In Serverware, save an npm-token connection, create an application whose proxy
authentication supports **Basic** (Basic-only or Basic and Bearer), and grant
either **Read package metadata** (`npm_metadata_read_v1`) for your exact package
or **Publish package** (`npm_publish_v1`) for your exact package and tag. The
additive **Install packages** (`npm_install_v1`) permission selects exact package
names including dependencies. It requires matching proxy capability; it is not
an upgrade to either older grant. Publishing
also grants metadata reads for that same package. Only one active npm metadata
or publishing permission is supported per application, and installation cannot
overlap another registry permission in that application; this example does not
change permissions or merge grants. The operator must also approve
`https://registry.npmjs.org` as an upstream.

The stock clients use the application ID/token for Basic CONNECT proxy
authentication; a Bearer-only application is not compatible with this example.

Install the pinned example dependencies in a trusted preparation environment,
before injecting any application token:

```sh
cd examples/npm-registry
npm ci --ignore-scripts --no-audit --no-fund
node --test client.test.mjs install.test.mjs
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
| `SERVERWARE_NPM_VERSION` | Specific `major.minor.patch` release, needed by manifest/publish/install/ci |

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

## Install a reviewed project

Installation requires the matching app/proxy capability. The October 12
compatible deployment includes it, and stock install and cold `ci` passed
against an isolated registry; see [the verification record](../../docs/operator-npm-install.md).
That does not establish public proxy reachability or your npm account's access.
Metadata and publish permissions do not authorize downloads or audit requests.

Use a separate installation application and whitelist every required package,
including transitive dependencies. No dependency is automatically authorized
because another package names it. The example accepts a small private project
whose `package.json` contains `name`, `version`, `private: true`, and exact
ordinary-release `dependencies` (optional `description`/`license` are allowed).
The selected `SERVERWARE_NPM_PACKAGE` and `SERVERWARE_NPM_VERSION` must appear in
those direct dependencies. Workspaces, lifecycle scripts and Git/file/URL specs
are outside this example.

```sh
export SERVERWARE_NPM_PROJECT=/absolute/reviewed/consumer-project
export SERVERWARE_NPM_OUTPUT=/absolute/new-installed-project
node client.mjs install
```

The output directory must not exist or be inside the source project. Only the
reviewed manifest and optional v3 lock are copied there; existing `.npmrc`,
`node_modules` and other source files are not copied or modified. The stock npm
CLI then installs there with scripts disabled and **default audit enabled**.
Installed files and the generated lock remain after the command, including
partial output after failure. Scratch configuration, trust files and cache are
removed separately. This is not a sandbox for untrusted package contents.

For a cold `ci`, select the first output as the reviewed input and choose another
new output path. A registry-only v3 `package-lock.json` is required; the command
verifies its bytes remain unchanged. Both commands use a fresh cache. Do not
reuse an output directory to bypass failure inspection.

Lock entries must use registry tarballs. Direct dependencies explicitly listed
in a registry package's `bundleDependencies` are accepted without separate
fetch fields; inherited or hoisted bundled graphs are outside this example.

The result includes the retained directory, installed package/version, lock
hash and npm's audit counts. Successful exit with missing/failed audit metadata
is refused: npm can otherwise return zero after its audit endpoint fails.
Nonzero vulnerability counts are reported, not hidden; an independent policy
can decide whether they should block adoption. The proxy's request/response
audit is separate from npm's dependency-vulnerability audit.

Failures include a small `diagnostic` object naming the launcher/worker stage
and an allowlisted process or npm error code. Unknown codes become `other`;
raw error messages, command output, credentials and paths are not included in
that object. This helps distinguish input, transport and verification failures
without retrying a command or treating a partial installation as success.

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

HTTP timeout is 10 seconds and retries are zero. For metadata/publish, npm's
subprocess timeout is 12 seconds and the whole worker process group is killed
after 15 seconds. Install/ci allow 55 seconds for npm, 60 seconds for the worker
and 65 seconds for its process group. Local
tarball inspection shares that worker budget. Scratch data is removed after the
worker exits; installation output remains. Original project/CA/tarball files and
the caller's environment are unchanged.
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

`node --test client.test.mjs install.test.mjs` exercises validation, configuration, dummy/token
separation, mocked stock SDK/CLI calls, local review refusal, receipt/error
handling and process-group setup. It opens no network connections or real child
processes and performs no registry writes. The installation copy test uses only
its own temporary files and verifies that existing input/output are preserved.
These tests do not establish proxy,
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

## Dependency repair and remaining upstream advisories

The October 12 dependency repair uses the official
[npm 11.20.0 release](https://github.com/npm/cli/releases/tag/v11.20.0) and
[pacote 21.5.1 release](https://github.com/npm/pacote/releases/tag/v21.5.1).
Both declare Node `^20.17.0 || >=22.9.0`, compatible with the retained Node
25.5.0 pin. npm's bundled pacote and npm-registry-fetch are checked separately
against the same exact versions as the standalone packages. No bundled code,
dependency override, TLS policy or retry policy is patched.

The regenerated lock still reports five vulnerable packages, all inside npm's
upstream bundle: `brace-expansion`, `http-cache-semantics`, `ip-address`,
`postcss-selector-parser`, and `undici` (three high, two moderate in the retained
October 12 npm audit). This is a partial dependency repair, not an advisory-free
or exploitability verdict. Do not hand-edit bundled dependencies or treat the
older proxy receipt as verification of this updated graph; the October 13
acceptance below is a separate run with the updated dependencies.

During the October 12 update, 29 Node component groups and 99 Python fixture/checker/recipe
groups passed in a read-only, network-disabled container. The actual stock CLI
also passed the separate loopback-only install, cold `ci`, and refused-audit
protocol checks: 13 arrivals total, no cold-`ci` metadata reads, unchanged lock
bytes, and audit failure rejected despite npm returning zero. That protocol
fixture is not the Serverware proxy, does not exercise TLS, and does not
establish publication or provider access for the updated versions. The first
CLI attempt ran as an unsupported numeric UID without a passwd entry and
failed before any registry arrival; using the image's existing normal account
resolved that harness error without changing application configuration.

## Current isolated proxy verification

On October 13, 2026, source `e7d7e05b` passed the actual 25-phase example flow
with npm 11.20.0, pacote 21.5.1 and npm-registry-fetch 19.1.1 through the real
Serverware application, Rust gate and HTTPS proxy against a network-isolated
synthetic registry. Nine commands succeeded and 16 expected refusals passed.
The run verified three exact publications, install and cold `ci` with transitive
package bytes and an unchanged lock, successful default audit, rejected audit
failure despite npm exiting zero, permission/revocation controls, and the
complete persisted audit chain. All owned containers were removed; source and
cached dependency bytes were unchanged.

The first current-graph attempt stopped at unscoped publication: npm succeeded,
but our example expected the older flat JSON receipt instead of npm 11.20's
package-keyed receipt. That failed attempt is retained and was not replayed.
The fix accepts exactly one matching package key and preserves the inner
package/version/ID/size and archive hash checks; 30 offline component tests
passed, including malformed-receipt controls that assert one call and no retry.
The successful acceptance used fresh runtime state and a new 519-input Rust
build/source join, not the older verification record.

See [the current acceptance record](../../docs/operator-npm-example-acceptance.md)
for exact source and evidence identities. This proves the bounded example with
a synthetic provider, not real npm entitlement, public routing, GitHub Actions
execution, native approval, or deployment of this source. Upstream dependency
advisories above remain; the project still never publishes by default.

## Historical isolated proxy verification

On 2026-10-12 UTC, the expanded stock npm 11.8.0 scenario passed 25 commands
against an isolated synthetic registry: nine successful commands and 16
expected failures. It verified installation, transitive package bytes, cold
`ci`, an unchanged lock, advisory success/failure handling and 63 durable audit
events. The tested app/proxy pair is deployed; live LAN proxy and audit checks
passed separately. This is not real npm entitlement or Internet CONNECT proof.
See [the installation record](../../docs/operator-npm-install.md).

On 2026-10-11 UTC, the then-current launcher and worker passed all 21 integration
cases through the actual Serverware application, Rust gate and HTTPS proxy
against an isolated synthetic registry. The run verified metadata reads, both
scoped and unscoped publications, permission/time-window/revocation denials,
missing-root TLS failures and local publication guards. Stored tarball bytes
and the durable audit chain were checked independently.

See [the acceptance record](../../docs/operator-npm-example-acceptance.md),
including the retained first failure and its checker correction. This is not
public npm, GitHub Actions, dependency-installation or current-deployment
acceptance. The project still never publishes by default.
