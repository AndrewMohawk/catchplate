# GitHub issues: implemented client contract and acceptance boundary

The GitHub client contract supports a server-held personal access token (PAT)
or a GitHub App installation, with the same two named-repository permissions.
The PAT connection originated at `7ee40d18`; the new App connection and automatic
installation-token renewal have a separate [verification checkpoint](#github-app-feature-verification-checkpoint).
Synthetic verification does not establish a successful real-provider request.

## Operator journey

In **Credentials → Add credential**, choose **GitHub**, then select a personal
access token or a GitHub App connection. This saves the credential only; it
creates no Serverware client, proxy token or permission. The same editor is
available inline from the **Set up access** action, not a separate sidebar page.
These consolidated labels await live deployment; see the
[UI checkpoint](operator-demo.md#navigation-update--source-verified-not-yet-deployed).

| Connection | Inputs saved in Serverware | Credential lifecycle |
| --- | --- | --- |
| Personal access token (PAT) | Connection name and the existing GitHub token. | Serverware does not renew the PAT; its provider permissions and expiry still apply. |
| GitHub App | Connection name, numeric App ID, numeric installation ID, private-key PEM, exact repository owner/name, and Issues access (`read` or `write`). | Serverware holds the encrypted private key and obtains short-lived installation tokens server-side, renewing them when needed. |

For a GitHub App, first register and install your App in GitHub with access to the
selected repository and the required Issues permission. This is an existing App
installation, not a GitHub OAuth user-login or consent flow. The GitHub App ID and
installation ID are also **not** the Serverware application ID: the latter
identifies an entry under **Clients**, the script or job allowed to use the proxy.
A GitHub App is a provider credential, not a Serverware client.

On the saved credential, choose **Use with a client**. Setup reuses that exact
credential without asking for its secret again. Select or create a client,
review the exact repository, and grant:

- **Read issues and comments**: list and read issues/comments, including supported
  pagination.
- **Read and create issues/comments**: those reads plus issue/comment creation.

No manual method, path, request-field or response-field lists are required.
For a PAT, the repository name is reviewed authority, not a verified discovery
result; saving the PAT does not test its validity. **Save and verify GitHub App**
instead contacts GitHub: it verifies the App and installation, obtains a scoped
installation token and verifies the repository before committing the connection.
The resulting App, installation, account and repository numeric identities are
bound to the selected repository and Issues permission ceiling. A read-only
App connection cannot authorize the create preset; a write-capable connection
still requires a separate application grant. Broader permissions on the GitHub
App do not become broader Serverware permissions. Existing generic Bearer keys
and saved rules are not automatically converted to either connection type.

Serverware stores the App private key encrypted, signs the App JWT server-side,
and requests an installation token limited to the saved repository and Issues
access, plus GitHub's read-only metadata permission. This does not grant clients
repository-metadata routes. Derived tokens are held in memory and renewed on demand near expiry
(a 65-second safety margin: 60 seconds plus a five-second lease allowance), not
handed to the SDK client. Renewal does
not extend the Serverware application token, expand a grant, or change the
stored credential configuration's generation. Manual private-key replacement is
a separate, generation-changing action described below. GitHub's [JWT documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
and [installation-token documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
explain the provider-side authentication and repository/permission limits.

A failed token-mint attempt is not retried in the same call. After a 60-second
backoff, a later separately authorized lease may attempt fresh authentication.
This is not a retry of an issue/comment request; repository writes are never
automatically replayed. Revoking the Serverware connection stops future local
use but does not claim remote GitHub-token revocation or recall an in-flight
request or an already-issued lease.

The deployment must advertise the exact GitHub capability and allow
`https://api.github.com` in its retained `allowed_upstreams`. A PAT may be saved
while that destination is disabled, but App verification/save requires it to be
enabled before any provider contact. Neither option can be granted or used
through client setup while the destination is disabled. The capability describes
co-versioned source support;
it does not negotiate or prove the running gate version. Wait for the exact saved
policy to be loaded by the accepted app/gate pair.

## Replace an App private key without rebuilding permissions

When the instance advertises this capability, open **Credentials**, select
**Replace GitHub App private key**, and review the repository and affected
clients. Generate a new private key for the same App in GitHub, then submit
that PEM. Do not create another Serverware connection or remove existing grants.
GitHub supports overlapping keys for rotation; deleting the old key is a
separate [GitHub-side action](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps).

Serverware verifies the candidate against the saved numeric App, installation,
account and repository identities and Issues ceiling before committing it. A
successful replacement advances the encrypted credential generation and catalog
revision once, records the replacement timestamp and emits the separately
selectable audit event `operator_catalog.credential.github_app_key_replaced`.
It does not change the credential identity, assigned applications, access rules,
signed policy or application proxy tokens. The replacement PEM is never returned
in the receipt or copied into audit notifications.

The review is bound to the saved generation, catalog revision and policy hash.
Changed state or failed provider verification refuses the replacement. If a
response is lost, refresh and review saved state; do not assume rollback or
automatically submit again. The form clears the PEM on submit, cancellation,
navigation and failure. Acknowledged storage and confirmed local cache
invalidation are reported separately. Previously issued GitHub installation
tokens, proxy leases and in-flight requests are not recalled by this operation.
Delete the old GitHub key separately after reviewing the result.

The current source includes this workflow; the deployed `fa49e872` instance does
not yet advertise it. Eight connected backend stories passed, including actual
RSA verification, encrypted storage without decrypting the old key, two shared
assignments, CAS/rollback/cache races, a fresh-process reopen and full-ASGI
authentication-before-body admission. Twenty focused UI groups and all thirteen
intercepted App/PAT browser groups passed, including desktop/mobile replacement,
private-draft clearing and manual recovery. The initial backend/browser attempts
found test-only header-casing, synthetic-token collision and collapsed-disclosure
assertions; those failures remain recorded. These checks did not contact GitHub,
run a stock SDK through Rust or deploy the feature. The later
[joined verification](operator-github-app-verification.md) passed at `7b253a11`:
all eighteen Node/Python/Go commands had expected outcomes, including key A to B
replacement through both assigned applications and nine scope/revocation denials.
That isolated synthetic-provider result does not establish real GitHub access
or deploy this capability to the running instance.

## Stock client recipe

Client setup generates the recipe from
[workspace_github.js](../serverware/operator_demo_web/workspace_github.js), using
Node.js **22.19 or newer**, **`@octokit/rest@22.0.1`** and **`undici@8.11.2`**.
It uses Octokit's normal request/pagination APIs and Undici `ProxyAgent` transport;
it does not install retry/throttling plugins or rewrite SDK requests in the client.

With either connection type, the application receives only the public GitHub dummy
`serverware-github-placeholder-v1`. Octokit sends
`Authorization: token serverware-github-placeholder-v1`; the proxy replaces that
exact value with the PAT or server-derived installation token after authorization. A missing or
different dummy is not permission to insert a credential.

Proxy authentication is separate: the public application ID is the Basic
username and the application's existing token is its password; retained
Bearer-only applications use their advertised Bearer mode. The recipe reads the
app token from `SERVERWARE_PROXY_TOKEN` and supplies it through the proxy-only
`token` option, never a credential-bearing URL or upstream header. Neither the
real GitHub token nor a literal application token appears in the displayed code.
The GitHub App private key, JWT and installation token must not be added to client
environment variables, configuration downloads or a GitHub Actions job. No SDK
App-authentication plugin or client-side token-renewal code is needed.

`proxyTls` verifies the outer HTTPS proxy using default trust or an explicitly
selected proxy CA. `requestTls` separately trusts the downloaded Serverware CA
for the intercepted destination. Do not disable certificate verification or
install a global TLS bypass. Private configuration download remains explicit and
requires the page to hold the matching one-time app token.

## Deliberate compatibility limits

This is GitHub REST issues/comments for the named repository, not full-provider
support: no GraphQL, git transport, edits, deletes, merges, Actions/workflow APIs
or unrelated routes. The App JWT/installation-token lifecycle is server-side
credential preparation, not an additional client API grant. A GitHub Actions
workflow may host the existing client, but that does not authorize workflow
management or other Actions operations. AWS and npm presets are not implemented
by this feature.

GET requests have no body; creation accepts bounded JSON up to 64 KiB. Supported
response JSON is preserved without field filtering, including provider errors:
up to 1 MiB for success and 64 KiB for errors, plus strictly empty HTTP 204.
Selected `Link`, `Retry-After`, request-ID and rate-limit headers are retained
under typed validation. Pagination links are checked and normalized onto the
already-authorized named repository; numeric repository URLs do not become an
additional client grant. Query values, status codes, headers and transport remain
bounded by [the protocol contract](../serverware/github_issues.py).

The signed GitHub-only `githubJsonUtf8V1` media policy admits JSON with an
optional single UTF-8 charset parameter. Other charsets, duplicate parameters,
quoted values and unrelated media types remain rejected; existing policies do
not acquire this exception implicitly.

Compression offers are discarded before forwarding; compressed responses,
streaming, redirects and arbitrary endpoints remain unsupported. Provider retry
metadata does not make an uncertain write safe to replay. A denial before
dispatch differs from a lost response after dispatch; issue/comment creation is
never automatically retried by the supplied recipe.

## GitHub App feature: verification checkpoint

On 2026-10-12, the retained-compatible demo branch passed 39 focused backend
tests: 13 provider-protocol checks, nine private-key boundary checks, six App
catalog checks, six existing PAT catalog checks and five actual encrypted-lease
checks. The API and lease fixtures use real SQLite custody, catalog publication,
request authentication, signing and X25519 envelope decryption, with synthetic
GitHub HTTP replies. They cover exact repository/permission binding, expiry,
automatic renewal, failure backoff, revocation and generation races. The private
key is not the dispatched credential. Protocol tests install a process-wide
network/subprocess refusal hook; run that suite separately from worker suites.

All 13 focused UI checks and seven App plus eight existing PAT rendered-browser
groups pass. Browser API responses are intercepted fixtures; those results do
not claim real GitHub authentication or SDK execution. Initial fixture mistakes
and one live-branch port guard-placement error were corrected before the final
successful runs. Test sources are under `scripts/test_github_app*.py` and
`scripts/test_operator_*github*.{py,cjs,mjs}`.

The earlier App-connection rollout used immutable source
`bf33afce290aba279033c4c1f78c486312516632`, deployed through the canonical workspace's
retained five-layer Compose configuration. Only the app source mount changed;
the accepted Rust binary remains
`7101d7e367ecaa398bf057a6cb12f24497670625dd0b0d4ca843f6a0ab6f4da6`.
Stopped-copy comparison preserved the schema, retained non-audit rows, CA and
custody, and all 472 audit records. Catalog revision 81, policy sequence 31 and
all 20 public rows in each resource collection remained unchanged.

A read-only browser check consumed actual deployed HTML and API responses via
the private authenticated relay: 11 GETs, desktop and 390-pixel layouts, both
GitHub credential choices, permission selectors and private-draft clearing passed
with no browser errors or resource mutations. Both external console URLs still
redirect unauthenticated users to SSO. This does not establish external SSO
completion, a saved real App or provider contact.

Private rollout receipts and preserved state live under
`serverware-operator-workspace-evidence/github-app-connection.Jenpesvt/`.
Real GitHub authentication and a real repository operation remain unverified.
A fresh [App-through-Rust SDK run](operator-github-app-verification.md) passed
at main `fa49e872`: Node/Python/Go reads across genuine expiry/renewal, all nine
scope/revocation denials, twelve distinct request/release audit pairs and clean
shutdown. The later canonical-instance cutover deployed `fa49e872` with normal
Rust `e94f2339`; see the [deployment record](../docker/serverware-operator-demo/README.md).
Neither check establishes real-provider use or resolves the public proxy's
outstanding DNS decision. Historical
SDK checkpoints below used a static-token fixture and remain separate evidence.

## Checked-in Node, Python and Go examples

Historical PAT/static-token checkpoint; not GitHub App lifecycle evidence:

On 2026-10-10, the actual entrypoints in `examples/github-issues-node`,
`examples/github-issues-python` and `examples/github-issues-go` passed through
the normal Rust proxy built from clean commit
`0b1fafe21d39ab98f4b4bef8674c2cae50e88726`. Its executable SHA-256 is
`a3d88673d40179864a52d3bd6902af7700fbe3562e8fbee423e3be73edc7ad10`.
This includes the exact stock Go issue-list Accept compatibility fix.

- Node 25.5.0 used Octokit 22.0.1 and Undici 8.11.2.
- Python 3.12.14 used PyGithub 2.10.0, Requests 2.34.2, urllib3 2.8.0 and
  certifi 2026.7.22. Its client-only combined CA bundle is not independently
  isolated outer/inner trust.
- The Go program was built with Go 1.23.12 and go-github/v74 74.0.0. Its
  executable SHA-256 is
  `28bec0ac7acc14475617f366e33de772e9b3780522cce1f40aef85748e9947f0`.

Each program completed two pages using the normal SDK, with genuine outer and
inner TLS verification, exact placeholder replacement and application proxy
authentication. The six provider requests and six released responses matched
their independently reconstructed canonical request/operation digests and six
distinct durable audit start/release pairs. Wrong-application and
wrong-repository attempts from each program produced six pre-dispatch denials.
No SDK request rewriting, real GitHub token or external provider contact was used.

The receiver ran on loopback inside an isolated network-none namespace. Runtime
inspection verified the executable digest, exact read-only source/client mounts,
shared private namespace and absence of host ports. The one-shot check passed
without retry. All six temporary containers were removed; cleanup reported no
errors and retained the fixture state and evidence. The run including startup
and cleanup took 70.492 seconds **after compilation**; this is not a native
pilot startup or cache-speed measurement.

Evidence is retained under
`serverware-operator-workspace-evidence/github-examples-acceptance.eZt0lZhl/`:
`build-result.json`, `run-inputs.json`, `selected-revision.json`,
`container-observations.json`, `checker-result.stdout.log`, and `terminal.json`.
The checker is [check_operator_github_examples.py](../scripts/check_operator_github_examples.py).
Cached dependencies were reused, not independently reproduced or fully
reinventoried. This engineering result is not production-release provenance.
GitHub Actions execution, actual provider permissions, deployed public routes
and the native hardware pilot still require their own acceptance.

## Earlier stock Octokit verification checkpoint

Recorded checkpoints (the earlier Python and browser suites were not rerun for
the Rust freshness fix):

- Six protocol tests, six catalog tests and 13 legacy key-replacement tests pass.
- The focused GitHub UI suite passes one pure group and eight intercepted-browser
  groups across 11 synthetic contexts. Selected existing Connect, proxy-login,
  Gmail-bundle and Google-reauthorization regressions also pass.
- On 2026-10-10, all 28 selected Rust checks passed against frozen source
  `5f06d3efb1bb5adcea70a0e82d9d76d900cd3005`: 18 existing GitHub/regression
  checks, two expiry checks and eight static-credential preparation checks.
  The separately built normal release binary has SHA-256
  `aafc1d1b9bb1d0730317a6420d12a073149f13b09ecaacc9434623a112bc3445`.
  This is a focused checkpoint, not a full-suite result.
- The same normal binary passed the complete network-isolated
  synthetic-provider fixture with stock Octokit `22.0.1`, Undici `8.11.2` and
  Node `25.5.0`: 11 provider attempts, nine released responses, two exact unsafe
  pagination-Link blocks and four denials before credential access. The checker
  verified canonical-v3 requests, raw query/body preservation, response/error
  metadata and distinct durable audit joins for all 11 attempts. This does not
  establish hidden-wire-header coverage.
- Independent review confirmed source/binary provenance across build,
  preparation, the running executable and checker receipts. Initial and
  running-checker isolation checks passed with loopback-only networking, no
  usable default route and no effective/permitted capabilities. The runner
  completed without retry, removed all six temporary containers and reported
  successful cleanup; a separate final check found no project containers or
  networks remaining. Synthetic evidence files were retained.
- Two earlier fixture runs failed: one during hostile-Link checks after nine
  legitimate requests, and another at the normal `rate_limit` operation. Their
  exact underlying errors were not retained. Source review identified and
  repaired a near-expiry cache availability issue before decision binding; the
  repaired build now passes the fixture, but that does not retrospectively
  establish the exact cause of either earlier failure.
- At `05fbe561`, bounded failure diagnostics were added and ten pure fixture
  groups passed. Expanded SDK failure diagnostics now pass all 14 pure fixture
  groups, including secret-safe output and exact refusal assertions. Separately, all
  11 stock endpoint-serialization cases passed with zero fetch calls. These
  offline checks do not prove proxy dispatch or response delivery.
- Source review found the generated recipe consistent with the fixture's stock
  client, dummy authentication and separate TLS trust configuration. The exact
  displayed snippet was not executed, and the SDK run exercised Basic proxy
  authentication, not the retained Bearer branch. Node `22.19` is the dependency
  minimum, not a runtime-tested version in this checkpoint.

Isolated runtime acceptance and pair-provenance review are complete for this
fixture. Deployment/public DNS and the intended real repository job still need
separate verification with authorized provider credentials. No real GitHub
request, AWS compatibility, npm compatibility or overall pilot completion is
claimed by this checkpoint.
