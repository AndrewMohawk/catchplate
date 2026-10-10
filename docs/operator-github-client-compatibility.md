# GitHub issues: implemented client contract and acceptance boundary

The operator-workspace feature at `7ee40d18` implements a reusable GitHub token
connection and two named-repository permissions. This document describes that
source contract, not a deployed GitHub integration or a successful real-provider
request. Runtime acceptance remains incomplete as recorded below.

## Operator journey

In **Connect an app**, choose **GitHub token**, save a name and personal access
token, select or create an application, then enter the repository owner/name and
choose:

- **Read issues and comments**: list and read issues/comments, including supported
  pagination.
- **Read and create issues/comments**: those reads plus issue/comment creation.

Review the exact repository and permission before granting access. No manual
method, path, request-field or response-field lists are required. The repository
name is reviewed authority, not a verified discovery result; the provider token
must already have the necessary repository permissions. Saving it does not test
its validity, and Serverware does not renew it. Existing generic Bearer keys and
saved rules are not automatically converted to GitHub permissions.

The deployment must advertise the exact GitHub capability and allow
`https://api.github.com` in its retained `allowed_upstreams`. A token may be saved
while that destination is disabled, but no GitHub permission can be granted or
used through client setup. The capability describes co-versioned source support;
it does not negotiate or prove the running gate version. Wait for the exact saved
policy to be loaded by the accepted app/gate pair.

## Stock client recipe

Client setup generates the recipe from
[workspace_github.js](../serverware/operator_demo_web/workspace_github.js), using
Node.js **22.19 or newer**, **`@octokit/rest@22.0.1`** and **`undici@8.11.2`**.
It uses Octokit's normal request/pagination APIs and Undici `ProxyAgent` transport;
it does not install retry/throttling plugins or rewrite SDK requests in the client.

The application receives only the public GitHub dummy
`serverware-github-placeholder-v1`. Octokit sends
`Authorization: token serverware-github-placeholder-v1`; the proxy replaces that
exact value with the stored provider credential after authorization. A missing or
different dummy is not permission to insert a credential.

Proxy authentication is separate: the public application ID is the Basic
username and the application's existing token is its password; retained
Bearer-only applications use their advertised Bearer mode. The recipe reads the
app token from `SERVERWARE_PROXY_TOKEN` and supplies it through the proxy-only
`token` option, never a credential-bearing URL or upstream header. Neither the
real GitHub token nor a literal application token appears in the displayed code.

`proxyTls` verifies the outer HTTPS proxy using default trust or an explicitly
selected proxy CA. `requestTls` separately trusts the downloaded Serverware CA
for the intercepted destination. Do not disable certificate verification or
install a global TLS bypass. Private configuration download remains explicit and
requires the page to hold the matching one-time app token.

## Deliberate compatibility limits

This is GitHub REST issues/comments for the named repository, not full-provider
support: no GraphQL, git transport, GitHub App installation/JWT/token lifecycle,
edits, deletes, merges or unrelated APIs. AWS and npm presets are not implemented
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

## Verification checkpoint

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
