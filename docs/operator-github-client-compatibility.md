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

Recorded for this source slice:

- Six protocol tests, six catalog tests and 13 legacy key-replacement tests pass.
- The focused GitHub UI suite passes one pure group and eight intercepted-browser
  groups across 11 synthetic contexts. Selected existing Connect, proxy-login,
  Gmail-bundle and Google-reauthorization regressions also pass.
- Acceptance of the 18 focused Rust cases and the isolated stock-SDK → normal
  proxy → synthetic-provider job is still pending. Browser fixtures do not prove
  those paths, deployment, real GitHub permission validity or provider behavior.

Complete that runtime acceptance and pair-provenance review before deployment;
then separately verify the intended real repository job with authorized provider
credentials. No real GitHub request, AWS compatibility or npm compatibility is
claimed by this checkpoint.
