# GitHub issues through Catchplate: Node.js

A runnable, read-only-by-default project using ordinary `@octokit/rest` **22.0.1**
and Undici **8.11.2**. It lists issues, following pagination for one explicitly
configured repository. Optional commands create one issue or one comment.

The transport follows the existing Catchplate Octokit fixture and generated
client recipe. This example's mocked and real-SDK offline tests are **not evidence
of a successful request to public GitHub**. There are no provider requests in the
tests, and no active workflow is installed by this directory.

## 1. Install the client dependencies

Use Node.js 22.19 or newer; the underlying pinned fixture used Node.js 25.5.0.
From this directory, install dependencies **before creating an application token
or downloading its private configuration**, so installation does not consume the
token's lifetime:

```sh
npm ci --ignore-scripts --no-audit --no-fund
```

This explicit installation downloads the versions in the checked-in
`package-lock.json`, without dependency lifecycle scripts. Review the lock before
use and deliberately review updates. The client itself does not install anything.

## 2. Configure Catchplate

In the operator UI:

For GitHub App setup, the operator must first allow `https://api.github.com`.
**Save and verify GitHub App** contacts GitHub to verify the App, installation
and exact repository and obtain a scoped token before saving. PAT storage alone
does not verify the token and is permitted while that upstream is disabled;
granting or using either connection still requires the enabled upstream.

1. Choose **GitHub**, then **personal access token (PAT)** or **GitHub App**.
   For a PAT, save a connection name and token. For an App, save its App ID,
   private-key PEM, exact repository owner/name and Issues
   access (`read`, or `write` for the creation commands). The App must already
   be installed for that repository with the required permission. Catchplate
   discovers and verifies its installation ID during the existing repository
   lookup; the optional advanced installation-ID override must match exactly.
   Saved connections and renewals keep that verified ID pinned. Provider
   credentials stay in Catchplate, never in this project or the workflow.
2. Create an application with **Basic and Bearer** proxy authentication and keep
   its application ID and token. This example uses Basic CONNECT authentication.
3. Grant that application **Read issues and comments** for one exact owner and
   repository, using the saved credential. For creation commands, explicitly
   grant **Read and create issues/comments** instead.
4. Confirm `https://api.github.com` is an operator-allowed upstream. Saving a
   credential or application alone does not grant access.
5. Download the proxy CA through the authenticated operator UI. Verify its
   identity with the proxy operator before trusting it. If the HTTPS proxy itself
   uses a private CA, obtain that separate outer CA too.

Application-token expiry/revocation and the provider's own permissions still
apply. Catchplate stores the App private key encrypted and automatically obtains
and renews its short-lived installation tokens; PATs are not automatically
renewed. The App's exact repository/Issues ceiling does not replace the separate
application grant. A GitHub App installation is not GitHub OAuth user login, and
its App ID is not `CATCHPLATE_APP_ID`.

App token reuse requires a 65-second expiry margin. A mint failure is not retried
in the same call; only a later separately authorized lease after a 60-second
backoff may attempt fresh authentication. This never retries a repository write.

Both choices use the unchanged SDK, public dummy and proxy-token inputs below.
Do not give Octokit the App private key, a JWT or an installation token. The client
does not configure the proxy, save credentials, renew tokens, change policy or
perform hardware approval. The new App flow is **not yet verified against real GitHub**; its [synthetic verification is recorded separately](../../docs/operator-github-client-compatibility.md#github-app-feature-verification-checkpoint).

## 3. Download and use the client configuration

Select the application's GitHub permission in **Client setup**, then download
the private client JSON and the proxy CA. Keep them outside your checkout, for
example together in a private directory. The JSON contains the **Catchplate
application token**, not the GitHub provider credential. Do not commit or share it.

```sh
chmod 600 /path/catchplate-client.private.json
node client.mjs --config /path/catchplate-client.private.json
# Equivalent explicit read:
node client.mjs --config /path/catchplate-client.private.json list
```

Put the downloaded CA at the JSON's `ca_file` path (normally
`./catchplate-ca.pem`). Relative CA paths are resolved against the JSON file's
directory, not the shell's working directory. If supplied, the separate outer
proxy CA in `client_recipe.proxy_ca_file` follows the same rule. Verify CA identity
with the operator before trusting it.

The file must be a regular JSON file no larger than 64 KiB, with an unexpired
token, Basic proxy identity, and matching GitHub permission/repository/upstream.
Its connection and repository settings override ambient connection settings;
an absent outer proxy CA uses normal Node trust, even if an old environment
variable names a CA. The JSON is data, not a script: commands, entrypoints,
environment objects, provider credentials and write content are never imported.

### Environment-only alternative

Set these environment variables using your shell or secret manager:

| Variable | Value |
| --- | --- |
| `CATCHPLATE_PROXY_URL` | HTTPS proxy origin, including its port if needed; no URL credentials/path/query |
| `CATCHPLATE_APP_ID` | Saved application's UUID |
| `CATCHPLATE_PROXY_TOKEN` | Saved application's token, **not a GitHub token** |
| `CATCHPLATE_CA_FILE` | Local trusted Catchplate interception CA PEM file |
| `CATCHPLATE_PROXY_CA_FILE` | Optional separate CA PEM for the outer HTTPS proxy; absent uses Node's normal trust |
| `CATCHPLATE_GITHUB_OWNER` | Exact owner from the saved permission |
| `CATCHPLATE_GITHUB_REPO` | Exact repository name from the saved permission |

Do not set `NODE_TLS_REJECT_UNAUTHORIZED=0`. Both TLS hops always verify the peer.
CA files, `.env` files and `node_modules` are ignored by this example's Git rules;
they are not credentials to copy into source control. The CA is supplied as an
explicit trusted input, not fetched over an unverified connection.

Octokit receives only the fixed public value
`catchplate-github-placeholder-v1`. Catchplate replaces it after authorization.
`GITHUB_TOKEN` and `GH_TOKEN` are not read. Proxy identity comes only from the
downloaded configuration or listed environment variables, not URL userinfo or
ambient proxy settings.

## 4. Run a read

```sh
node client.mjs --config /path/catchplate-client.private.json
# With the environment-only alternative:
node client.mjs list
```

Output is JSON containing the returned issue numbers and titles. GitHub's issue
listing may include pull requests. Treat titles from private repositories as
private data when choosing where to retain logs.

The normal Octokit `paginate()` helper is used, without retry or throttling
plugins and without modifying request headers, bodies, query strings or Link
values. Transport configuration supplies the explicit proxy and rejects
redirects. The example refuses another origin/repository and bounds the entire
run to 20 requests / 90 seconds; hitting a limit fails rather than silently
claiming a complete list. These are example limits, not a proxy latency SLA.

## Optional: an intentional write

These commands affect the configured repository if its saved write permission
allows them. Do not execute them merely to test connectivity.

For exactly one new issue, supply `CATCHPLATE_ISSUE_TITLE` and a nonempty
`CATCHPLATE_ISSUE_BODY`, then run:

```sh
node client.mjs create-issue
# Or use a downloaded write-enabled permission:
node client.mjs --config /path/catchplate-client.private.json create-issue
```

For exactly one comment on an existing issue, supply `CATCHPLATE_ISSUE_NUMBER`
and a nonempty `CATCHPLATE_COMMENT_BODY`, then run:

```sh
node client.mjs create-comment
# Or use a downloaded write-enabled permission:
node client.mjs --config /path/catchplate-client.private.json create-comment
```

Content comes from environment variables so it is not required in command-line
arguments or imported from the JSON. A read-only configuration rejects either
write command. Bodies are bounded and the serialized JSON must fit 64 KiB. No issue
is automatically created as a prerequisite for a comment. There are no edit,
delete, repository-management or arbitrary-request commands.

There are **no automatic retries**. After a lost response or an uncertain
creation result, inspect GitHub and Catchplate audit records before deciding
whether to submit again. Errors print only a fixed message and an optional HTTP
status; raw Octokit errors can contain sensitive request details and are not
logged.

## No-network tests

```sh
node --test client.test.mjs
```

The tests use Node's built-in test runner and mocked SDK/transport objects. They
need neither installed third-party packages nor credentials, and cover exact
repository selection, pagination-helper invocation, explicit write inputs,
downloaded-config validation and CLI selection, separate TLS trust, fixed dummy authentication, request bounds and redacted
failures. They do not prove real Octokit serialization, TLS, proxy forwarding or
GitHub success; those require a separately authorized integration run.

The original eight mocked test groups passed locally on 2026-10-10. That result alone is
not proxy integration evidence.

After installing the checked-in dependencies, run the separate real-SDK checks:

```sh
node --test client.sdk.test.mjs
```

On 2026-10-10, all **4 top-level groups and 17 nested controls (21 test nodes)**
passed with pinned Octokit 22.0.1. These execute the public `createClient` and
`perform` entrypoints with real SDK pagination and issue/comment serializers.
They check exact inner URLs, headers and dummy authorization, proxy-identity
separation, invalid pagination targets and errors without SDK retries. Fetch
returns synthetic `Response` objects and `ProxyAgent` is an inert configuration
stub; no actual TLS, proxy forwarding or GitHub request is established.

The later 2026-10-10 [actual-entrypoint acceptance](../../docs/operator-github-client-compatibility.md#checked-in-node-python-and-go-examples)
passed this program through the normal Rust proxy with verified TLS and a
synthetic GitHub service: two-page reads succeeded, and wrong-application and
wrong-repository requests were denied before dispatch. No real GitHub request
or GitHub Actions execution is claimed. This historical static-token fixture
does not verify GitHub App installation authentication or token renewal.

## GitHub Actions sample

`workflow.example.yml` is deliberately inactive. Review it before placing a copy
under `.github/workflows/` in your own repository, keeping this project at
`examples/github-issues-node/` with its checked-in `package-lock.json`.

It uses a normal **GitHub-hosted `ubuntu-24.04` runner**: checkout, install Node.js
**25.5.0**, run `npm ci --ignore-scripts --no-audit --no-fund`, then read the selected
repository. No preprovisioned runner or dependency directory is required. The
install step has no Catchplate token or CA inputs; only the final client step
receives them. Package caching is disabled, and checkout does not persist its
repository credential.

Create the protected GitHub environment `catchplate-demo`, allow only your
trusted default branch, and restrict who may approve/run it. Configure:

- Environment secrets: `CATCHPLATE_PROXY_TOKEN`, `CATCHPLATE_CA_PEM`, and
  optionally `CATCHPLATE_PROXY_CA_PEM`. The PEM inputs must come from your trusted
  proxy operator; they are not blindly downloaded during the workflow.
- Variables: `CATCHPLATE_PROXY_URL`, `CATCHPLATE_APP_ID`,
  `CATCHPLATE_GITHUB_OWNER`, `CATCHPLATE_GITHUB_REPO`.

Use **Actions → Run workflow** on that default branch. There are no pull-request
triggers, user-supplied workflow inputs or arbitrary checkout refs; the job also
checks the selected branch before running. Review changes to this workflow,
client and dependency lock before approving access to the environment. The
proxy must be reachable by GitHub-hosted runners, and the app token must still
be valid. This sample does not bypass network restrictions or renew tokens.

The workflow performs **only a read**. Its `contents: read` permission is for
checking out the example, not authentication to the target GitHub repository;
the client uses the Catchplate application token and fixed public GitHub dummy.
Do not add a real GitHub provider token, App private key, JWT or installation
token to the workflow. Running this issues client in Actions does not grant
access to Actions/workflow management APIs. The job has a five-minute
deadline; the read step is limited to two minutes and its client process to
100 seconds. It creates a private temporary CA directory and removes only its
two named PEM files and that directory on exit. Logs can contain returned issue
titles, so apply appropriate Actions log access and retention.

The action pins were checked against their official release commits on
2026-10-10:

- [`actions/checkout` v7.0.1](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1)
- [`actions/setup-node` v7.1.0](https://github.com/actions/setup-node/commit/949feb2413d6458794dcd2491c4babbbce0c15c1)

This hosted workflow has not been executed as acceptance evidence. A successful
run would prove only the requests it actually performed, not general GitHub,
provider-token or hardware support.

References: [Octokit REST client](https://github.com/octokit/rest.js),
[GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
and the project's [GitHub compatibility scope](../../docs/operator-github-client-compatibility.md).
