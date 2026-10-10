# GitHub issues through Serverware: Node.js

A runnable, read-only-by-default project using ordinary `@octokit/rest` **22.0.1**
and Undici **8.11.2**. It lists issues, following pagination for one explicitly
configured repository. Optional commands create one issue or one comment.

The transport follows the existing Serverware Octokit fixture and generated
client recipe. This example's mocked and real-SDK offline tests are **not evidence
of a successful request to public GitHub**. There are no provider requests in the
tests, and no active workflow is installed by this directory.

## 1. Configure Serverware

In the operator UI:

1. Add a **GitHub token** credential. The real GitHub token stays in Serverware;
   never put it in this project or the workflow.
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

Application-token expiry/revocation and the provider token's own permissions
still apply. The client does not configure the proxy, save credentials, renew
tokens, change policy or perform hardware approval.

## 2. Install and configure the client

Use Node.js 22.19 or newer; the underlying pinned fixture used Node.js 25.5.0.
From this directory:

```sh
npm ci --ignore-scripts --no-audit --no-fund
```

This explicit installation downloads the versions in the checked-in
`package-lock.json`, without running dependency lifecycle scripts. Review the
lock before use and deliberately review updates. The client itself does not
install anything.

Set these environment variables using your shell or secret manager:

| Variable | Value |
| --- | --- |
| `SERVERWARE_PROXY_URL` | HTTPS proxy origin, including its port if needed; no URL credentials/path/query |
| `SERVERWARE_APP_ID` | Saved application's UUID |
| `SERVERWARE_PROXY_TOKEN` | Saved application's token, **not a GitHub token** |
| `SERVERWARE_CA_FILE` | Local trusted Serverware interception CA PEM file |
| `SERVERWARE_PROXY_CA_FILE` | Optional separate CA PEM for the outer HTTPS proxy; absent uses Node's normal trust |
| `SERVERWARE_GITHUB_OWNER` | Exact owner from the saved permission |
| `SERVERWARE_GITHUB_REPO` | Exact repository name from the saved permission |

Do not set `NODE_TLS_REJECT_UNAUTHORIZED=0`. Both TLS hops always verify the peer.
CA files, `.env` files and `node_modules` are ignored by this example's Git rules;
they are not credentials to copy into source control. The CA is supplied as an
explicit trusted input, not fetched over an unverified connection.

Octokit receives only the fixed public value
`serverware-github-placeholder-v1`. Serverware replaces it after authorization.
`GITHUB_TOKEN` and `GH_TOKEN` are not read. Proxy identity comes only from the
listed environment variables, not URL userinfo or ambient proxy settings.

## 3. Run a read

```sh
node client.mjs
# Equivalent: npm start -- list
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

For exactly one new issue, supply `SERVERWARE_ISSUE_TITLE` and a nonempty
`SERVERWARE_ISSUE_BODY`, then run:

```sh
node client.mjs create-issue
```

For exactly one comment on an existing issue, supply `SERVERWARE_ISSUE_NUMBER`
and a nonempty `SERVERWARE_COMMENT_BODY`, then run:

```sh
node client.mjs create-comment
```

Content comes from environment variables so it is not required in command-line
arguments. Bodies are bounded and the serialized JSON must fit 64 KiB. No issue
is automatically created as a prerequisite for a comment. There are no edit,
delete, repository-management or arbitrary-request commands.

There are **no automatic retries**. After a lost response or an uncertain
creation result, inspect GitHub and Serverware audit records before deciding
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
separate TLS trust, fixed dummy authentication, request bounds and redacted
failures. They do not prove real Octokit serialization, TLS, proxy forwarding or
GitHub success; those require a separately authorized integration run.

All eight mocked test groups passed locally on 2026-10-10. That result alone is
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
or GitHub Actions execution is claimed.

## GitHub Actions sample

`workflow.example.yml` is deliberately inactive. Review it before placing a copy
under `.github/workflows/` in your own repository, keeping this project at
`examples/github-issues-node/` with its checked-in `package-lock.json`.

It uses a normal **GitHub-hosted `ubuntu-24.04` runner**: checkout, install Node.js
**25.5.0**, run `npm ci --ignore-scripts --no-audit --no-fund`, then read the selected
repository. No preprovisioned runner or dependency directory is required. The
install step has no Serverware token or CA inputs; only the final client step
receives them. Package caching is disabled, and checkout does not persist its
repository credential.

Create the protected GitHub environment `serverware-demo`, allow only your
trusted default branch, and restrict who may approve/run it. Configure:

- Environment secrets: `SERVERWARE_PROXY_TOKEN`, `SERVERWARE_CA_PEM`, and
  optionally `SERVERWARE_PROXY_CA_PEM`. The PEM inputs must come from your trusted
  proxy operator; they are not blindly downloaded during the workflow.
- Variables: `SERVERWARE_PROXY_URL`, `SERVERWARE_APP_ID`,
  `SERVERWARE_GITHUB_OWNER`, `SERVERWARE_GITHUB_REPO`.

Use **Actions → Run workflow** on that default branch. There are no pull-request
triggers, user-supplied workflow inputs or arbitrary checkout refs; the job also
checks the selected branch before running. Review changes to this workflow,
client and dependency lock before approving access to the environment. The
proxy must be reachable by GitHub-hosted runners, and the app token must still
be valid. This sample does not bypass network restrictions or renew tokens.

The workflow performs **only a read**. Its `contents: read` permission is for
checking out the example, not authentication to the target GitHub repository;
the client uses the Serverware application token and fixed public GitHub dummy.
Do not add a real GitHub provider token to the workflow. The job has a five-minute
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
