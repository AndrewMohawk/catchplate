# Clients and recipes

[Home](Home.md) · [Getting started](Getting-started.md) · [Proxy and CA](Proxy-and-CA.md)

A **client** is your script, agent, CLI tool or CI job. It is not the provider account it uses.

- **Credentials** holds provider accounts and keys, such as a GitHub App, Google account or npm token.
- **Clients** creates a workload identity with its own expiring Catchplate proxy token.
- **Permissions** connects a client to a credential for an explicit operation and scope.

A GitHub App ID is **not** `CATCHPLATE_APP_ID`. The latter is the Catchplate client's UUID. A client can use a saved GitHub App connection without receiving its private key, JWT or installation token.

## Set up one client

1. Save or connect the provider credential in **Credentials**. Saving it alone grants no access.
2. Choose **Set up access**, select that credential, then select or create a client. Use a distinct client per independently managed workload.
3. The maintained SDK/CLI examples below need standard proxy login using HTTP Basic on CONNECT. New guided clients already receive compatible standard login; for a retained Bearer-only client, use **Clients → Enable standard client login**. This explicitly enables Basic alongside Bearer; it does not rotate the token.
4. Save the one-time proxy token privately. “One-time” means it is displayed once, not that it authorizes only one request. It remains subject to its expiry and permissions.
5. Select the advertised provider preset and exact scope: repository, package, username, chain or connected account. Review and save the permission.
6. Confirm the destination is operator-approved and the saved policy has loaded. A credential, permission or green policy status alone does not prove a provider request succeeded.
7. Open **Proxy setup**, select this client and permission, and download the interception CA. Verify it through your trusted operator channel. Use the proxy URL, not the workspace URL.
8. Prepare the chosen example's dependencies **before supplying the client token**, then run its reviewed entrypoint and inspect **Audit log**.

Presets and copied recipes are capability-gated. If the matching control is unavailable, do not replace it with a broad generic grant or disable verification. See [Permissions and policies](Permissions-and-policies.md).

## Inputs the client receives

The GitHub, Gmail, npm, Alchemy and X examples accept the matching **Download
private client config** file with `--config PATH`. Prepare dependencies first,
then keep the downloaded JSON and CA together. Relative CA paths resolve beside
the JSON. This avoids retyping the connection values below; environment-only
setup remains an alternative. The file contains the client token, not a provider
credential, and never selects a write operation or supplies posting/publishing
confirmation.

| Input | Meaning |
| --- | --- |
| `CATCHPLATE_PROXY_URL` | Approved HTTPS proxy origin; no embedded username/password, path or query. |
| `CATCHPLATE_APP_ID` | Catchplate client UUID; retained API/environment naming uses “app”. |
| `CATCHPLATE_PROXY_TOKEN` | That client's private proxy token, never a provider token. |
| `CATCHPLATE_CA_FILE` | Local trusted interception CA PEM path. |
| `CATCHPLATE_PROXY_CA_FILE` | Separate outer-proxy CA only when the selected example supports it and the proxy needs it. |
| Provider selectors | Exact nonsecret scope matching the permission, such as owner/repository or chain. |

After preparing dependencies, a Bash session can read the token without placing a literal in shell history:

```bash
export CATCHPLATE_PROXY_URL='https://your-approved-proxy.example:443'
export CATCHPLATE_APP_ID='your-saved-client-uuid'
export CATCHPLATE_CA_FILE='/absolute/path/catchplate-ca.pem'
read -r -s -p 'Catchplate client token: ' CATCHPLATE_PROXY_TOKEN
echo
export CATCHPLATE_PROXY_TOKEN
```

Replace the public placeholders with your deployment's values. Disable shell tracing and HTTP/SDK debug logging. Environment and process memory still contain the client token; use a trusted workstation or protected runner. Run `unset CATCHPLATE_PROXY_TOKEN` when finished.

The `.env.example` files document inputs; the examples do not automatically load them. **Download private client config** is available only while the page holds the matching one-time token, so download it before dismissing the token or reloading. That JSON is not an executable. Keep it out of source control, chat and logs.

## Connect an MCP-capable agent

Use the [local MCP server and setup guide](https://github.com/AndrewMohawk/catchplate/blob/main/examples/mcp/README.md)
with downloaded private client configurations. It is a stdio server launched by
your MCP client, not a new hosted URL or an administrator API. Give the agent a
dedicated Catchplate client and only the permissions it needs; provider secrets
remain in Catchplate.

The three tools are `list_operations`, `read_operation` and `perform_action`.
Discovery returns the configured operations and argument schemas without a
provider call. Actions require an operator's startup `--allow-actions` opt-in
for that configuration alias and literal `confirmed: true` on the call.
This confirmation is not human approval: a permission requiring host review
still stops with HTTP 428. Review it in Catchplate, then explicitly request the
identical retry. Never automatically replay an uncertain action.

The adapter supports the common-app presets and selected GitHub, Gmail, Alchemy,
X and npm metadata operations. It does not offer arbitrary HTTP requests,
credential administration, AWS/ECR or npm publication. The setup guide lists
exact support, optional Node dependencies and limits. Keep private configuration
files out of model prompts and logs. Hosted MCP delivery remains future work.

## Optional renewal for a long-running workload

Manual token rotation remains the default. The deployed ordinary instance offers **Clients → Managed workload renewal**, but no existing client is implicitly enrolled. Renewal requires an administrator's explicit Ed25519 public-key enrollment: a **1–90 day grant** and **1–24 hour tokens**, never beyond the grant's deadline. It changes neither permissions nor provider credentials.

1. Use a separate client and private helper directory for each workload or replica; do not share a renewal owner across workers.
2. Follow the [managed-client README's initialization instructions](https://github.com/AndrewMohawk/catchplate/blob/main/examples/managed-client/README.md#enroll-once). The helper generates its private key locally and prints only the public key. Keep the private key on the workload host; never paste it into Catchplate.
3. Save any displayed one-time client token privately before enrollment clears it from the page. In **Clients → Managed workload renewal**, select the existing client, paste only the public key, choose both lifetimes, review the consent and choose **Enroll workload public key**. Enrollment does not issue a token; it can shorten the existing token's expiry to the grant deadline.
4. Wait for the matching saved policy to load, then choose **Download public setup JSON**. This contains public identifiers, fingerprint and timing—not a private key or proxy token. Follow the same README's `configure` instructions using that setup and the separately saved token.
5. Follow the README's [worker instructions](https://github.com/AndrewMohawk/catchplate/blob/main/examples/managed-client/README.md#run-a-worker) for the actual run commands and CA setup. A saved enrollment or setup download does not prove a renewal or provider request succeeded.

The helper must regularly obtain a current token and replace SDK connection pools when its generation changes. The previous token has **at most five minutes of overlap**, ending sooner at its original expiry. Renewal cannot extend its own enrollment. Cancellation, enrollment replacement or manual rotation invalidates the old renewal authority and overlap; see [Operations and maintenance](Operations-and-maintenance.md#manage-workload-renewal).

The normal proxy passed isolated synthetic-provider checks with stock Requests 2.31.0, and the shipped helper's default HTTPS transport separately passed with its locked Requests 2.34.2 graph. That run recovered a saved pending operation from its reopened journal without a second issuance, then joined two provider calls to audit. The deployed GET-only UI check also passed. An explicitly enrolled deployed workload and a real provider job still need acceptance. See the [project tracker](https://github.com/AndrewMohawk/catchplate/blob/main/docs/project-completion.md#default-managed-helper-https--isolated-connected-acceptance); do not interpret this recipe as real-provider verification.

## Node.js, Python and Go: read GitHub issues

Start with **GitHub issues: read** for one exact repository. Either a saved PAT or a verified GitHub App connection can supply the provider credential. Python and Go are read-only; Node also has explicit issue/comment creation commands.

### Use the downloaded settings

After preparing the chosen example's dependencies (and building the Go binary), choose **Download private client config** in Proxy setup. This requires standard username/password proxy login and the matching one-time client token still held by the page. Save the downloaded CA next to `catchplate-client.private.json` when the CA field is `./catchplate-ca.pem`, then protect the JSON with `chmod 600 /path/catchplate-client.private.json`.

Run one of these commands from its example directory:

```bash
node client.mjs --config /path/catchplate-client.private.json
python issues.py --config /path/catchplate-client.private.json
./github-issues --config /path/catchplate-client.private.json
```

These commands read issues. The file supplies the exact repository, proxy, client login and CA paths without retyping environment variables. Relative CA paths resolve beside the JSON file, not the working directory. File settings override ambient connection/repository variables, and an expired token or incompatible profile is refused before a provider request. The file does not select an executable or trigger a write. Existing environment-only commands remain supported; Node writes still require an explicit operation and locally supplied content. PyGithub retains its combined-trust limitation and rejects a separate outer-proxy CA.

### Use environment variables instead

Set `CATCHPLATE_GITHUB_OWNER` and `CATCHPLATE_GITHUB_REPO` to the saved permission's exact values. From the repository checkout, prepare **one** example before injecting the token:

```bash
# Node.js: use the runtime supported by this example's README.
cd examples/github-issues-node
npm ci --ignore-scripts --no-audit --no-fund
```

With the common inputs and repository selectors set, run `node client.mjs list`. See the [Node recipe](https://github.com/AndrewMohawk/catchplate/tree/main/examples/github-issues-node).

```bash
# Python: create a dedicated environment from this example directory.
cd examples/github-issues-python
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Then run `.venv/bin/python -B issues.py --limit 100`. This recipe rejects `CATCHPLATE_PROXY_CA_FILE`, even when empty: its outer proxy must be certifi-trusted. It uses a combined client CA bundle and puts proxy userinfo only in an isolated child's environment. Read the [Python transport tradeoffs](https://github.com/AndrewMohawk/catchplate/blob/main/examples/github-issues-python/README.md) before choosing it.

```bash
# Go: use the toolchain required by this example's README/go.mod.
cd examples/github-issues-go
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go build -o github-issues-example .
```

Then run `./github-issues-example`. It prints counts rather than issue contents. See the [Go recipe](https://github.com/AndrewMohawk/catchplate/tree/main/examples/github-issues-go).

Each `cd` block above starts from the repository root; they are alternatives, not one sequential script. Node/Python results can include issue titles: treat private-repository output as private data.

The SDK receives only the fixed public GitHub dummy. Catchplate substitutes the authorized provider credential. `GITHUB_TOKEN` and `GH_TOKEN` are not the Catchplate login. Running this job does not grant git, GraphQL or Actions-management access.

## Other maintained SDK jobs

Use the selected directory's README, dependency pins and `.env.example`; do not transplant a different SDK's proxy settings.

For Gmail, prepare one example, then download the private config and CA for the
saved **Official Gmail SDK** permission. From that example's directory, run one:

```bash
node client.mjs --config /path/catchplate-client.private.json
.venv/bin/python -I -B gmail.py --config /path/catchplate-client.private.json
./gmail-example --config /path/catchplate-client.private.json
```

No manual environment setup is needed. Relative CA paths resolve beside the
JSON, and expired or mismatched configurations are refused. These examples read
an inbox sample; the file never selects a command or supplies a Google token.
Keep the JSON private, for example with `chmod 600`.

Gmail's default remains **All mail — no age restriction**. If the instance
offers the optional 1–3650-day limit, choose it on the permission and download
that permission's complete configuration; the Node, Python and Go SDK recipes
carry the saved age policy without requiring you to rebuild it by hand. They
use five-message pages and an explicit `after:<epoch-seconds>` convenience query
held constant across page tokens. The query is not proof: the proxy checks
Gmail `internalDate`, permits at most 32 messages per restricted list and blocks
the whole page if evidence fails. Editing the file does not change the proxy's
saved restriction.
This mode passed connected synthetic acceptance and is deployed with passing
public/browser checks. Google remains unconfigured, so real-Google use is still
unverified. See the
[Gmail age guide](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-gmail-job-verification.md#optional-last-n-days-policy--connected-acceptance-passed-and-deployed).

| Job and required permission | Node.js | Python | Go |
| --- | --- | --- | --- |
| Gmail inbox sample — **Read Gmail → Official Gmail SDK** | [client.mjs](https://github.com/AndrewMohawk/catchplate/tree/main/examples/google-gmail-node) | [gmail.py](https://github.com/AndrewMohawk/catchplate/tree/main/examples/google-gmail-python) | [gmail-example](https://github.com/AndrewMohawk/catchplate/tree/main/examples/google-gmail-go) |
| Alchemy chain status — exact mainnet or Sepolia chain | [client.mjs](https://github.com/AndrewMohawk/catchplate/tree/main/examples/alchemy-chain-status-node) | [chain_status.py](https://github.com/AndrewMohawk/catchplate/tree/main/examples/alchemy-chain-status-python) | [Go RPC client](https://github.com/AndrewMohawk/catchplate/tree/main/examples/alchemy-chain-status-go) |
| X app-only username lookup — exact lowercase username | [client.mjs](https://github.com/AndrewMohawk/catchplate/tree/main/examples/x-username-node) | [username.py](https://github.com/AndrewMohawk/catchplate/tree/main/examples/x-username-python) | [Go client](https://github.com/AndrewMohawk/catchplate/tree/main/examples/x-username-go) |
| X text posting — explicit connected-user posting permission | [client.mjs](https://github.com/AndrewMohawk/catchplate/tree/main/examples/x-post-node) | [post.py](https://github.com/AndrewMohawk/catchplate/tree/main/examples/x-post-python) | [Go client](https://github.com/AndrewMohawk/catchplate/tree/main/examples/x-post-go) |

- **Gmail:** connect the account first; use the SDK preset's exact dummy and ordered-query mode, not automatic header insertion. Choose the SDK language in Proxy setup. The job lists a bounded inbox sample and reads metadata, not bodies or attachments. Python uses the generated Google SDK with a Requests transport adapter; it does not claim unchanged `httplib2` HTTPS-proxy support.
- **Alchemy:** the downloaded config supplies the saved chain; alternatively set `CATCHPLATE_ALCHEMY_CHAIN=eth-mainnet` or `eth-sepolia`. The job reads `eth_chainId` then `eth_blockNumber` at the keyless `/v2` endpoint. No wallets, transactions or arbitrary RPC. Node uses Viem with an explicit Undici HTTPS proxy transport; the environment and permission stay the same. The current Node/Python/Go recipes passed [isolated proxy/TLS verification](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-alchemy-verification.md#current-sdk-through-proxy-acceptance), including credential replacement, audit, denial and revocation controls. Your real provider entitlement and deployed job still need verification.
- **X lookup:** the downloaded config supplies the saved username; alternatively set `CATCHPLATE_X_USERNAME` to the permitted `[a-z0-9_]{1,15}` name without `@`. This uses an app-only credential and does not authorize posting.
- **X posting:** set reviewed `CATCHPLATE_X_POST_TEXT` and deliberately set `CATCHPLATE_X_POST_CONFIRM=post-once`, then invoke the selected entrypoint once. It can create a real post. A timeout, withheld response or other post-dispatch failure is an **unknown outcome**, not permission to replay. An advertised shared daily limit counts posting attempts, not guaranteed successes.

For Alchemy and either X job, add `--config ./catchplate-client.private.json`
to the prepared example's normal command: `node client.mjs`,
`python3 -I chain_status.py` / `username.py` / `post.py`, or `go run .`.
The X posting text and confirmation must still be supplied locally, never in
the JSON. Follow each README for the supported runtime and exact preparation.

Public DNS, verified TLS and authenticated external access to a synthetic route, followed by revocation and denial, have [passed separately](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-public-proxy-verification.md#authenticated-synthetic-route-acceptance-passed). That routing result does not establish real-provider SDK jobs or OAuth consent/entitlement. Those still require separate acceptance, and older isolated results do not transfer automatically to changed SDK versions. Consult the [completion record](https://github.com/AndrewMohawk/catchplate/blob/main/docs/project-completion.md) for evidence boundaries.

## CLI: curl and npm

For a custom HTTP request, use **Proxy setup → Copy connection template** for the exact saved permission. It supplies the method, URL, allowed headers, proxy login and CA settings for that permission; do not start from an arbitrary `curl` command and add a real provider token.

1. Select the intended client and permission, and enter the downloaded CA path.
2. Supply the client's saved proxy token privately, then review the generated command before running it in a trusted shell.
3. Keep certificate verification enabled. Do not add `-k`, proxy bypasses or redirect following to work around a denial.
4. Check the response and the corresponding audit outcome. For writes, a lost response is not proof that the operation did not happen.

The maintained [template builder](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/app.js) is the source of the curl recipe. Shell expansion may place its token-bearing options in process arguments; do not use it on a host where process inspection is untrusted.

For npm, use the [stock npm/pacote launcher](https://github.com/AndrewMohawk/catchplate/tree/main/examples/npm-registry), not your personal `.npmrc`:

```bash
# Prepare without the Catchplate token, from the repository root.
cd examples/npm-registry
npm ci --ignore-scripts --no-audit --no-fund
# After configuring the client and exact package permission:
node client.mjs --config ./catchplate-client.private.json
# Explicit version required locally for this second command:
node client.mjs --config ./catchplate-client.private.json manifest
```

For metadata/publish permissions, the file supplies the selected package;
`manifest` also needs local `CATCHPLATE_NPM_VERSION`. Environment-only use remains
supported by omitting `--config` and setting `CATCHPLATE_NPM_PACKAGE` and the
connection variables. These commands read metadata only. Preparing this
launcher's dependencies is separate from its proxied job. Explicit `install`,
`ci` and `publish` commands also accept `--config`, but their local inputs and
confirmation below remain required.

**Install packages and run npm audit** is a different capability-gated permission: authorize every required package, including transitive dependencies. Set `CATCHPLATE_NPM_PROJECT` to a reviewed source and `CATCHPLATE_NPM_OUTPUT` to a new directory, then use `node client.mjs install`. For `node client.mjs ci`, supply a reviewed v3 lock and another new output directory. Scripts stay disabled, default audit stays enabled, and output remains for inspection after failure.

**Publish package** is a real write. Follow the [publication recipe](https://github.com/AndrewMohawk/catchplate/blob/main/examples/npm-registry/README.md#explicit-public-publication): exact package/version/tag, reviewed tarball and SHA-256, and `CATCHPLATE_NPM_PUBLISH_CONFIRM=publish-publicly`. Publishing is never the default; never automatically retry an uncertain publication.

## GitHub Actions

Six reviewed **inactive samples** are available: [GitHub issues](https://github.com/AndrewMohawk/catchplate/blob/main/examples/github-issues-node/workflow.example.yml), [npm metadata](https://github.com/AndrewMohawk/catchplate/blob/main/examples/npm-registry/workflow.example.yml), [Alchemy reads](https://github.com/AndrewMohawk/catchplate/blob/main/examples/alchemy-chain-status-node/workflow.example.yml), [X username lookup](https://github.com/AndrewMohawk/catchplate/blob/main/examples/x-username-node/workflow.example.yml), [Gmail reads](https://github.com/AndrewMohawk/catchplate/blob/main/examples/google-gmail-node/workflow.example.yml), and [a common-app GET](https://github.com/AndrewMohawk/catchplate/blob/main/examples/common-apps/github-actions.yml).

For each sample:

1. Keep the corresponding example directory and lock in your repository. Review the sample, then deliberately copy it into `.github/workflows/`.
2. Create a protected GitHub environment, restrict it to trusted default-branch runs, and control who may approve access. The samples call it `catchplate-demo`; that is a legacy **GitHub environment name**, not a separate Catchplate mode. Rename it consistently if desired.
3. For GitHub, Alchemy, X username, Gmail and the common-app GET, supply the complete private download as `CATCHPLATE_CLIENT_CONFIG_JSON`, plus `CATCHPLATE_CA_PEM` and optional `CATCHPLATE_PROXY_CA_PEM`. Their connection and exact selectors come from the downloaded permission, not separately retyped variables. Obtain CA material from your trusted operator; never add provider keys, refresh tokens or GitHub App private keys.
4. The npm sample retains its documented `CATCHPLATE_PROXY_TOKEN`, CA secrets and proxy/client/package variables; follow that sample's instructions rather than mixing the two configuration formats. For every sample, the proxy must be reachable from the runner and the client token unexpired. GitHub requires the read-only `github_issues_read_v1` download, not its write-enabled bundle.
5. Run manually on the trusted default branch. Dependency installation receives no Catchplate token; only the final bounded read step receives the client configuration.

The common-app sample uses Ubuntu 24.04's Python 3.12 and the checked-in
`examples/common-apps/request.py` and `requirements.txt`. Supply the complete
GET-only private download as `CATCHPLATE_CLIENT_CONFIG_JSON`, plus
`CATCHPLATE_CA_PEM` and optional `CATCHPLATE_PROXY_CA_PEM`; no per-selector
variable mapping is needed. The client login must be unexpired and the proxy
reachable from the runner. Dispatch manually on the trusted default branch.
It refuses POST permissions, withholds provider responses from logs and removes
its private temporary files. See the [common-app workflow setup](https://github.com/AndrewMohawk/catchplate/blob/main/examples/common-apps/README.md#github-actions-one-manual-read).

The samples do not publish, post, rotate tokens or manage GitHub Actions through the proxy. Their `contents: read` permission is for repository checkout, not the target provider API. They are not evidence of a successful hosted workflow or public-provider job.

## Common apps and AI providers

The [common-app recipes](https://github.com/AndrewMohawk/catchplate/blob/main/examples/common-apps/README.md)
cover the guided OpenAI, Anthropic, Gemini, OpenRouter, Slack, Discord, Notion,
Stripe, Resend, GitLab, Cloudflare and Sentry presets. The service example uses
ordinary Python HTTP requests; the AI example uses the actual provider SDKs.
The separate `services_python.py` recipe uses standard Slack, Stripe and
Cloudflare Python SDKs plus the maintained third-party Notion client. It reads
one explicit page or sends one explicitly confirmed Slack message; it does not
auto-paginate or retry. New Cloudflare permissions support its SDK metadata
headers; legacy permissions retain their original authority and Requests recipe.
Use the supplied public dummy credentials, approved request shapes and explicit
proxy/CA configuration, never the real provider secret.

Read the [operation and compatibility guide](https://github.com/AndrewMohawk/catchplate/blob/main/docs/common-apps.md)
before choosing an SDK. These are non-streaming, bounded JSON permissions, not
unrestricted native-client compatibility. A full Slack/Discord bot, arbitrary
Notion traversal, Stripe payments, AI tools/files and automatic header-based
pagination are outside these recipes. Provider writes and AI calls that may
incur charges require an explicit deliberate run; do not replay uncertain
outcomes automatically.

## AWS ECR publication

The [Boto3 example](https://github.com/AndrewMohawk/catchplate/blob/main/examples/ecr-publish-python/README.md)
provides a narrow workflow: save AWS credentials in Catchplate,
grant one client/account/standard-region/repository/tag permission, stage verified
image bytes, review that exact image, then explicitly activate its publication
UUID and publish with `--execute-write`. Only one ECR permission per client and
region is allowed. This is five ECR API actions ending in `PutImage`, not Docker
push, an image build or arbitrary AWS access. The private client download carries
only Catchplate login/scope/trust settings, never AWS keys.

The normal `a69503f8` / `ffe0fbe4…` build and connected stock-Boto3 check passed:
all five actions, eight signed requests and matching ACK/audit records in
62.391 seconds, with no automatic retries. This used a synthetic provider;
the `15ef645c` UI follow-up is deployed with the same proxy, existing
destinations/permissions unchanged and no automatically enabled AWS access.
Public/read-only browser checks passed, not human SSO, notification delivery or
real AWS. Review is host-trusted, not TEE or
YubiKey enforcement. The original 30-minute deadline is clipped to client/AWS
expiry; never automatically replay an uncertain upload. Explicit **Retire staged
files** reclaims a retained slot for eligible terminal publications, preserving
AWS images and audit/history; uncertain or possible-send outcomes cannot be
retired. The four stage slots remain bounded, while retained history now has
ten-record pages rather than a 1,024-publication lifetime stop. ECR review alerts
and audit events use the existing independently configured Slack/webhook slots;
no slot is enabled automatically and live delivery remains unverified. The local
MCP delivery excludes ECR. Read the [current ECR guide](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-ecr-publication.md)
for commands, retained limits and the exact source-versus-live boundary.

## Agents, scheduled scripts and existing applications

Use the same workload model: create a client for the agent/job, grant only its required operations, and inject only that client's proxy token and trusted CA inputs. Run the maintained example entrypoint as a tool when it matches the task. Do not put provider secrets or the client token into prompts, tool output or conversation history.

For a different application, first identify its documented proxy, proxy-authentication and TLS hooks. Setting `HTTPS_PROXY` alone is **not** a general SDK integration guarantee. The examples use explicit per-client transport configuration; some launch isolated children. npm and PyGithub also document combined-CA tradeoffs rather than independent trust stores. Never weaken TLS or rewrite SDK requests to force a preset match.

Use finite job deadlines and inspect audit records on failure. Do not automatically retry writes, post unknown outcomes, or interpret a blocked response as proof of no upstream effect. Client-token expiry is separate from provider-token refresh. Manually managed clients need explicit rotation and a workload-secret update; long-running workers can instead use the optional finite enrollment above. Revoke unused permissions or clients. See [Operations and maintenance](Operations-and-maintenance.md).

Saving AWS credentials alone is not publication permission; the deployed ECR capability still needs its exact approved regional destination, client permission and image review. For unavailable capabilities or denials, use [Troubleshooting](Troubleshooting.md) and the [capability matrix](Capability-matrix-and-glossary.md); do not substitute broader authority.
