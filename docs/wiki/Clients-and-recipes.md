# Clients and recipes

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Getting started](https://github.com/AndrewMohawk/serverware/wiki/Getting-started) · [Proxy and CA](https://github.com/AndrewMohawk/serverware/wiki/Proxy-and-CA)

A **client** is your script, agent, CLI tool or CI job. It is not the provider account it uses.

- **Credentials** holds provider accounts and keys, such as a GitHub App, Google account or npm token.
- **Clients** creates a workload identity with its own expiring Serverware proxy token.
- **Permissions** connects a client to a credential for an explicit operation and scope.

A GitHub App ID is **not** `SERVERWARE_APP_ID`. The latter is the Serverware client's UUID. A client can use a saved GitHub App connection without receiving its private key, JWT or installation token.

## Set up one client

1. Save or connect the provider credential in **Credentials**. Saving it alone grants no access.
2. Choose **Set up access**, select that credential, then select or create a client. Use a distinct client per independently managed workload.
3. The maintained SDK/CLI examples below need standard proxy login using HTTP Basic on CONNECT. New guided clients already receive compatible standard login; for a retained Bearer-only client, use **Clients → Enable standard client login**. This explicitly enables Basic alongside Bearer; it does not rotate the token.
4. Save the one-time proxy token privately. “One-time” means it is displayed once, not that it authorizes only one request. It remains subject to its expiry and permissions.
5. Select the advertised provider preset and exact scope: repository, package, username, chain or connected account. Review and save the permission.
6. Confirm the destination is operator-approved and the saved policy has loaded. A credential, permission or green policy status alone does not prove a provider request succeeded.
7. Open **Proxy setup**, select this client and permission, and download the interception CA. Verify it through your trusted operator channel. Use the proxy URL, not the workspace URL.
8. Prepare the chosen example's dependencies **before supplying the client token**, then run its reviewed entrypoint and inspect **Audit log**.

Presets and copied recipes are capability-gated. If the matching control is unavailable, do not replace it with a broad generic grant or disable verification. See [Permissions and policies](https://github.com/AndrewMohawk/serverware/wiki/Permissions-and-policies).

## Inputs the client receives

| Input | Meaning |
| --- | --- |
| `SERVERWARE_PROXY_URL` | Approved HTTPS proxy origin; no embedded username/password, path or query. |
| `SERVERWARE_APP_ID` | Serverware client UUID; retained API/environment naming uses “app”. |
| `SERVERWARE_PROXY_TOKEN` | That client's private proxy token, never a provider token. |
| `SERVERWARE_CA_FILE` | Local trusted interception CA PEM path. |
| `SERVERWARE_PROXY_CA_FILE` | Separate outer-proxy CA only when the selected example supports it and the proxy needs it. |
| Provider selectors | Exact nonsecret scope matching the permission, such as owner/repository or chain. |

After preparing dependencies, a Bash session can read the token without placing a literal in shell history:

```bash
export SERVERWARE_PROXY_URL='https://your-approved-proxy.example:443'
export SERVERWARE_APP_ID='your-saved-client-uuid'
export SERVERWARE_CA_FILE='/absolute/path/serverware-ca.pem'
read -r -s -p 'Serverware client token: ' SERVERWARE_PROXY_TOKEN
echo
export SERVERWARE_PROXY_TOKEN
```

Replace the public placeholders with your deployment's values. Disable shell tracing and HTTP/SDK debug logging. Environment and process memory still contain the client token; use a trusted workstation or protected runner. Run `unset SERVERWARE_PROXY_TOKEN` when finished.

The `.env.example` files document inputs; the examples do not automatically load them. **Download private client config** is available only while the page holds the matching one-time token. That JSON contains the client token and is not an executable. The GitHub and Gmail examples accept their matching downloads explicitly with `--config` as shown below; other examples still use their documented inputs. Keep it out of source control, chat and logs.

## Optional renewal for a long-running workload

Manual token rotation remains the default. The deployed ordinary instance offers **Clients → Managed workload renewal**, but no existing client is implicitly enrolled. Renewal requires an administrator's explicit Ed25519 public-key enrollment: a **1–90 day grant** and **1–24 hour tokens**, never beyond the grant's deadline. It changes neither permissions nor provider credentials.

1. Use a separate client and private helper directory for each workload or replica; do not share a renewal owner across workers.
2. Follow the [managed-client README's initialization instructions](https://github.com/AndrewMohawk/serverware/blob/main/examples/managed-client/README.md#enroll-once). The helper generates its private key locally and prints only the public key. Keep the private key on the workload host; never paste it into Serverware.
3. Save any displayed one-time client token privately before enrollment clears it from the page. In **Clients → Managed workload renewal**, select the existing client, paste only the public key, choose both lifetimes, review the consent and choose **Enroll workload public key**. Enrollment does not issue a token; it can shorten the existing token's expiry to the grant deadline.
4. Wait for the matching saved policy to load, then choose **Download public setup JSON**. This contains public identifiers, fingerprint and timing—not a private key or proxy token. Follow the same README's `configure` instructions using that setup and the separately saved token.
5. Follow the README's [worker instructions](https://github.com/AndrewMohawk/serverware/blob/main/examples/managed-client/README.md#run-a-worker) for the actual run commands and CA setup. A saved enrollment or setup download does not prove a renewal or provider request succeeded.

The helper must regularly obtain a current token and replace SDK connection pools when its generation changes. The previous token has **at most five minutes of overlap**, ending sooner at its original expiry. Renewal cannot extend its own enrollment. Cancellation, enrollment replacement or manual rotation invalidates the old renewal authority and overlap; see [Operations and maintenance](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance#manage-workload-renewal).

The normal proxy passed isolated synthetic-provider checks with stock Requests 2.31.0, and the shipped helper's default HTTPS transport separately passed with its locked Requests 2.34.2 graph. That run recovered a saved pending operation from its reopened journal without a second issuance, then joined two provider calls to audit. The deployed GET-only UI check also passed. An explicitly enrolled deployed workload and a real provider job still need acceptance. See the [project tracker](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md#default-managed-helper-https--isolated-connected-acceptance); do not interpret this recipe as real-provider verification.

## Node.js, Python and Go: read GitHub issues

Start with **GitHub issues: read** for one exact repository. Either a saved PAT or a verified GitHub App connection can supply the provider credential. Python and Go are read-only; Node also has explicit issue/comment creation commands.

### Use the downloaded settings

After preparing the chosen example's dependencies (and building the Go binary), choose **Download private client config** in Proxy setup. This requires standard username/password proxy login and the matching one-time client token still held by the page. Save the downloaded CA next to `serverware-client.private.json` when the CA field is `./serverware-ca.pem`, then protect the JSON with `chmod 600 /path/serverware-client.private.json`.

Run one of these commands from its example directory:

```bash
node client.mjs --config /path/serverware-client.private.json
python issues.py --config /path/serverware-client.private.json
./github-issues --config /path/serverware-client.private.json
```

These commands read issues. The file supplies the exact repository, proxy, client login and CA paths without retyping environment variables. Relative CA paths resolve beside the JSON file, not the working directory. File settings override ambient connection/repository variables, and an expired token or incompatible profile is refused before a provider request. The file does not select an executable or trigger a write. Existing environment-only commands remain supported; Node writes still require an explicit operation and locally supplied content. PyGithub retains its combined-trust limitation and rejects a separate outer-proxy CA.

### Use environment variables instead

Set `SERVERWARE_GITHUB_OWNER` and `SERVERWARE_GITHUB_REPO` to the saved permission's exact values. From the repository checkout, prepare **one** example before injecting the token:

```bash
# Node.js: use the runtime supported by this example's README.
cd examples/github-issues-node
npm ci --ignore-scripts --no-audit --no-fund
```

With the common inputs and repository selectors set, run `node client.mjs list`. See the [Node recipe](https://github.com/AndrewMohawk/serverware/tree/main/examples/github-issues-node).

```bash
# Python: create a dedicated environment from this example directory.
cd examples/github-issues-python
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Then run `.venv/bin/python -B issues.py --limit 100`. This recipe rejects `SERVERWARE_PROXY_CA_FILE`, even when empty: its outer proxy must be certifi-trusted. It uses a combined client CA bundle and puts proxy userinfo only in an isolated child's environment. Read the [Python transport tradeoffs](https://github.com/AndrewMohawk/serverware/blob/main/examples/github-issues-python/README.md) before choosing it.

```bash
# Go: use the toolchain required by this example's README/go.mod.
cd examples/github-issues-go
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go build -o github-issues-example .
```

Then run `./github-issues-example`. It prints counts rather than issue contents. See the [Go recipe](https://github.com/AndrewMohawk/serverware/tree/main/examples/github-issues-go).

Each `cd` block above starts from the repository root; they are alternatives, not one sequential script. Node/Python results can include issue titles: treat private-repository output as private data.

The SDK receives only the fixed public GitHub dummy. Serverware substitutes the authorized provider credential. `GITHUB_TOKEN` and `GH_TOKEN` are not the Serverware login. Running this job does not grant git, GraphQL or Actions-management access.

## Other maintained SDK jobs

Use the selected directory's README, dependency pins and `.env.example`; do not transplant a different SDK's proxy settings.

For Gmail, prepare one example, then download the private config and CA for the
saved **Official Gmail SDK** permission. From that example's directory, run one:

```bash
node client.mjs --config /path/serverware-client.private.json
.venv/bin/python -I -B gmail.py --config /path/serverware-client.private.json
./gmail-example --config /path/serverware-client.private.json
```

No manual environment setup is needed. Relative CA paths resolve beside the
JSON, and expired or mismatched configurations are refused. These examples read
an inbox sample; the file never selects a command or supplies a Google token.
Keep the JSON private, for example with `chmod 600`.

| Job and required permission | Node.js | Python | Go |
| --- | --- | --- | --- |
| Gmail inbox sample — **Read Gmail → Official Gmail SDK** | [client.mjs](https://github.com/AndrewMohawk/serverware/tree/main/examples/google-gmail-node) | [gmail.py](https://github.com/AndrewMohawk/serverware/tree/main/examples/google-gmail-python) | [gmail-example](https://github.com/AndrewMohawk/serverware/tree/main/examples/google-gmail-go) |
| Alchemy chain status — exact mainnet or Sepolia chain | [client.mjs](https://github.com/AndrewMohawk/serverware/tree/main/examples/alchemy-chain-status-node) | [chain_status.py](https://github.com/AndrewMohawk/serverware/tree/main/examples/alchemy-chain-status-python) | [Go RPC client](https://github.com/AndrewMohawk/serverware/tree/main/examples/alchemy-chain-status-go) |
| X app-only username lookup — exact lowercase username | [client.mjs](https://github.com/AndrewMohawk/serverware/tree/main/examples/x-username-node) | [username.py](https://github.com/AndrewMohawk/serverware/tree/main/examples/x-username-python) | [Go client](https://github.com/AndrewMohawk/serverware/tree/main/examples/x-username-go) |
| X text posting — explicit connected-user posting permission | [client.mjs](https://github.com/AndrewMohawk/serverware/tree/main/examples/x-post-node) | [post.py](https://github.com/AndrewMohawk/serverware/tree/main/examples/x-post-python) | [Go client](https://github.com/AndrewMohawk/serverware/tree/main/examples/x-post-go) |

- **Gmail:** connect the account first; use the SDK preset's exact dummy and ordered-query mode, not automatic header insertion. Choose the SDK language in Proxy setup. The job lists a bounded inbox sample and reads metadata, not bodies or attachments. Python uses the generated Google SDK with a Requests transport adapter; it does not claim unchanged `httplib2` HTTPS-proxy support.
- **Alchemy:** set `SERVERWARE_ALCHEMY_CHAIN=eth-mainnet` or `eth-sepolia`. The job reads `eth_chainId` then `eth_blockNumber` at the keyless `/v2` endpoint. No wallets, transactions or arbitrary RPC. Node uses Viem with an explicit Undici HTTPS proxy transport; the environment and permission stay the same. The current Node/Python/Go recipes passed [isolated proxy/TLS verification](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-alchemy-verification.md#current-sdk-through-proxy-acceptance), including credential replacement, audit, denial and revocation controls. Your real provider entitlement and deployed job still need verification.
- **X lookup:** set `SERVERWARE_X_USERNAME` to the permitted `[a-z0-9_]{1,15}` name without `@`. This uses an app-only credential and does not authorize posting.
- **X posting:** set reviewed `SERVERWARE_X_POST_TEXT` and deliberately set `SERVERWARE_X_POST_CONFIRM=post-once`, then invoke the selected entrypoint once. It can create a real post. A timeout, withheld response or other post-dispatch failure is an **unknown outcome**, not permission to replay. An advertised shared daily limit counts posting attempts, not guaranteed successes.

Public DNS, verified TLS and authenticated external access to a synthetic route, followed by revocation and denial, have [passed separately](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-public-proxy-verification.md#authenticated-synthetic-route-acceptance-passed). That routing result does not establish real-provider SDK jobs or OAuth consent/entitlement. Those still require separate acceptance, and older isolated results do not transfer automatically to changed SDK versions. Consult the [completion record](https://github.com/AndrewMohawk/serverware/blob/main/docs/project-completion.md) for evidence boundaries.

## CLI: curl and npm

For a custom HTTP request, use **Proxy setup → Copy connection template** for the exact saved permission. It supplies the method, URL, allowed headers, proxy login and CA settings for that permission; do not start from an arbitrary `curl` command and add a real provider token.

1. Select the intended client and permission, and enter the downloaded CA path.
2. Supply the client's saved proxy token privately, then review the generated command before running it in a trusted shell.
3. Keep certificate verification enabled. Do not add `-k`, proxy bypasses or redirect following to work around a denial.
4. Check the response and the corresponding audit outcome. For writes, a lost response is not proof that the operation did not happen.

The maintained [template builder](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/app.js) is the source of the curl recipe. Shell expansion may place its token-bearing options in process arguments; do not use it on a host where process inspection is untrusted.

For npm, use the [stock npm/pacote launcher](https://github.com/AndrewMohawk/serverware/tree/main/examples/npm-registry), not your personal `.npmrc`:

```bash
# Prepare without the Serverware token, from the repository root.
cd examples/npm-registry
npm ci --ignore-scripts --no-audit --no-fund
# After configuring the client and exact package permission:
node client.mjs view
node client.mjs manifest
```

Set `SERVERWARE_NPM_PACKAGE`; `manifest` also needs `SERVERWARE_NPM_VERSION`. These commands read metadata only. Preparing this launcher’s dependencies is separate from its proxied job.

**Install packages and run npm audit** is a different capability-gated permission: authorize every required package, including transitive dependencies. Set `SERVERWARE_NPM_PROJECT` to a reviewed source and `SERVERWARE_NPM_OUTPUT` to a new directory, then use `node client.mjs install`. For `node client.mjs ci`, supply a reviewed v3 lock and another new output directory. Scripts stay disabled, default audit stays enabled, and output remains for inspection after failure.

**Publish package** is a real write. Follow the [publication recipe](https://github.com/AndrewMohawk/serverware/blob/main/examples/npm-registry/README.md#explicit-public-publication): exact package/version/tag, reviewed tarball and SHA-256, and `SERVERWARE_NPM_PUBLISH_CONFIRM=publish-publicly`. Publishing is never the default; never automatically retry an uncertain publication.

## GitHub Actions

Four reviewed **inactive samples** are available: [GitHub issues](https://github.com/AndrewMohawk/serverware/blob/main/examples/github-issues-node/workflow.example.yml), [npm metadata](https://github.com/AndrewMohawk/serverware/blob/main/examples/npm-registry/workflow.example.yml), [Alchemy reads](https://github.com/AndrewMohawk/serverware/blob/main/examples/alchemy-chain-status-node/workflow.example.yml), and [X username lookup](https://github.com/AndrewMohawk/serverware/blob/main/examples/x-username-node/workflow.example.yml).

1. Keep the corresponding example directory and lock in your repository. Review the sample, then deliberately copy it into `.github/workflows/`.
2. Create a protected GitHub environment, restrict it to trusted default-branch runs, and control who may approve access. The samples call it `serverware-demo`; that is a legacy **GitHub environment name**, not a separate Serverware mode. Rename it consistently if desired.
3. Set environment secrets `SERVERWARE_PROXY_TOKEN`, `SERVERWARE_CA_PEM`, and optional `SERVERWARE_PROXY_CA_PEM` where supported. Obtain CA material from your trusted operator. Never add provider keys, refresh tokens or GitHub App private keys.
4. Set the sample's variables: proxy URL, client UUID and exact provider selectors. Ensure the proxy is reachable from the runner and the client token remains valid.
5. Run manually on the trusted default branch. Dependency installation receives no Serverware token; only the final bounded read step receives the client configuration.

The samples do not publish, post, rotate tokens or manage GitHub Actions through the proxy. Their `contents: read` permission is for repository checkout, not the target provider API. They are not evidence of a successful hosted workflow or public-provider job.

## Agents, scheduled scripts and existing applications

Use the same workload model: create a client for the agent/job, grant only its required operations, and inject only that client's proxy token and trusted CA inputs. Run the maintained example entrypoint as a tool when it matches the task. Do not put provider secrets or the client token into prompts, tool output or conversation history.

For a different application, first identify its documented proxy, proxy-authentication and TLS hooks. Setting `HTTPS_PROXY` alone is **not** a general SDK integration guarantee. The examples use explicit per-client transport configuration; some launch isolated children. npm and PyGithub also document combined-CA tradeoffs rather than independent trust stores. Never weaken TLS or rewrite SDK requests to force a preset match.

Use finite job deadlines and inspect audit records on failure. Do not automatically retry writes, post unknown outcomes, or interpret a blocked response as proof of no upstream effect. Client-token expiry is separate from provider-token refresh. Manually managed clients need explicit rotation and a workload-secret update; long-running workers can instead use the optional finite enrollment above. Revoke unused permissions or clients. See [Operations and maintenance](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance).

AWS credential storage is not an ECR publication recipe, and ordinary approval-dependent jobs are not enabled by these examples. For unavailable capabilities or denials, use [Troubleshooting](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting) and the [capability matrix](https://github.com/AndrewMohawk/serverware/wiki/Capability-matrix-and-glossary); do not substitute broader authority.
