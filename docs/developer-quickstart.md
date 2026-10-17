# Use the access your operator gave you

You need a private Catchplate client configuration, its verified public CA,
and the name of the permitted job. You do **not** need a provider API key,
administrator access, a proxy build, a pilot or a verification ceremony.
If you do not yet have access, send your operator to
[first-client setup](wiki/Getting-started.md).

During the [Catchplate rename](catchplate-rename.md), keep existing downloaded
configurations unchanged and use the matching client release. New source names
do not migrate saved permissions, placeholder headers or MCP launch paths;
compatibility and the retained-instance cutover are not yet verified.
For supported ordinary exports, follow the scoped
[local migration guide](../examples/client-config-migration.md); unsupported
signed/managed/ECR/custom configurations need a new operator handoff.

The JSON contains your expiring Catchplate login. Keep it out of Git, chat,
prompts and logs. Keep the CA beside it when `ca_file` is
`./catchplate-ca.pem`; relative CA paths start beside the JSON, not your shell.
An optional outer-proxy CA is a separate trust input. Never disable TLS checks.

## 1. Prepare one example, once

Use the repository checkout containing these examples. Choose only the example
for your permission, and install dependencies **before** supplying its private
configuration or exporting a client token. Subsequent runs reuse the environment;
they do not need another install or build.

For a common-app HTTP permission, from the repository root:

```sh
cd examples/common-apps
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Other maintained choices:

| Your job | Example and preparation |
| --- | --- |
| GitHub issues | [Node/Octokit](../examples/github-issues-node/README.md), [Python/PyGithub](../examples/github-issues-python/README.md), or [Go/go-github](../examples/github-issues-go/README.md). PAT and GitHub App connections use the same client config. |
| Gmail inbox sample | Official [Node](../examples/google-gmail-node/README.md), [Python](../examples/google-gmail-python/README.md), or [Go](../examples/google-gmail-go/README.md) SDK; saved age restrictions are preserved. |
| npm metadata, install/ci or publication | [Stock npm example](../examples/npm-registry/README.md); Node **25.5.0** and its checked-in lock are required. These are separate permission types. |
| Alchemy chain status | [Node](../examples/alchemy-chain-status-node/README.md), [Python](../examples/alchemy-chain-status-python/README.md), or [Go](../examples/alchemy-chain-status-go/README.md); only the two permitted reads. |
| X username or text posting | [Username lookup](../examples/x-username-node/README.md) and [text posting](../examples/x-post-node/README.md) each have Node/Python/Go projects. A lookup permission cannot post. |
| Slack, Notion, Stripe or Cloudflare | [Python service SDKs](../examples/common-apps/README.md#standard-service-sdks), using `.venv-services`. Retained Cloudflare permissions may support HTTP only. |
| OpenAI, Anthropic, Gemini or OpenRouter | [Provider AI SDKs](../examples/common-apps/README.md#official-ai-sdks), using `.venv-ai`; sending requires explicit `--send`. |
| Other common-app presets | [Requests example](../examples/common-apps/README.md), using `.venv`. It implements supported operations, not arbitrary provider APIs. |
| AWS ECR image publication | [Boto3 example](../examples/ecr-publish-python/README.md): stage, review, explicitly publish. It is not Docker push. |

In **Proxy setup → Run a prepared example**, choose a language/runtime to see
one exact project directory, preparation command and run command. Gmail has its
own **Gmail SDK language** selector. Run Python through the displayed virtual
environment, not an unrelated system Python.

For Go, download modules and build **once before providing credentials**. The
prepared-binary handoff uses these names:

| Project directory | One-time build, after `GOTOOLCHAIN=local go mod download` |
| --- | --- |
| `examples/github-issues-go` | `GOTOOLCHAIN=local go build -o github-issues .` |
| `examples/google-gmail-go` | `GOTOOLCHAIN=local go build -o gmail-example .` |
| `examples/alchemy-chain-status-go` | `GOTOOLCHAIN=local go build -o chain-status-example .` |
| `examples/x-username-go` | `GOTOOLCHAIN=local go build -o x-username-example .` |
| `examples/x-post-go` | `GOTOOLCHAIN=local go build -o x-post-example .` |

Use Go 1.25 or newer for Gmail/Alchemy, 1.23 or newer for the other projects.
Run the resulting binary with `--config PATH`; do not use `go run` for each job.
No Catchplate service or Rust build is required.

## 2. Check your files, then run one read

Keep the private download outside the checkout when practical and restrict its
permissions, for example `chmod 600 /private/catchplate-client.private.json`.
Do not paste the JSON into your shell or rename a provider key as a client token.

From the prepared common-app example directory:

```sh
.venv/bin/python request.py --config /private/catchplate-client.private.json --check-config
```

This checks the local JSON, token expiry, pinned dependencies, CA files and
configured query. It sends **nothing**: no DNS, proxy or provider request. A
`configuration_ready` result does not verify destination approval, policy
activation, provider credentials or network reachability. Other example families
have their own loaders; this checker is for common-app configurations only.

If your permission is a read, run it deliberately:

```sh
.venv/bin/python request.py --config /private/catchplate-client.private.json
```

Or run your selected SDK's displayed command with the same `--config` path.
The complete download supplies the connection and exact scope: no separate
proxy/app/provider-selector variables need retyping. `.env.example` files are
reference material, not automatically loaded settings.

Inspect the result and the matching Catchplate audit outcome. For errors:

- **Nothing was sent:** fix the named local config, dependency, CA or query
  problem. An expired client token needs a current operator-issued config.
- **HTTP 428 / approval required:** open the validated review link. After human
  approval, explicitly repeat the identical request before its deadline.
- **Failure after a write attempt:** its outcome can be unknown. Check the
  provider and audit log before deciding whether another attempt is safe.

Writes always need their example's separate deliberate inputs and confirmation.
Installing dependencies, downloading a config, selecting a recipe or approving
a request does not execute it. The examples do not retry uncertain writes.

## 3. Move the same access to an agent or CI job

For an MCP-capable agent, follow the [local MCP guide](../examples/mcp/README.md).
Its local `--check` validates configured permissions, and
`--print-client-config` produces a copyable launch entry using your actual
interpreter and config paths. It exposes operations, not administrator access.
Actions are off unless explicitly enabled; no hosted MCP URL is required.

For GitHub Actions, use the reviewed **inactive** sample linked from your
example. The config-based samples use `CATCHPLATE_CLIENT_CONFIG_JSON`,
`CATCHPLATE_CA_PEM` and optional `CATCHPLATE_PROXY_CA_PEM`; use the exact sample's
instructions. Only the final read step receives the private configuration.
Review it before copying to `.github/workflows/`, dispatch manually on the trusted
default branch, and ensure the proxy is reachable and the login unexpired.
No provider secret belongs in the workflow. See [CI recipes](wiki/Clients-and-recipes.md#github-actions).

Long-running workloads can use separately enrolled
[managed renewal](../examples/managed-client/README.md). It is optional and does
not happen merely because an SDK, MCP server or CI workflow was installed.
