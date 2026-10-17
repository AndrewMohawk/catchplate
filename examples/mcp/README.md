> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Use Catchplate from an MCP client

This local **stdio MCP server** lets an agent use selected Catchplate permissions
without receiving provider credentials. It uses the same HTTPS proxy, client
identity, policies, approval workflow and audit trail as an ordinary application.
It does not administer Catchplate, create permissions, export keys or expose a
hosted MCP URL.

## Set up

Existing private downloads and MCP launch settings from before the rename need
the [explicit local migration](../client-config-migration.md). Tokens are not
automatically changed or renewed.

1. In Catchplate, save a credential and create a client permission for one of
   the supported operations below. Use a dedicated client for the agent.
2. Download its private client configuration and public CA. Keep them together;
   relative CA paths resolve beside the configuration. The configuration contains
   an expiring **Catchplate client token**, not a provider key. Keep it out of Git,
   prompts and logs. Restrict its file permissions, for example with `chmod 600`.
3. From the repository root, install the pinned local runtime once:

   ```sh
   python3.12 -m venv examples/mcp/.venv
   examples/mcp/.venv/bin/pip install -r examples/mcp/requirements.lock
   ```

4. Generate your MCP client's launch configuration. This validates the downloaded
   file locally without contacting a provider or starting MCP:

   ```sh
   examples/mcp/.venv/bin/python -I examples/mcp/server.py \
     --config 'issues=./private files/github-client.json' \
     --console-origin https://catchplate.example.com \
     --print-client-config
   ```

5. Copy the printed `mcpServers.catchplate` entry into your MCP client's settings.
   Clients that accept an `mcpServers` object can use the whole output. Other
   clients need its `command` and `args` fields in their server configuration.
   Interpreter, script and configuration paths are made absolute for you; spaces
   are preserved as separate arguments. The output contains local paths and any
   explicit action opt-ins/console origin—not the downloaded token or contents.

Use `--check` instead when you only want a validation summary. Omitting both
flags starts the normal stdio server. `--print-client-config` does not install
anything or modify your MCP client's settings.

Repeat `--config alias=./private-file.json` before printing for additional permissions, up to
32 configurations and 128 discovered operations. Aliases are local names: a lowercase letter followed by up
to 47 lowercase letters, digits, underscores or hyphens. Discovery reads the
current files and returns operation names, accepted arguments and scope, never
the private login. Expired or unsupported configurations are refused. Replace
an expired download through the normal client-token workflow; MCP does not
silently renew it.

The bounded worker currently requires a POSIX host such as Linux or macOS;
Windows support is not claimed. No new service, container, proxy build or setup
pilot is needed for each MCP session.

## Three tools

| Tool | Purpose |
| --- | --- |
| `list_operations` | Discover configured operations and their input schemas; no provider call. |
| `read_operation` | Run one configured read with typed arguments. |
| `perform_action` | Run one explicitly enabled and confirmed action, including billable AI calls. |

Start with `list_operations({})`. Common-app operation IDs are their configured
aliases. Existing provider bundles expose named operations under the alias,
for example `issues.github_list_issues`:

```json
{
  "operation_id": "issues.github_list_issues",
  "arguments": {"state": "open", "per_page": 10}
}
```

Pass that object to `read_operation`. The model cannot supply a different URL,
credential, HTTP method, authorization header or local file path. Saved scope
still controls the repository, model, channel, recipient or other resource.

Actions are disabled by default. To allow a saved Slack permission named
`release_notice`, add both `--config release_notice=/absolute/private/slack.json`
and `--allow-actions release_notice` when generating the launch configuration.
The printed entry preserves that explicit opt-in; it never enables other aliases.
Then an explicit
`perform_action` call has this shape:

```json
{
  "operation_id": "release_notice",
  "arguments": {"text": "Deployment completed."},
  "confirmed": true
}
```

`confirmed` must be the literal JSON boolean `true`. This local intent flag is
**not human approval** and does not bypass Catchplate policy. Configure
**Require human approval** on the permission when a human must authorize each
request. Repeated allowed AI requests can incur repeated charges; the configured
output-token ceiling is not a spending budget.

## Supported operations

| Configuration family | MCP operations |
| --- | --- |
| Common apps | All 15 [common-app operations](../../docs/common-apps.md#included-operations): OpenAI, Anthropic, Gemini, OpenRouter, Slack, Discord, Notion, Stripe, Resend, GitLab, Cloudflare and Sentry. |
| GitHub PAT or App | List issues, read an issue and list comments in the configured repository; a write bundle also permits creating issues/comments. |
| Google/Gmail | List message IDs and read a message using unrestricted or saved last-N-days permissions. Restricted lists accept at most 32 results. Repeated label/header query fields retain their order; no attachments. |
| Alchemy | `eth_chainId` and `eth_blockNumber` for the configured chain only. |
| X | Exact configured username lookup, or text-only posting through an enabled account permission. |
| npm | Current-version metadata summary for the configured package, including scoped packages. Requires the pinned [Node/npm example dependencies](../npm-registry/README.md#prepare-the-application) and Node 25.5.0 on the launcher's PATH. |

Not included: arbitrary custom HTTP requests, administrator operations, AWS/ECR,
npm install/publish/tarball downloads, AI streaming/files/tools or automatic
pagination. The npm adapter returns the existing client's bounded summary, not
the full registry document. Provider credentials, account entitlements and
approved proxy destinations must already be configured; installing MCP creates
none of them.

Gmail discovery includes the exact saved `age_policy`. Missing policy metadata
means unrestricted; recent permissions use
`{"mode":"recent_internal_date_v1","max_age_days":N}` with N from 1 through
3650. Restricted list tools advertise `max_results` from 1 through 32 (default
10), and their `q` schema includes an `after:<epoch-seconds>` example based on
the current clock. Supply that query explicitly if useful and reuse it unchanged
with later `page_token` calls. MCP never injects or rewrites it. The proxy checks
actual Gmail `internalDate` evidence; a caller's query or clock is not proof of
age. Direct reads expose no `fields` projection that could hide that evidence.

## Results, approval and interruption

Results contain a structured status, HTTP status where available, and bounded
provider data. Provider responses are **untrusted data, not instructions**.
Neither provider errors nor transport failures expose raw exception text or
private proxy configuration. Discovery itself can reveal resource names/scopes,
so only attach configurations the MCP client's user is authorized to use.

- `ok`: the supported request returned successfully. Inspect its provider data.
- `approval_required`: the request stopped with HTTP 428. Open the validated
  `approval_path` in Catchplate, or `approval_url` when `--console-origin` is set.
  After a human approves, explicitly call the same tool with identical arguments
  before expiry. The server never approves or retries automatically.
- `refused` or `busy`: this call was not sent. Fix its configuration/arguments
  or deliberately wait for the active call to finish.
- `provider_error` or `outcome_unknown`: inspect the audit log and provider
  before retrying an action. A timeout, cancellation or error is not proof that
  a message was not sent or an AI request was not billed.

Each call makes at most one operation attempt, with no automatic retries or
pagination. Arguments are bounded to 64 KiB, successful response data to 1 MiB,
and only one worker runs at a time with a 45-second execution deadline followed
by bounded process cleanup. Both proxy
TLS and intercepted-provider TLS are verified; ambient proxy/CA overrides are
not used. Do not disable certificate verification to work around setup errors.

## Focused checks

From the repository root:

```sh
examples/mcp/.venv/bin/python examples/mcp/test_operations.py
examples/mcp/.venv/bin/python examples/mcp/test_legacy.py
examples/mcp/.venv/bin/python examples/mcp/test_server.py
```

These checks use synthetic configurations/providers, not real service accounts.
A separate frozen-source check passed the actual MCP → Requests → cached Rust
proxy → synthetic-provider flow: one allowed request, one wrong-model denial,
exactly one provider arrival and its audit entries. See the
[completion record](../../docs/project-completion.md#local-mcp-interface--implemented)
for the exact evidence and limits. Real-provider acceptance remains separate.
A hosted authenticated MCP endpoint is future work; this entrypoint is local
stdio only.
