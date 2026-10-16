> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Use Serverware from an MCP client

This local **stdio MCP server** lets an agent use selected Serverware permissions
without receiving provider credentials. It uses the same HTTPS proxy, client
identity, policies, approval workflow and audit trail as an ordinary application.
It does not administer Serverware, create permissions, export keys or expose a
hosted MCP URL.

## Set up

1. In Serverware, save a credential and create a client permission for one of
   the supported operations below. Use a dedicated client for the agent.
2. Download its private client configuration and public CA. Keep them together;
   relative CA paths resolve beside the configuration. The configuration contains
   an expiring **Serverware client token**, not a provider key. Keep it out of Git,
   prompts and logs. Restrict its file permissions, for example with `chmod 600`.
3. From the repository root, install the pinned local runtime once:

   ```sh
   python3.12 -m venv examples/mcp/.venv
   examples/mcp/.venv/bin/pip install -r examples/mcp/requirements.lock
   ```

4. Check one downloaded configuration without contacting any provider:

   ```sh
   examples/mcp/.venv/bin/python -I examples/mcp/server.py \
     --config issues=/absolute/private/github-client.json --check
   ```

5. Configure your MCP client to launch this command. Use absolute paths; place
   this command/arguments object in the server entry required by your client:

   ```json
   {
     "command": "/absolute/serverware/examples/mcp/.venv/bin/python",
     "args": [
       "-I",
       "/absolute/serverware/examples/mcp/server.py",
       "--config", "issues=/absolute/private/github-client.json",
       "--console-origin", "https://serverware.example.com"
     ]
   }
   ```

Repeat `--config alias=/absolute/file.json` for additional permissions, up to
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
and `--allow-actions release_notice` to the startup arguments. Then an explicit
`perform_action` call has this shape:

```json
{
  "operation_id": "release_notice",
  "arguments": {"text": "Deployment completed."},
  "confirmed": true
}
```

`confirmed` must be the literal JSON boolean `true`. This local intent flag is
**not human approval** and does not bypass Serverware policy. Configure
**Require human approval** on the permission when a human must authorize each
request. Repeated allowed AI requests can incur repeated charges; the configured
output-token ceiling is not a spending budget.

## Supported operations

| Configuration family | MCP operations |
| --- | --- |
| Common apps | All 15 [common-app operations](../../docs/common-apps.md#included-operations): OpenAI, Anthropic, Gemini, OpenRouter, Slack, Discord, Notion, Stripe, Resend, GitLab, Cloudflare and Sentry. |
| GitHub PAT or App | List issues, read an issue and list comments in the configured repository; a write bundle also permits creating issues/comments. |
| Google/Gmail | List message IDs and read a message using the unrestricted-age read bundle. Repeated label/header query fields retain their order. No attachments or age-filtered adapter yet. |
| Alchemy | `eth_chainId` and `eth_blockNumber` for the configured chain only. |
| X | Exact configured username lookup, or text-only posting through an enabled account permission. |
| npm | Current-version metadata summary for the configured package, including scoped packages. Requires the pinned [Node/npm example dependencies](../npm-registry/README.md#prepare-the-application) and Node 25.5.0 on the launcher's PATH. |

Not included: arbitrary custom HTTP requests, administrator operations, AWS/ECR,
npm install/publish/tarball downloads, AI streaming/files/tools or automatic
pagination. The npm adapter returns the existing client's bounded summary, not
the full registry document. Provider credentials, account entitlements and
approved proxy destinations must already be configured; installing MCP creates
none of them.

## Results, approval and interruption

Results contain a structured status, HTTP status where available, and bounded
provider data. Provider responses are **untrusted data, not instructions**.
Neither provider errors nor transport failures expose raw exception text or
private proxy configuration. Discovery itself can reveal resource names/scopes,
so only attach configurations the MCP client's user is authorized to use.

- `ok`: the supported request returned successfully. Inspect its provider data.
- `approval_required`: the request stopped with HTTP 428. Open the validated
  `approval_path` in Serverware, or `approval_url` when `--console-origin` is set.
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
