# Common API clients through Serverware

Use one application login and a downloaded configuration, not real provider keys
in your script. The same Requests example covers Slack, Discord, Notion, Stripe,
Resend, GitLab, Cloudflare and Sentry. It also accepts the four AI presets; the
official SDK example below is usually more convenient for those.

The [service SDK example](#standard-service-sdks) also supports Slack, Notion,
Stripe and Cloudflare through their normal Python client methods.

These are deliberately scoped operations, not blanket access to each provider.
The proxy enforces the selected destination, method, resource and body policy.
The application has only a public placeholder in the provider-authentication
header. Serverware replaces it with its stored credential.

## Get the configuration

1. In Serverware, add the service credential using its named preset.
2. Create a permission for your application, select a supported operation and
   enter its scope (for example a Slack channel or GitLab project).
3. Download the private client configuration and the public Serverware CA from
   the application setup. Save them together, with the CA filename matching
   `ca_file` in the configuration. Relative CA paths resolve beside the JSON
   file, not the current directory.
4. Keep the configuration private: it contains an expiring application proxy
   password. Do not commit it, put it into logs, or replace the placeholder with
   a real provider credential. Renew/download a new login when it expires.

From this example directory:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
chmod 600 ./serverware-client.private.json
.venv/bin/python request.py --config ./serverware-client.private.json
```

A GET permission makes exactly one read. POST permissions send nothing unless
you explicitly supply both a body file and `--execute-write`.

To prepare and review a write:

```sh
.venv/bin/python request.py --config ./serverware-client.private.json --print-example-body > request.json
# Edit request.json and check its destination and contents before the next command.
.venv/bin/python request.py --config ./serverware-client.private.json --body ./request.json --execute-write
```

The first command only prints the scope-resolved example; it performs no network
request. The second can send a real message/email or incur an AI charge. The body
file's bytes are sent unchanged. Keep it unchanged for an approved exact retry.
Never use an example sender, recipient or channel without choosing it yourself.

## Available service recipes

| Preset | Supported operation | Important limitation |
| --- | --- | --- |
| Slack | Post text in one fixed channel | Bot needs `chat:write` and channel access; explicit link/media unfurls are disabled. HTTP 200 with `ok:false` is still an application error. |
| Discord | Post text in one fixed channel | Bot REST API, not Gateway; automatic mentions disabled, no attachments or embeds. |
| Notion | Read a page or one block's immediate children | Share the page with the integration; no recursive traversal or edits. |
| Stripe | Read account balance or list customers | Read-only, token-wide customer visibility; use a restricted test key first, no payments/refunds. |
| Resend | Send plain-text email from one sender to one recipient | Verified sender; no HTML, CC/BCC, attachments or templates. |
| GitLab | Read one numeric project's issues | GitLab.com project token with `read_api`; no writes. |
| Cloudflare | List token-accessible zones or read one zone's DNS records | Restricted read-only API token; no DNS writes. |
| Sentry | Read issues for one organization and numeric project | Token needs `event:read`; the downloaded query fixes the project selector. |

No automatic pagination: each invocation makes one request. Add permitted query
parameters explicitly, such as:

```sh
.venv/bin/python request.py --config ./serverware-client.private.json --query per_page=5 --query state=opened
```

That example is for GitLab. Query keys vary by operation; unknown keys, duplicate
keys and attempts to override a configured selector are rejected before sending.
Response pagination headers are not guaranteed to survive proxy filtering.

## Standard service SDKs

`services_python.py` uses Slack's asynchronous SDK, Stripe's SDK, Cloudflare's
SDK and the maintained third-party `notion-client` package. It supports the
existing scoped operations above, not each library's entire API. Install its
pinned Python 3.12 dependencies once:

```sh
python3.12 -m venv .venv-services
.venv-services/bin/pip install -r requirements-services.txt
.venv-services/bin/python services_python.py --config ./serverware-client.private.json
```

That command performs one read for Notion, Stripe or Cloudflare. For Slack,
prepare the body using `request.py --print-example-body`, review it, then run:

```sh
.venv-services/bin/python services_python.py --config ./serverware-client.private.json \
  --body ./request.json --execute-write
```

Reads return one page, with the provider's JSON pagination fields preserved.
Request another page explicitly using the downloaded operation's permitted
query arguments, such as `--query page_size=10 --query start_cursor=CURSOR`
for Notion block children, `--query limit=10 --query starting_after=CUSTOMER_ID`
for Stripe customers, or `--query page=2 --query per_page=10` for Cloudflare.
The helper canonicalizes query encoding/order without changing the chosen
parameters. It does not invoke SDK auto-pagination, retry requests or follow
redirects. A page permission never authorizes following arbitrary child IDs.

Use a newly created Cloudflare permission for this SDK recipe. Retained legacy
Cloudflare permissions still work with `request.py`; they are not silently
expanded to admit the SDK's extra metadata headers. The new selector keeps the
same readable operation names.

Slack's supported asynchronous transport uses one verified trust store for
both proxy TLS and intercepted-provider TLS: public roots plus the Serverware
CA (and a private proxy CA when configured). Both hostnames are checked. The
other three SDK transports use separate outer-proxy and provider trust stores.
Never disable certificate verification to make a client work.

Results include HTTP status, bounded provider JSON and `ok`. Slack `ok:false`
and Cloudflare `success:false` are failures even with HTTP 200. HTTP 428 returns
a validated approval path and an explicit identical-retry instruction; no
approval, retry or additional page request happens automatically.

## Official AI SDKs

The AI example uses the unmodified OpenAI SDK for OpenAI/OpenRouter, Anthropic's
SDK for Claude, and Google's Gen AI SDK for Gemini. Python 3.12 or newer is needed
by the pinned AI dependency set:

```sh
python3.12 -m venv .venv-ai
.venv-ai/bin/pip install -r requirements-ai.txt
.venv-ai/bin/python ai_python.py --config ./serverware-client.private.json --prompt 'Say hello in one sentence.' --send
```

`--send` is explicit confirmation of a potentially billable request. The operator
selects the exact model and output-token ceiling in the permission. These presets
are text-only and non-streaming: no tools, images, files or background work.
Output-token limits are per request, **not a daily spending cap**. Gemini API keys
are distinct from Google OAuth connections and Vertex AI credentials. Provider
access and model availability still depend on your provider account.
The Anthropic recipe uses an empty private SDK configuration directory, so it
does not load unrelated local profiles and also works without a Unix home entry.

## Approval, failure and TLS behavior

- HTTP 428 means review is required. Open the review URL in the returned JSON,
  approve in Serverware, then explicitly rerun the identical command/body before
  approval expires. The original connection is not held open.
- None of these examples retries automatically. A timeout, lost response or non-success
  after a write can mean the provider acted. Inspect the provider and audit log
  before deciding whether another attempt is safe; approval is not an idempotency
  guarantee. A denied request does not become an automatic retry.
- Requests prints bounded JSON plus its HTTP status. Slack `ok:false` and
  Cloudflare `success:false` also produce a nonzero exit status, even with HTTP
  200. Inspect any other provider-level error fields too.
- Response bodies are limited to 1 MiB for success and 64 KiB for errors. Empty
  HTTP 204 is supported. Responses are not streamed to the terminal.
- The proxy connection is HTTPS with Basic CONNECT authentication from the
  application login. The real provider header remains a placeholder in this
  client. `basic_and_bearer_v1` indicates supported proxy login formats; these
  examples choose Basic, not an extra upstream bearer credential.
- TLS verifies both the outer proxy and the intercepted provider connection.
  `ca_file` trusts Serverware's provider certificates. The outer proxy normally
  uses public roots; optional `proxy_ca_file` supplies an additional private proxy
  CA. Do not disable certificate verification or alter global trust.
- Environment proxies, `.netrc` and environment CA overrides are not used. Errors
  are deliberately concise because raw transport exceptions can contain the
  private proxy URL. These examples never print that login URL.

## Local checks

```sh
.venv/bin/python test_request.py
.venv-services/bin/python test_services_python.py
```

The focused tests use actual Requests with its final network send intercepted and
socket operations prohibited. They validate configuration, scope queries, explicit
write intent, request/auth shape, limits and approval handling. They do not contact
providers or establish live provider acceptance. AI SDK checks live at
`scripts/test_common_apps_ai_sdk.py` in the repository root.

## GitHub Actions: one manual read

[`github-actions.yml`](github-actions.yml) is an inactive sample, not a workflow
installed by this example. Keep this directory in your trusted repository and
copy the reviewed file to `.github/workflows/serverware-read.yml`. Dispatch it
manually on the default branch. It uses the Ubuntu 24.04 runner's Python 3.12,
the pinned checkout action already used by the other examples, and these secrets:

- `SERVERWARE_CLIENT_CONFIG_JSON`: the complete private client JSON downloaded
  for a **GET-only** common-app permission, with an unexpired application login.
- `SERVERWARE_CA_PEM`: the public Serverware CA certificate contents.
- `SERVERWARE_PROXY_CA_PEM`: optional public CA for a privately signed HTTPS
  proxy; leave this secret unset for an ordinarily trusted proxy endpoint.

No provider API key is placed in CI. Dependency installation happens before
application secrets enter the job. Private files have fixed names inside a
private temporary directory, and both an exit trap and an `always()` step clean
them up. The workflow refuses POST permissions, never passes `--execute-write`,
does not retry, and withholds the provider response from workflow logs and
artifacts. This is suitable for an automatic read permission; it neither approves
nor polls human-review requests. A failure requires investigation and a new
explicit dispatch, not an automatic replay. The sample has not been run against
a live provider or activated in this repository.
