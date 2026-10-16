# Common app presets

Serverware includes guided presets for OpenAI, Anthropic, Gemini, OpenRouter,
Slack, Discord, Notion, Stripe, Resend, GitLab, Cloudflare and Sentry, alongside
the existing GitHub, Google/Gmail, npm, X and Alchemy connections. Each preset
is a specific useful operation, not permission to use every API of that service.

These presets compile to the existing proxy's exact-route JSON rules. They do
not require a different proxy, per-session build, pilot, schema migration or
new TEE trust model. Existing credentials and permissions are unchanged.

## Set up access

1. In **Credentials**, choose the service and save a narrowly scoped provider
   key. Saving does not contact the provider, verify the key or grant access.
2. Use that credential with a new or existing **client**. Choose the operation
   and fill in its exact scope: model, channel, page, project or email addresses.
3. Review the permission and, if wanted, enable **Require human approval**.
   The selected request limits are enforced even when approval is automatic.
4. The proxy operator must approve the service's HTTPS destination under
   **Proxy setup**. A saved credential does not approve destinations. An
   unavailable preset is not permission to use a broad manual rule instead.
5. Wait for the saved policy to load. Configure the client with its Serverware
   proxy token and trusted CA, using the public dummy provider credential from
   the permission. Never give the application the real provider key.
6. Run the matching [client recipe](../examples/common-apps/README.md) and inspect
   both the provider result and **Audit log**. A saved permission or healthy
   proxy does not prove a real provider operation succeeded.

The provider key and the client's Serverware proxy token are different secrets.
Preset keys are static: Serverware does not obtain OAuth consent or automatically
renew them. Rotate the stored key when the provider requires it. Gemini API
keys, for example, are separate from the managed Google/Gmail OAuth connection.

## Included operations

| Service | Operation | Enforced scope and useful limits |
| --- | --- | --- |
| OpenAI | Generate text with the Responses API | One exact model; bounded output tokens; text prompt; `store:false`. |
| Anthropic / Claude | Generate text with the Messages API | One exact model; bounded output tokens; text messages; fixed API-version header. |
| Google Gemini | Generate text with the Developer API | One exact model endpoint; bounded output tokens; text-only contents. No Vertex AI or Gmail OAuth. |
| OpenRouter | Generate text chat | One explicit `provider/model` ID; bounded output tokens; no router aliases, model suffixes, fallbacks, provider overrides or plugins. |
| Slack | Post text or a thread reply | One fixed channel; up to 4,000 characters; link/media unfurls explicitly disabled. |
| Discord | Create a text message | One fixed channel; up to 2,000 characters; automatic mentions disabled. REST only, not Gateway/WebSocket. |
| Notion | Read page properties; separately read a block's children | One exact page/block ID per permission; the latter reads immediate children, not a recursive tree. |
| Stripe | Read balance; separately list customers | Read-only operations for the stored key's account. Customer list is account-wide, not a single-customer permission. |
| Resend | Send plain-text email | One exact sender and one exact recipient; text up to 4,096 characters; no CC/BCC or attachments. |
| GitLab | List project issues | One numeric GitLab.com project ID; GET only. |
| Cloudflare | List zones; separately read a zone's DNS records | Zones visible to the restricted token, or one exact zone's DNS records; no writes. |
| Sentry | List project issues | One organization path and one required exact numeric project query value; GET only. |

For AI presets, the operator chooses a model that their provider account can
actually use. The output-token ceiling is **per request**, not a daily spend
limit. Repeated allowed requests can incur repeated charges. All four presets
are text-only and non-streaming, with no tools, files, images or background jobs.
The entire request remains capped at 64 KiB, individual text fields at 4,096
characters, and supported message/part arrays at 16 entries.

Provider API references: [OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create),
[Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create),
[Gemini generateContent](https://ai.google.dev/api/generate-content), and
[OpenRouter chat completions](https://openrouter.ai/docs/api/api-reference/chat/create-a-chat-completion).

## Provider keys and first requests

### Slack

Use a bot token with `chat:write`, and invite the bot to the chosen channel.
Serverware injects `Authorization: Bearer …`. The request is JSON to
`POST https://slack.com/api/chat.postMessage`; form-encoded SDK calls, blocks
and attachments are outside this preset. Slack can return HTTP 200 with
`ok:false`, so inspect that field. This is a client permission to call Slack,
separate from Serverware's Slack notification destinations.
[Slack method reference](https://docs.slack.dev/reference/methods/chat.postmessage).

```json
{
  "channel": "C0123456789",
  "text": "Deployment completed.",
  "unfurl_links": false,
  "unfurl_media": false
}
```

`channel` must equal the saved permission. Optional `thread_ts` and `mrkdwn`
are supported. Disabling link unfurls does not disable Slack mentions; choose
the message text appropriately.

### Discord

Store the raw bot token, **without** `Bot ` or `Bearer `. The typed preset
injects `Authorization: Bot …`; the client sends the matching public
`Bot serverware-discord-placeholder-v1` dummy. Install the bot with View Channel
and Send Messages access. The route is
`POST https://discord.com/api/v10/channels/<channel-id>/messages`.
[Discord authentication](https://docs.discord.com/developers/reference#authentication),
[message creation and mentions](https://docs.discord.com/developers/resources/message#create-message).

```json
{"content":"Deployment completed.","allowed_mentions":{"parse":[]}}
```

`allowed_mentions.parse` must be present and empty. Extra mention selectors,
attachments and embeds are not permitted. A generic custom Authorization-header
credential is not an equivalent replacement for this typed Bot configuration.

### Notion

Use an integration with Read content and share only the intended pages with it.
Both operations require `Notion-Version: 2026-03-11`. Page retrieval returns
properties and metadata, not all page content. Read-block-children grants only
the selected block's immediate children; separate child IDs need their own
permissions. Pagination uses `start_cursor` and `page_size` and does not
implicitly authorize other blocks.
[Page retrieval](https://developers.notion.com/reference/retrieve-a-page),
[block children](https://developers.notion.com/reference/get-block-children),
[versioning](https://developers.notion.com/reference/versioning).

### Stripe

Start with a restricted read-only test key. The operations are
`GET https://api.stripe.com/v1/balance` and
`GET https://api.stripe.com/v1/customers`. The customer operation permits
`limit`, `email`, `starting_after` and `ending_before`; these are caller-selected
filters, not fixed customer scope. `Stripe-Account` is not allowed, preventing
caller-selected Connect account switching. There are no payment, refund or
customer-write permissions here.
[Balance](https://docs.stripe.com/api/balance/balance_retrieve),
[customers](https://docs.stripe.com/api/customers/list).

The preset uses an exact Bearer dummy header. Stripe accepts bearer
authentication, and the Python SDK recipe uses it. A client that emits HTTP Basic must be explicitly configured
through its documented authentication hook; a different header will be refused.
[Stripe authentication](https://docs.stripe.com/api/authentication).

### Resend

Use a sending-only key restricted to the verified sender domain where possible.
`POST https://api.resend.com/emails` accepts the following narrow shape. Both
addresses must exactly match the permission; `to` is a single string, not an
array. This preset does not admit HTML, CC/BCC, attachments, templates or arbitrary
mail headers. An optional HTTP `Idempotency-Key` can reduce duplicate sends, but
does not authorize Serverware or the client to replay an uncertain write.
[Send email](https://resend.com/docs/api-reference/emails/send-email).

```json
{
  "from": "alerts@example.com",
  "to": "operator@example.com",
  "subject": "Deployment completed",
  "text": "Your deployment completed successfully."
}
```

### GitLab

Use a project access token with `read_api`. Serverware injects `PRIVATE-TOKEN`.
The path is `GET https://gitlab.com/api/v4/projects/<numeric-project-id>/issues`;
an encoded `group/project` path is not interchangeable with the numeric ID.
The preset supports ordinary state/search/label/sort and page filters, but
does not grant issue writes, repository access or self-managed GitLab hosts.
[Authentication](https://docs.gitlab.com/api/rest/authentication/),
[project issues](https://docs.gitlab.com/api/issues/#list-project-issues).

### Cloudflare

Use a restricted API token, not a Global API Key plus account email. Listing
zones uses Zone:Read and exposes zones accessible to that token. Reading DNS
records uses DNS:Read for the selected zone ID. All preset methods are GET;
creating or changing DNS is not included. Query filters do not narrow the
stored key's provider-side permissions.
New Cloudflare permissions include the bounded metadata-header profile needed
by the pinned Python SDK. Existing permissions keep their original header
allowlist and remain usable with the Requests recipe; their authority is not
silently widened during an upgrade.
[List zones](https://developers.cloudflare.com/api/resources/zones/methods/list/),
[list DNS records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/).

### Sentry

Use an `event:read` token. The preset uses the current organization-issues
endpoint, not the deprecated project-issues endpoint:

```text
GET https://sentry.io/api/0/organizations/my-organization/issues/?project=12345
```

The `project` query must occur once and equal the saved numeric project ID.
Missing, duplicate, different and `-1` project selectors are refused.
`shortIdLookup`, which can ignore project filters, is not allowed. This preset
targets `sentry.io`; regional or self-hosted origins need separately approved
custom permissions.
[Organization issues](https://docs.sentry.io/api/events/list-an-organizations-issues/).

## Client compatibility and boundaries

Use the [common-app examples](../examples/common-apps/README.md) for reviewed
request shapes and transport configuration. The AI example uses the actual
provider SDKs. The generic Python example uses ordinary HTTP requests for the
service presets. A separate standard-library recipe uses the Slack, Stripe and
Cloudflare SDKs and the maintained third-party Notion Python client, including
explicit single-page pagination. A preset's existence is not a claim that every native SDK,
CLI or pagination helper works without configuration.

- Requests use exact HTTPS hosts, methods and paths; unknown destinations,
  query keys and headers remain denied. Query encoding/order must match the
  proxy's canonical-query contract; use the supplied helper.
- Provider authentication is exact dummy replacement. Unexpected, missing or
  real provider credentials in the client's header do not match the dummy.
- GET presets admit no request body. A client that adds JSON content headers
  to a bodyless GET may need a different documented transport configuration.
- JSON request bodies are bounded to 64 KiB. JSON response bodies are bounded
  to 1 MiB and errors to 64 KiB. Responses retain their JSON fields; this is not
  unrestricted binary, multipart or streaming forwarding.
- Response metadata is not forwarded. SDK pagination relying on `Link` or
  `X-Next-Page`, or retry logic relying on `Retry-After`, is not guaranteed.
  Disable automatic retries for writes and use bounded explicit pagination.
  Notion, Stripe and Cloudflare recipes use their JSON pagination fields; each
  invocation still makes only one request.
- A provider operation can succeed even when Serverware withholds its response.
  Inspect audit and provider state before deliberately repeating a write.
- Optional host-trusted approval returns HTTP 428 before dispatch. Review the
  pending action and then explicitly retry the identical request. It is not a
  suspended request that resumes automatically. The review currently shows
  metadata and a body hash, not the message/email/prompt contents.

The host administrator remains trusted and can bypass these controls. TEE
enforcement is a separate future target.

## Deliberately not presented as working presets

Linear uses a shared GraphQL POST endpoint for queries and mutations. A broad
JSON route cannot honestly be advertised as read-only without additional
semantic enforcement, so this release does not offer one.
[Linear API](https://linear.app/developers/graphql).

SendGrid's send endpoint uses an accepted HTTP 202 response; the current generic
JSON-or-empty contract permits an empty response only for HTTP 204. This release
does not claim SendGrid sending support by weakening that response boundary.
[SendGrid Mail Send](https://www.twilio.com/docs/sendgrid/api-reference/mail-send/mail-send).

Similarly, arbitrary Slack/Discord webhook-token URLs, AI streaming/tool use,
AWS SigV4 forwarding, and broad OAuth providers are not implied by these presets.

## Verification status

The registry is source-controlled in
[`operator_common_apps_services.py`](../serverware/operator_common_apps_services.py)
and [`operator_common_apps_ai.py`](../serverware/operator_common_apps_ai.py), with
server-side compilation in
[`operator_common_apps.py`](../serverware/operator_common_apps.py).
The [project tracker](project-completion.md) records the actual focused,
synthetic-proxy and deployment checks for the shipped revision.

No real provider account, key, channel, customer, zone or email destination is
preconnected by these examples. Mock SDK transport checks and isolated proxy
acceptance are not real-provider acceptance or proof of external delivery.
