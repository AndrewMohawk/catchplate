"""Reviewed service presets using existing exact-route JSON enforcement.

Public dummy values are deliberately not provider credentials. Provider
references and the supported subset are documented in docs/common-apps.md.
"""
from __future__ import annotations


HEADERS = ["accept", "accept-language", "sec-fetch-mode", "user-agent"]
UUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
EMAIL = r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$"


def _scope(key, label, pattern, placeholder):
    return {"key": key, "label": label, "type": "text", "required": True,
        "pattern": pattern, "placeholder": placeholder}


def _provider(identifier, label, description, operations, *, auth_type="bearer",
              header_name="Authorization", secret_label="API token", secret_hint="Store the raw token, without an Authorization prefix.",
              injection_prefix=None):
    token = "serverware-" + identifier + "-placeholder-v1"
    prefix = injection_prefix if injection_prefix is not None else ("Bearer " if auth_type == "bearer" else "")
    result = {"id": identifier, "label": label, "description": description,
        "auth_type": auth_type, "header_name": header_name, "secret_label": secret_label,
        "secret_hint": secret_hint, "sdk_auth_token": token,
        "placeholder": prefix + token, "operations": operations}
    if injection_prefix is not None:
        result["injection_prefix"] = injection_prefix
    return result


def _read(identifier, label, description, origin, path, *, scope=(), query=(), headers=(), notes=(), **extra):
    return {"id": identifier, "label": label, "description": description,
        "origin": origin, "path_template": path, "methods": ["GET"],
        "scope_fields": list(scope), "request_fields": [], "query_keys": list(query),
        "allowed_headers": HEADERS + list(headers), "field_rules": {},
        "value_rules": [], "example_body": None, "notes": list(notes), **extra}


PRESETS = [
    _provider("slack", "Slack", "Post text to one approved Slack channel.", [
        {"id": "post_message", "label": "Post a message to one channel",
         "description": "Send plain-text messages and thread replies; the channel is fixed by this permission.",
         "origin": "https://slack.com", "path_template": "/api/chat.postMessage", "methods": ["POST"],
         "scope_fields": [_scope("channel", "Channel ID", r"^[CGD][A-Z0-9]{8,31}$", "C0123456789")],
         "request_fields": ["channel", "text", "thread_ts", "mrkdwn", "unfurl_links", "unfurl_media"],
         "query_keys": [], "allowed_headers": HEADERS,
         "field_rules": {
             "channel": {"type": "string", "required": True, "equals": {"$scope": "channel"}},
             "text": {"type": "string", "required": True, "minLength": 1, "maxLength": 4000},
             "thread_ts": {"type": "string", "maxLength": 32, "pattern": r"^[0-9.]{1,32}$"},
             "mrkdwn": {"type": "boolean"},
             "unfurl_links": {"type": "boolean", "required": True, "equals": False},
             "unfurl_media": {"type": "boolean", "required": True, "equals": False}},
         "value_rules": [],
         "example_body": {"channel": {"$scope": "channel"}, "text": "Deployment completed.",
             "unfurl_links": False, "unfurl_media": False},
         "notes": ["Use a bot token with chat:write and invite the bot to this channel.",
             "JSON only; form-encoded calls, attachments and blocks are not in this preset.",
             "Link/media unfurls must explicitly be false. Mention handling is still Slack's behavior.",
             "A Slack HTTP 200 can contain ok:false; inspect the returned JSON.",
             "This client API permission is separate from Serverware's notification destinations."]}],
        secret_label="Bot token", secret_hint="Store the raw xoxb bot token. Grant chat:write and invite the bot to the intended channel."),
    _provider("discord", "Discord", "Send text to one approved Discord channel through the REST API.", [
        {"id": "create_message", "label": "Send a message to one channel",
         "description": "Send bounded text to one channel, with all automatic mentions disabled.",
         "origin": "https://discord.com", "path_template": "/api/v10/channels/{channel_id}/messages",
         "methods": ["POST"],
         "scope_fields": [_scope("channel_id", "Channel ID", r"^[1-9][0-9]{16,19}$", "123456789012345678")],
         "request_fields": ["content", "allowed_mentions.parse"], "query_keys": [],
         "allowed_headers": HEADERS,
         "field_rules": {"content": {"type": "string", "required": True, "minLength": 1, "maxLength": 2000},
             "allowed_mentions": {"type": "object", "required": True},
             "allowed_mentions.parse": {"type": "array", "required": True, "minItems": 0, "maxItems": 0}},
         "value_rules": [], "example_body": {"content": "Deployment completed.", "allowed_mentions": {"parse": []}},
         "notes": ["Install the bot and grant View Channel and Send Messages for this channel.",
             "Store the raw bot token; Serverware supplies the Bot authorization prefix.",
             "REST text messages only: no Gateway/WebSocket, attachments, embeds or webhook-token URLs.",
             "The request must include allowed_mentions:{parse:[]} to avoid unintended mentions."]}],
        secret_label="Bot token", secret_hint="Store the raw Discord bot token, without the Bot prefix.", injection_prefix="Bot "),
    _provider("notion", "Notion", "Read a page or the immediate children of one block.", [
        _read("retrieve_page", "Read one page's properties", "Retrieve metadata and properties, not the page's block contents.",
            "https://api.notion.com", "/v1/pages/{page_id}",
            scope=[_scope("page_id", "Page ID", UUID, "01234567-89ab-cdef-0123-456789abcdef")],
            headers=["notion-version"], request_headers={"Notion-Version": "2026-03-11"},
            required_headers={"notion-version": {"type": "string", "minLength": 10, "maxLength": 10, "pattern": r"^[0-9-]{10,10}$"}},
            value_rules=[{"source": "header", "name": "notion-version", "predicate": {"kind": "equals", "value": "2026-03-11"}}],
            notes=["Share the page with the integration and enable Read content.",
                "Send Notion-Version:2026-03-11; a page read does not permit search or other pages."]),
        _read("block_children", "Read one block's children", "Read the immediate child blocks of one page/block; no recursive grant.",
            "https://api.notion.com", "/v1/blocks/{block_id}/children",
            scope=[_scope("block_id", "Page or block ID", UUID, "01234567-89ab-cdef-0123-456789abcdef")],
            query=["start_cursor", "page_size"], headers=["notion-version"],
            request_headers={"Notion-Version": "2026-03-11"},
            required_headers={"notion-version": {"type": "string", "minLength": 10, "maxLength": 10, "pattern": r"^[0-9-]{10,10}$"}},
            value_rules=[{"source": "header", "name": "notion-version", "predicate": {"kind": "equals", "value": "2026-03-11"}}],
            notes=["Share the containing page with the integration and enable Read content.",
                "Child blocks with their own children need separately granted exact-block permissions.",
                "Use the returned next_cursor; do not assume all page content fits in one response."])],
        secret_label="Integration token", secret_hint="Store the raw integration token and share only the intended Notion pages with it."),
    _provider("stripe", "Stripe", "Read account balance or customer records; no payment writes.", [
        _read("balance", "Read account balance", "Read the account selected by the stored Stripe key.",
            "https://api.stripe.com", "/v1/balance", headers=["stripe-version", "x-stripe-client-user-agent"],
            notes=["Use a restricted read-only test key first; Connect account-selection headers are not allowed."]),
        _read("customers", "List customers", "Read customer records visible to the stored key, with optional filters and pagination.",
            "https://api.stripe.com", "/v1/customers", query=["limit", "email", "starting_after", "ending_before"],
            headers=["stripe-version", "x-stripe-client-user-agent"],
            notes=["This is account-wide customer read access, not a single-customer or email-equality grant.",
                "Use a restricted read-only key. No customer changes, payments, refunds or Connect account switching.",
                "The client must send the exact Bearer dummy header; an SDK using Basic needs its documented auth hook."])],
        secret_label="Restricted API key", secret_hint="Prefer a restricted read-only Stripe key; start with test mode. Store only the raw key."),
    _provider("resend", "Resend", "Send an email from one exact sender to one exact recipient.", [
        {"id": "send_email", "label": "Send email to one recipient",
         "description": "Send bounded plain-text email; sender and recipient are fixed by the permission.",
         "origin": "https://api.resend.com", "path_template": "/emails", "methods": ["POST"],
         "scope_fields": [_scope("sender", "Verified sender email", EMAIL, "alerts@example.com"),
             _scope("recipient", "Recipient email", EMAIL, "operator@example.com")],
         "request_fields": ["from", "to", "subject", "text"], "query_keys": [],
         "allowed_headers": HEADERS + ["idempotency-key"],
         "field_rules": {"from": {"type": "string", "required": True, "equals": {"$scope": "sender"}},
             "to": {"type": "string", "required": True, "equals": {"$scope": "recipient"}},
             "subject": {"type": "string", "required": True, "minLength": 1, "maxLength": 998},
             "text": {"type": "string", "required": True, "minLength": 1, "maxLength": 4096}},
         "value_rules": [], "example_body": {"from": {"$scope": "sender"}, "to": {"$scope": "recipient"},
             "subject": "Deployment completed", "text": "Your deployment completed successfully."},
         "notes": ["Use a sending-only key scoped to the verified sender domain where possible.",
             "Use a single recipient string, not an array. No CC/BCC, HTML, attachments, templates or custom mail headers.",
             "An optional Idempotency-Key reduces duplicate sends; Serverware does not replay uncertain writes."]}],
        secret_hint="Store the raw Resend API key. Prefer sending-only access for the verified sender domain."),
    _provider("gitlab", "GitLab", "Read issues in one GitLab.com project.", [
        _read("project_issues", "Read one project's issues", "List issues in one exact numeric project; no repository or issue writes.",
            "https://gitlab.com", "/api/v4/projects/{project_id}/issues",
            scope=[_scope("project_id", "Numeric project ID", r"^[1-9][0-9]{0,19}$", "12345")],
            query=["state", "labels", "search", "page", "per_page", "order_by", "sort"],
            notes=["Use a project access token with read_api and access to this project.",
                "Use the numeric project ID, not an encoded group/project path.",
                "GitLab.com only in this preset. Self-managed hosts require a separately approved custom API permission.",
                "Pagination response headers are not forwarded; request explicit bounded pages."])],
        auth_type="header", header_name="PRIVATE-TOKEN", secret_label="Project access token",
        secret_hint="Store the raw GitLab project access token with read_api; Serverware injects PRIVATE-TOKEN."),
    _provider("cloudflare", "Cloudflare", "Read permitted zones or DNS records in one exact zone.", [
        _read("zones", "List zones", "List zones visible to this restricted Cloudflare API token; never modify DNS.",
            "https://api.cloudflare.com", "/client/v4/zones", query=["name", "status", "page", "per_page", "order", "direction"],
            notes=["Use a restricted API token with Zone:Read on only the intended zones.",
                "This lists all token-accessible zones; the optional name query is a filter, not a fixed permission scope."]),
        _read("dns_records", "Read DNS records in one zone", "List DNS records in one exact zone; no create/update/delete operations.",
            "https://api.cloudflare.com", "/client/v4/zones/{zone_id}/dns_records",
            scope=[_scope("zone_id", "Zone ID", r"^[0-9a-f]{32}$", "0123456789abcdef0123456789abcdef")],
            query=["name", "type", "page", "per_page", "order", "direction"],
            notes=["Use a restricted API token with DNS:Read for this zone.",
                "This credential does not use the Global API Key plus account email scheme."])],
        secret_label="Restricted API token", secret_hint="Store a scoped Cloudflare API token, not a Global API Key. This preset only grants reads."),
    _provider("sentry", "Sentry", "Read issues for one exact project in one organization.", [
        _read("project_issues", "Read one project's issues", "Use the current organization-issues endpoint with one required project selector.",
            "https://sentry.io", "/api/0/organizations/{organization}/issues/",
            scope=[_scope("organization", "Organization slug", r"^[a-z0-9][a-z0-9-]{0,62}$", "my-organization"),
                _scope("project_id", "Numeric project ID", r"^[1-9][0-9]{0,19}$", "12345")],
            query=["project", "query", "statsPeriod", "sort", "limit", "cursor"],
            value_rules=[{"source": "query", "name": "project", "predicate": {"kind": "equals", "value": {"$scope": "project_id"}}}],
            example_query={"project": {"$scope": "project_id"}},
            notes=["Use a token with event:read and access to this organization/project.",
                "Every request must supply exactly one project query equal to the configured numeric ID.",
                "shortIdLookup and alternative project selection are not allowed.",
                "sentry.io only; regional or self-hosted API origins need separately approved custom permissions.",
                "Pagination Link headers are not forwarded; this recipe does not promise automatic multi-page SDK traversal."])],
        secret_label="Read-only auth token", secret_hint="Store an auth token with event:read and access to the intended organization/project."),
]
