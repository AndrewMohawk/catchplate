"""Closed, text-only AI presets compiled with existing generic REST constraints.

No provider discovery, model recommendation, API call or credential lives here.
Model IDs are operator choices and output limits are per request, not spend caps.
"""

_STAINLESS_HEADERS = [
    "accept", "user-agent", "x-stainless-lang", "x-stainless-package-version",
    "x-stainless-os", "x-stainless-arch", "x-stainless-runtime",
    "x-stainless-runtime-version", "x-stainless-async", "x-stainless-retry-count",
    "x-stainless-read-timeout", "x-stainless-timeout",
]
_MODEL = {"key": "model", "label": "Allowed model ID", "type": "text",
    "required": True, "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
    "placeholder": "Exact model ID from your provider account"}
_TOKENS = {"key": "max_output_tokens", "label": "Maximum output tokens per request",
    "type": "number", "required": True, "min": 16, "max": 4096, "default": 1024}
_TEXT = {"type": "string", "minLength": 1, "maxLength": 4096}
_MODEL_RULE = {"type": "string", "required": True, "equals": {"$scope": "model"}}
_TOKEN_RULE = {"type": "integer", "required": True, "min": 16,
    "max": {"$scope": "max_output_tokens"}}
_COMMON_NOTES = [
    "Text only, buffered responses; no streaming, tools, files, images or background jobs.",
    "Exact model and per-request output-token ceiling are enforced by the proxy.",
    "Requests are capped at 64 KiB; each text field is capped at 4096 characters.",
    "This is not a daily spend limit. Repeated allowed requests can incur repeated charges.",
    "Provider access, billing and model availability still depend on your provider account.",
]

PRESETS = [
    {
        "id": "openai", "label": "OpenAI", "description": "Generate a bounded text response with one approved model.",
        "auth_type": "bearer", "header_name": "Authorization", "secret_label": "OpenAI API key",
        "secret_hint": "Use an API project key, not a ChatGPT login or subscription token.",
        "sdk_auth_token": "serverware-openai-placeholder-v1",
        "placeholder": "Bearer serverware-openai-placeholder-v1",
        "operations": [{
            "id": "responses_text_v1", "label": "Generate text", "description": "One text prompt using the Responses API.",
            "origin": "https://api.openai.com", "path_template": "/v1/responses", "methods": ["POST"],
            "scope_fields": [_MODEL, _TOKENS], "query_keys": [], "allowed_headers": _STAINLESS_HEADERS,
            "request_fields": ["model", "input", "instructions", "max_output_tokens", "stream", "store"],
            "field_rules": {"model": _MODEL_RULE, "input": {**_TEXT, "required": True},
                "instructions": _TEXT, "max_output_tokens": _TOKEN_RULE,
                "stream": {"type": "boolean", "equals": False},
                "store": {"type": "boolean", "required": True, "equals": False}},
            "example_body": {"model": {"$scope": "model"}, "input": "Say hello in one sentence.",
                "max_output_tokens": {"$scope": "max_output_tokens"}, "stream": False, "store": False},
            "notes": [*_COMMON_NOTES, "Response storage must be explicitly disabled with store=false."],
        }],
    },
    {
        "id": "anthropic", "label": "Anthropic / Claude", "description": "Send text messages using a single-workspace API key.",
        "auth_type": "header", "header_name": "x-api-key", "secret_label": "Anthropic API key",
        "secret_hint": "Use a key for one workspace; Claude browser/Code login tokens are not API keys.",
        "sdk_auth_token": "serverware-anthropic-placeholder-v1",
        "placeholder": "serverware-anthropic-placeholder-v1",
        "operations": [{
            "id": "messages_text_v1", "label": "Generate text", "description": "Text-only Messages API requests, up to 16 messages.",
            "origin": "https://api.anthropic.com", "path_template": "/v1/messages", "methods": ["POST"],
            "scope_fields": [_MODEL, _TOKENS], "query_keys": [],
            "allowed_headers": [*_STAINLESS_HEADERS, "anthropic-version"],
            "request_headers": {"anthropic-version": "2023-06-01"},
            "required_headers": {"anthropic-version": {"type": "string", "minLength": 10,
                "maxLength": 10}},
            "value_rules": [{"source": "header", "name": "anthropic-version",
                "predicate": {"kind": "equals", "value": "2023-06-01"}}],
            "request_fields": ["model", "messages.role", "messages.content", "system", "max_tokens", "stream"],
            "field_rules": {"model": _MODEL_RULE, "max_tokens": _TOKEN_RULE,
                "messages": {"type": "array", "required": True, "minItems": 1, "maxItems": 16},
                "messages.role": {"type": "string", "required": True, "enum": ["user", "assistant"]},
                "messages.content": {**_TEXT, "required": True}, "system": _TEXT,
                "stream": {"type": "boolean", "equals": False}},
            "example_body": {"model": {"$scope": "model"},
                "messages": [{"role": "user", "content": "Say hello in one sentence."}],
                "max_tokens": {"$scope": "max_output_tokens"}, "stream": False},
            "notes": [*_COMMON_NOTES, "Uses x-api-key and anthropic-version: 2023-06-01. Multi-workspace selection is not enabled."],
        }],
    },
    {
        "id": "gemini", "label": "Google Gemini", "description": "Generate text using a Gemini Developer API key.",
        "auth_type": "header", "header_name": "x-goog-api-key", "secret_label": "Gemini API key",
        "secret_hint": "Use a Gemini Developer API key; this is separate from Google OAuth and Vertex AI.",
        "sdk_auth_token": "serverware-gemini-placeholder-v1",
        "placeholder": "serverware-gemini-placeholder-v1",
        "operations": [{
            "id": "generate_text_v1", "label": "Generate text", "description": "Text-only generateContent for one exact model.",
            "origin": "https://generativelanguage.googleapis.com",
            "path_template": "/v1beta/models/{model}:generateContent", "methods": ["POST"],
            "scope_fields": [{**_MODEL, "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}, _TOKENS],
            "query_keys": [], "allowed_headers": ["accept", "user-agent", "x-goog-api-client", "x-server-timeout"],
            "request_fields": ["contents.role", "contents.parts.text", "generationConfig.maxOutputTokens"],
            "field_rules": {"contents": {"type": "array", "required": True, "minItems": 1, "maxItems": 16},
                "contents.role": {"type": "string", "enum": ["user", "model"]},
                "contents.parts": {"type": "array", "required": True, "minItems": 1, "maxItems": 16},
                "contents.parts.text": {**_TEXT, "required": True},
                "generationConfig": {"type": "object", "required": True},
                "generationConfig.maxOutputTokens": _TOKEN_RULE},
            "example_body": {"contents": [{"role": "user", "parts": [{"text": "Say hello in one sentence."}]}],
                "generationConfig": {"maxOutputTokens": {"$scope": "max_output_tokens"}}},
            "notes": [*_COMMON_NOTES, "No Vertex AI credentials, tools, cached content or streamGenerateContent endpoint."],
        }],
    },
    {
        "id": "openrouter", "label": "OpenRouter", "description": "Generate text with one exact OpenRouter model ID.",
        "auth_type": "bearer", "header_name": "Authorization", "secret_label": "OpenRouter API key",
        "secret_hint": "Prefer a provider-side credit-limited key; Serverware's output limit is per request.",
        "sdk_auth_token": "serverware-openrouter-placeholder-v1",
        "placeholder": "Bearer serverware-openrouter-placeholder-v1",
        "operations": [{
            "id": "chat_text_v1", "label": "Generate text", "description": "Non-streaming text chat with no model fallback list.",
            "origin": "https://openrouter.ai", "path_template": "/api/v1/chat/completions", "methods": ["POST"],
            "scope_fields": [{**_MODEL,
                "pattern": r"^(?!openrouter/)[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
                "placeholder": "Exact provider/model ID; no auto-router or suffix"}, _TOKENS],
            "query_keys": [], "allowed_headers": _STAINLESS_HEADERS,
            "request_fields": ["model", "messages.role", "messages.content", "max_tokens", "stream"],
            "field_rules": {"model": _MODEL_RULE, "max_tokens": _TOKEN_RULE,
                "messages": {"type": "array", "required": True, "minItems": 1, "maxItems": 16},
                "messages.role": {"type": "string", "required": True, "enum": ["system", "user", "assistant"]},
                "messages.content": {**_TEXT, "required": True},
                "stream": {"type": "boolean", "equals": False}},
            "example_body": {"model": {"$scope": "model"},
                "messages": [{"role": "user", "content": "Say hello in one sentence."}],
                "max_tokens": {"$scope": "max_output_tokens"}, "stream": False},
            "notes": [*_COMMON_NOTES,
                "Use a provider/model ID without suffixes; openrouter/* router aliases are excluded.",
                "No model fallback arrays, provider overrides, plugins or web-search tools."],
        }],
    },
]
