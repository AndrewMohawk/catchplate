"""Typed operations over private Serverware downloads, independent of MCP transport.

Only fixed, checked-in adapters may derive wire requests. Discovery and preparation
do no network I/O. Provider results remain untrusted data, not instructions.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import importlib.util
import json
from pathlib import Path
import re
import sys
import time


def _module(name, path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ROOT = Path(__file__).resolve().parents[2]
_http = _module("serverware_mcp_request", _ROOT / "examples/common-apps/request.py")
_PRESETS = {
    app["id"]: app
    for name in ("operator_common_apps_ai", "operator_common_apps_services")
    for app in _module("serverware_mcp_" + name, _ROOT / "serverware" / (name + ".py")).PRESETS
}
_ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,47}")
_INVALID = "Invalid, unsupported, or expired Serverware operation configuration or arguments."
_INTENT = "This action requires operator opt-in and explicit confirmation; proxy approval still applies."


class OperationError(ValueError):
    """Fixed public message, never private paths, tokens, or request contents."""


def _legacy():
    return _module("serverware_mcp_legacy", Path(__file__).with_name("legacy.py"))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _resolve(value, scope):
    if type(value) is dict:
        if set(value) == {"$scope"}:
            return scope[value["$scope"]]
        return {key: _resolve(item, scope) for key, item in value.items()}
    if type(value) is list:
        return [_resolve(item, scope) for item in value]
    return value


def _object(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


def _text(maximum=2048, *, pattern=None):
    result = {"type": "string", "minLength": 1, "maxLength": maximum}
    if pattern:
        result["pattern"] = pattern
    return result


def _integer(maximum=100, minimum=1):
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


def _check(schema, value):
    """Validate the small closed JSON Schema subset emitted by our adapters."""
    kind = schema["type"]
    if kind == "object":
        if (type(value) is not dict or set(value) - set(schema["properties"])
                or set(schema["required"]) - set(value)):
            raise ValueError()
        for key, item in value.items():
            _check(schema["properties"][key], item)
        if "oneOf" in schema and sum(all(key in value for key in part["required"])
                                     for part in schema["oneOf"]) != 1:
            raise ValueError()
    elif kind == "array":
        if type(value) is not list or not schema["minItems"] <= len(value) <= schema["maxItems"]:
            raise ValueError()
        for item in value:
            _check(schema["items"], item)
    elif kind == "string":
        if (type(value) is not str or not schema.get("minLength", 0) <= len(value) <= schema["maxLength"]
                or "pattern" in schema and re.fullmatch(schema["pattern"], value) is None):
            raise ValueError()
    elif kind == "integer":
        if type(value) is not int or not schema["minimum"] <= value <= schema["maximum"]:
            raise ValueError()
    else:
        raise ValueError()
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError()


def _common(config):
    app = _PRESETS[config["app_preset"]]
    operation = next(item for item in app["operations"] if item["id"] == config["app_operation"])
    scope = config["scope"]
    if set(scope) != {item["key"] for item in operation["scope_fields"]}:
        raise ValueError()
    for item in operation["scope_fields"]:
        value = scope[item["key"]]
        if item["type"] == "number":
            _check(_integer(item["max"], item["min"]), value)
        else:
            _check(_text(256, pattern=item.get("pattern")), value)
            if not value.isascii():
                raise ValueError()
    expected_headers = {app["header_name"].lower(): app["placeholder"],
                        **{key.lower(): value for key, value in operation.get("request_headers", {}).items()}}
    if (config["upstream_url"] != operation["origin"] + operation["path_template"].format(**scope)
            or config["methods"] != operation["methods"]
            or config.get("query_keys") != operation["query_keys"]
            or config["request_query"] != _resolve(operation.get("example_query", {}), scope)
            or {key.lower(): value for key, value in config["request_headers"].items()} != expected_headers):
        raise ValueError()
    return app, operation


def _input_schema(app, operation, scope):
    provider = app["id"]
    fields = operation["field_rules"]
    if provider in {"openai", "anthropic", "gemini", "openrouter"}:
        text_field = "input" if provider == "openai" else "contents.parts.text" if provider == "gemini" else "messages.content"
        token_field = "max_output_tokens" if provider == "openai" else "generationConfig.maxOutputTokens" if provider == "gemini" else "max_tokens"
        properties = {"prompt": _text(fields[text_field]["maxLength"]),
            "output_tokens": _integer(scope["max_output_tokens"], fields[token_field]["min"])}
        if provider == "openai":
            properties["instructions"] = _text(fields["instructions"]["maxLength"])
            return _object(properties, ["prompt"])
        roles = fields["contents.role" if provider == "gemini" else "messages.role"]["enum"]
        message_rule = fields["contents" if provider == "gemini" else "messages"]
        properties["messages"] = {"type": "array", "minItems": message_rule["minItems"], "maxItems": message_rule["maxItems"],
            "items": _object({"role": {**_text(16), "enum": roles},
                "content": _text(fields[text_field]["maxLength"])}, ["role", "content"])}
        if provider == "anthropic":
            properties["system"] = _text(fields["system"]["maxLength"])
        return {**_object(properties), "oneOf": [{"required": ["prompt"]}, {"required": ["messages"]}]}
    if provider in {"slack", "discord"}:
        source = fields["text" if provider == "slack" else "content"]
        properties = {"text": _text(source["maxLength"])}
        if provider == "slack":
            properties["thread_ts"] = _text(fields["thread_ts"]["maxLength"], pattern=fields["thread_ts"]["pattern"])
        return _object(properties, ["text"])
    if provider == "resend":
        return _object({key: _text(fields[key]["maxLength"]) for key in ("subject", "text")}, ["subject", "text"])
    # Only query keys already allowed by this exact reviewed operation are exposed.
    properties = {}
    for key in operation["query_keys"]:
        if key in _resolve(operation.get("example_query", {}), scope):
            continue
        properties[key] = (_integer(10000 if key == "page" else 100)
                           if key in {"limit", "page", "per_page", "page_size"} else _text())
    return _object(properties)


def _describe_common(config, alias):
    app, operation = _common(config)
    return {"id": alias, "provider": app["id"], "label": app["label"] + ": " + operation["label"],
        "effect": "action" if config["methods"] == ["POST"] else "read",
        "scope": deepcopy(config["scope"]), "input_schema": _input_schema(app, operation, config["scope"]),
        "limits": {"max_request_bytes": _http.MAX_BODY_BYTES,
            "max_response_bytes": _http.MAX_RESPONSE_BYTES, "automatic_retries": 0,
            **({"max_output_tokens": config["scope"]["max_output_tokens"]}
               if "max_output_tokens" in config["scope"] else {})}}


def _prepare_common(config, arguments):
    app, operation = _common(config)
    _check(_input_schema(app, operation, config["scope"]), arguments)
    provider, scope = app["id"], config["scope"]
    if config["methods"] == ["GET"]:
        return config, None, tuple(key + "=" + str(value) for key, value in sorted(arguments.items()))
    if provider == "openai":
        body = {"model": scope["model"], "input": arguments["prompt"], "stream": False, "store": False,
                "max_output_tokens": arguments.get("output_tokens", scope["max_output_tokens"])}
        if "instructions" in arguments:
            body["instructions"] = arguments["instructions"]
    elif provider in {"anthropic", "gemini", "openrouter"}:
        messages = arguments.get("messages", [{"role": "user", "content": arguments.get("prompt")}])
        tokens = arguments.get("output_tokens", scope["max_output_tokens"])
        if provider == "gemini":
            body = {"contents": [{"role": item["role"], "parts": [{"text": item["content"]}]} for item in messages],
                    "generationConfig": {"maxOutputTokens": tokens}}
        else:
            body = {"model": scope["model"], "messages": messages, "max_tokens": tokens, "stream": False}
            if "system" in arguments:
                body["system"] = arguments["system"]
    elif provider == "slack":
        body = {"channel": scope["channel"], "text": arguments["text"], "unfurl_links": False, "unfurl_media": False}
        if "thread_ts" in arguments:
            body["thread_ts"] = arguments["thread_ts"]
    elif provider == "discord":
        body = {"content": arguments["text"], "allowed_mentions": {"parse": []}}
    elif provider == "resend":
        body = {"from": scope["sender"], "to": scope["recipient"], **arguments}
    else:
        raise ValueError()
    raw = _canonical(body)
    if not 0 < len(raw) <= _http.MAX_BODY_BYTES:
        raise ValueError()
    return config, raw, ()


@dataclass(repr=False)
class PreparedRequest:
    """Private one-shot request; plain fields support an isolated spawn worker.

    A timeout or interrupted action has an uncertain outcome. Reconstructing a
    request explicitly is allowed, but neither this class nor its transport
    performs a retry or treats caller confirmation as proxy approval.
    """
    operation_id: str
    effect: str
    console_origin: str | None
    _config: dict = field(repr=False)
    _body: bytes | None = field(repr=False)
    _query: tuple[str, ...] = field(repr=False)
    _used: bool = field(default=False, init=False, repr=False)

    @property
    def provider(self):
        """Public identity from a validated fixed preset, never caller arguments."""
        common = self._config.get("app_preset")
        if common in _PRESETS:
            return common
        return {"github_issues_read_v1": "github", "github_issues_write_v1": "github",
            "gmail_read_v1": "gmail", "alchemy_chain_status_read_v1": "alchemy",
            "x_username_read_v1": "x_lookup", "x_text_post_v1": "x_post",
            "npm_metadata_read_v1": "npm"}.get(self._config.get("operation_bundle"))

    def execute(self):
        if self._used:
            raise OperationError("A prepared operation can only be executed once; no automatic retry is allowed.")
        self._used = True
        if self._config["token_expires_at_epoch_ms"] <= time.time_ns() // 1000000:
            raise OperationError(_INVALID)
        if "_legacy_runner" in self._config:
            if self._config["_legacy_runner"] != "npm_metadata":
                raise OperationError(_INVALID)
            return _legacy().execute_external(self._config)
        # Verify the installed wire dependencies before opening a session.
        try:
            _http.check_versions()
        except Exception:
            pass
        else:
            return _http.execute_body(self._config, self._body,
                                      self._config["methods"] == ["POST"], self._query)
        raise OperationError("Install the pinned MCP client dependencies before executing operations.")


class OperationSet:
    def __init__(self, configs: dict[str, Path], *, allow_actions: set[str], console_origin: str | None):
        valid = False
        try:
            if (type(configs) is not dict or not 1 <= len(configs) <= 32
                    or any(type(alias) is not str or _ALIAS.fullmatch(alias) is None
                           or not isinstance(path, Path) for alias, path in configs.items())
                    or type(allow_actions) is not set or not allow_actions <= set(configs)):
                raise ValueError()
            if console_origin is not None:
                _http.https_url(console_origin, origin=True)
                console_origin = console_origin.rstrip("/")
            self._paths = {alias: path.absolute() for alias, path in configs.items()}
            self._allow_actions = frozenset(allow_actions)
            self._console_origin = console_origin
            valid = True
        except Exception:
            pass
        if not valid:
            raise OperationError(_INVALID)

    def _load(self, alias):
        path = self._paths[alias]
        # Dispatch only. The selected strict loader independently re-reads the
        # file; its actual output determines the adapter and is validated again.
        raw = _http.strict_json(_http.read_file(path, _http.MAX_CONFIG_BYTES).decode("utf-8"))
        if type(raw) is not dict:
            raise ValueError()
        if "app_preset" in raw:
            config = _http.load_configuration(path)
            _common(config)
            return config, [_describe_common(config, alias)], False
        config = _legacy().load_configuration(path)
        return config, _legacy().describe(config, alias), True

    def describe(self):
        result = None
        try:
            result = []
            for alias in sorted(self._paths):
                _, descriptors, _ = self._load(alias)
                for descriptor in descriptors:
                    item = deepcopy(descriptor)
                    item["limits"]["actions_enabled"] = alias in self._allow_actions
                    result.append(item)
        except Exception:
            result = None
        if result is None:
            raise OperationError(_INVALID)
        return result

    def prepare(self, operation_id: str, arguments: dict, *, action: bool = False, confirmed: bool = False):
        prepared, intent_error = None, False
        try:
            if (type(operation_id) is not str or len(operation_id) > 128 or type(arguments) is not dict
                    or type(action) is not bool or type(confirmed) is not bool
                    or len(_canonical(arguments)) > _http.MAX_BODY_BYTES):
                raise ValueError()
            alias = operation_id.partition(".")[0]
            config, descriptors, legacy = self._load(alias)
            descriptor = next(item for item in descriptors if item["id"] == operation_id)
            if descriptor["effect"] == "action":
                if not action or not confirmed or alias not in self._allow_actions:
                    intent_error = True
                    raise ValueError()
            elif descriptor["effect"] != "read" or action or confirmed:
                raise ValueError()
            if legacy:
                config, body, query = _legacy().prepare(config, operation_id, alias, arguments)
            else:
                config, body, query = _prepare_common(config, arguments)
            prepared = PreparedRequest(operation_id, descriptor["effect"], self._console_origin,
                                       deepcopy(config), body, tuple(query))
        except Exception:
            pass
        if prepared is None:
            raise OperationError(_INTENT if intent_error else _INVALID)
        return prepared
