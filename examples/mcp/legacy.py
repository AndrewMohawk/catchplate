"""Typed adapters for existing downloaded permissions; no caller-selected URLs.

Only the operator-selected configuration loader reads a path. Descriptors never
contain proxy logins, and request preparation never opens a provider connection.
The existing proxy remains the authority for scope, approval and credential use.
"""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.parse import quote, urlencode
from uuid import UUID


_SPEC = importlib.util.spec_from_file_location("legacy_common_request",
    Path(__file__).resolve().parents[1] / "common-apps" / "request.py")
_HTTP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HTTP)
MAX_BODY = 65536
OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
PACKAGE = r"(?:[a-z0-9][a-z0-9._-]*|@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*)"
BUNDLES = {
    "github_issues_read_v1", "github_issues_write_v1", "gmail_read_v1",
    "alchemy_chain_status_read_v1", "x_username_read_v1", "x_text_post_v1",
    "npm_metadata_read_v1",
}
# Resolve operator-installed runtime before the per-call worker clears its env.
# The standard pinned nvm install avoids a PATH wrapper depending on HOME.
_NVM_NODE = Path.home() / ".nvm" / "versions" / "node" / "v25.5.0" / "bin" / "node"
_NODE_CANDIDATE = str(_NVM_NODE) if _NVM_NODE.is_file() else shutil.which("node")
NODE_EXECUTABLE = str(Path(_NODE_CANDIDATE).resolve()) if _NODE_CANDIDATE else None
NPM_CLIENT = Path(__file__).resolve().parents[1] / "npm-registry" / "client.mjs"


class LegacyConfigurationError(ValueError):
    def __init__(self):
        super().__init__("Unsupported, expired or invalid downloaded Serverware permission.")


class LegacyArgumentError(ValueError):
    def __init__(self):
        super().__init__("Arguments do not match this configured Serverware operation; nothing was sent.")


class NpmMetadataError(ValueError):
    def __init__(self):
        super().__init__("npm metadata did not complete. Check Node 25.5.0, the locked npm example dependencies, the application login and Serverware's audit/Pending actions. Nothing was retried.")


def _require(value):
    if not value:
        raise ValueError("Legacy operation contract refused")


def _text(value, minimum=1, maximum=4096, *, query=False, pattern=None):
    _require(type(value) is str and minimum <= len(value.encode("utf-8")) <= maximum and "\x00" not in value)
    if query:
        _require(not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c == "\\" for c in value))
    if pattern is not None:
        _require(re.fullmatch(pattern, value) is not None)
    return value


def _integer(value, maximum=9007199254740991):
    _require(type(value) is int and 1 <= value <= maximum)
    return value


def _enum(value, choices):
    _require(type(value) is str and value in choices)
    return value


def _fresh(config):
    expiry = config.get("token_expires_at_epoch_ms")
    _require(type(expiry) is int and time.time_ns() // 1000000 < expiry <= 2**53 - 1)


def _gmail_age_policy(config):
    value = config.get("age_policy", {"mode": "unrestricted"})
    _require(type(value) is dict)
    if value == {"mode": "unrestricted"}:
        return value
    _require(set(value) == {"mode", "max_age_days"} and value["mode"] == "recent_internal_date_v1")
    _integer(value["max_age_days"], 3650)
    return value


def _family(config):
    _fresh(config)
    bundle = config.get("operation_bundle")
    _require(type(bundle) is str and bundle in BUNDLES and "app_preset" not in config)
    _require(config.get("credential_input") == "replace_exact")
    methods, mode, placeholder = ["GET"], None, None
    if bundle.startswith("github_issues_"):
        repo = config.get("repository")
        _require(type(repo) is dict and set(repo) == {"owner", "name"})
        _text(repo["owner"], maximum=39, pattern=OWNER)
        _text(repo["name"], maximum=100, pattern=r"[A-Za-z0-9_.-]{1,100}")
        _require(repo["name"] not in {".", ".."} and config.get("query_mode") == "githubRestV1"
            and config.get("request_body_mode") == "preserve_json_v1")
        target = "https://api.github.com/repos/" + repo["owner"] + "/" + repo["name"] + "/issues"
        methods = ["GET"] if bundle == "github_issues_read_v1" else ["GET", "POST"]
        provider, scope = "github", {"repository": deepcopy(repo)}
        mode, placeholder = "unfiltered_json_or_empty_v2", "token serverware-github-placeholder-v1"
    elif bundle == "gmail_read_v1":
        policy = _gmail_age_policy(config)
        _require(config.get("query_mode") == "orderedFormV1")
        target = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        provider, scope = "gmail", {"account": "me", "age_policy": deepcopy(policy)}
        mode, placeholder = "gmail_read_json_v1", "Bearer serverware-gmail-placeholder-v1"
    elif bundle == "alchemy_chain_status_read_v1":
        chain = _enum(config.get("chain"), {"eth-mainnet", "eth-sepolia"})
        _require(config.get("rpc_methods") == ["eth_chainId", "eth_blockNumber"])
        target = "https://" + chain + ".g.alchemy.com/v2"
        provider, scope, methods = "alchemy", {"chain": chain}, ["POST"]
        mode, placeholder = "alchemy_rpc_read_json_v1", "Bearer serverware-alchemy-placeholder-v1"
    elif bundle == "x_username_read_v1":
        username = _text(config.get("username"), maximum=15, pattern=r"[a-z0-9_]{1,15}")
        target = "https://api.x.com/2/users/by/username/" + username
        provider, scope = "x_lookup", {"username": username}
        mode, placeholder = "x_app_read_json_v1", "Bearer serverware-x-placeholder-v1"
    elif bundle == "x_text_post_v1":
        target = "https://api.x.com/2/tweets"
        provider, scope, methods = "x_post", {"operation": "text_only_post"}, ["POST"]
        mode, placeholder = "x_post_json_v1", "Bearer serverware-x-post-placeholder-v1"
    else:
        packages = config.get("packages")
        _require(type(packages) is list and 1 <= len(packages) <= 64
            and all(type(p) is str and 1 <= len(p) <= 214 and re.fullmatch(PACKAGE, p) for p in packages)
            and packages == sorted(set(packages)))
        recipe = config.get("client_recipe")
        _require(type(recipe) is dict and recipe.get("package") in packages)
        target = "https://registry.npmjs.org/"
        provider, scope = "npm", {"package": recipe["package"]}
        mode, placeholder = "npm_metadata_json_v1", "Bearer serverware-npm-placeholder-v1"
    _require(config.get("upstream_url") == target and config.get("methods") == methods
        and config.get("response_mode") == mode)
    supplied = config.get("request_headers")
    _require(type(supplied) is dict and all(type(k) is str and type(v) is str for k, v in supplied.items()))
    headers = {k.lower(): v for k, v in supplied.items()}
    _require(len(headers) == len(supplied) and set(headers) <= {"authorization", "content-type"}
        and headers.get("authorization") == placeholder
        and ("content-type" not in headers or headers["content-type"] == "application/json"))
    return provider, scope, {"Authorization": placeholder}


def load_configuration(path):
    """Read one operator-selected private download; unsupported families refuse."""
    try:
        path = Path(path).absolute()
        config = _HTTP.strict_json(_HTTP.read_file(path, _HTTP.MAX_CONFIG_BYTES).decode("utf-8"))
        _require(type(config) is dict)
        for field in ("application_id", "access_rule_id"):
            _require(type(config.get(field)) is str and str(UUID(config[field])) == config[field])
        _require(config.get("proxy_authentication") == "basic_and_bearer_v1"
            and config.get("proxy_username") == config["application_id"])
        token = config.get("proxy_password")
        _require(type(token) is str and 1 <= len(token) <= 8192 and all(33 <= ord(c) <= 126 for c in token))
        proxy = _HTTP.https_url(config.get("proxy_url"), origin=True)
        recipe = config.get("client_recipe", {})
        _require(type(recipe) is dict)
        for field in ("ca_file", "proxy_ca_file"):
            value = config.get(field, recipe.get(field))
            if field == "proxy_ca_file" and value is None:
                config[field] = None
            else:
                _text(value, maximum=4096, query=True)
                config[field] = str((path.parent / value).resolve())
        _family(config)
        # Downloaded data cannot select an executable or an alternate runner.
        # Only our parent-process prepare step may add these private dispatch hints.
        config.pop("_npm_node_executable", None)
        config.pop("_legacy_runner", None)
        config["_config_path"] = str(path)
        config["_proxy_url"] = "https://" + quote(config["proxy_username"], safe="") + ":" + quote(token, safe="") + "@" + proxy.netloc
        return config
    except Exception:
        pass
    raise LegacyConfigurationError()


def _string(maximum=4096, *, enum=None, default=None):
    result = {"type": "string", "maxLength": maximum}
    if enum is not None:
        result["enum"] = list(enum)
    if default is not None:
        result["default"] = default
    return result


def _number(maximum, default=None):
    value = {"type": "integer", "minimum": 1, "maximum": maximum}
    if default is not None:
        value["default"] = default
    return value


def _definition(suffix, label, properties=None, required=(), effect="read"):
    return {"suffix": suffix, "label": label, "effect": effect, "input_schema": {
        "type": "object", "properties": properties or {}, "required": list(required), "additionalProperties": False}}


def _definitions(provider, config):
    page = {"page": _number(1000000, 1), "per_page": _number(100, 30)}
    issue = {"issue_number": _number(9007199254740991)}
    if provider == "github":
        result = [
            _definition("github_list_issues", "List repository issues", {**page,
                "state": _string(enum=("open", "closed", "all"), default="open"),
                "sort": _string(enum=("created", "updated", "comments"), default="updated"),
                "direction": _string(enum=("asc", "desc"), default="desc"), "labels": _string(1024)}),
            _definition("github_get_issue", "Read one repository issue", issue, ("issue_number",)),
            _definition("github_list_comments", "List one issue's comments", {**issue, **page}, ("issue_number",)),
        ]
        if config["operation_bundle"] == "github_issues_write_v1":
            result.extend([
                _definition("github_create_issue", "Create an issue in the configured repository",
                    {"title": _string(1024), "body": _string(60000)}, ("title",), "action"),
                _definition("github_create_comment", "Add a comment to one issue",
                    {**issue, "body": _string(60000)}, ("issue_number", "body"), "action"),
            ])
        return result
    if provider == "gmail":
        policy = _gmail_age_policy(config)
        restricted = policy["mode"] == "recent_internal_date_v1"
        query = _string(2048)
        query["description"] = "Optional caller-selected Gmail query; not proof of message age. Reuse it unchanged with page_token."
        if restricted:
            cutoff = (time.time_ns() // 1000000 - policy["max_age_days"] * 86400000 + 999) // 1000
            query["examples"] = ["after:" + str(cutoff)]
        return [
            _definition("gmail_list_messages", "List Gmail message IDs (one page)", {
                "max_results": _number(32 if restricted else 500, 10), "q": query, "page_token": _string(4096),
                "label_ids": {"type": "array", "minItems": 0, "maxItems": 32, "items": _string(128)}}),
            _definition("gmail_get_message", "Read one Gmail message", {
                "message_id": _string(512), "format": _string(enum=("metadata", "full"), default="metadata"),
                "metadata_headers": {"type": "array", "minItems": 0, "maxItems": 32, "items": _string(128)}}, ("message_id",)),
        ]
    if provider == "alchemy":
        return [_definition("alchemy_chain_id", "Read the configured chain ID"),
            _definition("alchemy_block_number", "Read the configured chain's latest block number")]
    if provider == "x_lookup":
        return [_definition("x_lookup_username", "Look up the exact configured X username")]
    if provider == "x_post":
        return [_definition("x_create_post", "Publish one text-only X post",
            {"text": _string(16384)}, ("text",), "action")]
    return [_definition("npm_metadata", "Read metadata for the configured npm package")]


def describe(config, alias):
    try:
        provider, scope, _ = _family(config)
        _require(type(alias) is str and 1 <= len(alias) <= 128)
        return [{"id": alias + "." + item["suffix"], "provider": provider,
            "label": item["label"], "effect": item["effect"], "scope": deepcopy(scope),
            "input_schema": deepcopy(item["input_schema"]), "limits": {
                "max_request_bytes": 32768 if provider == "x_post" else MAX_BODY,
                "max_response_bytes": 65536 if provider == "alchemy" else 1048576,
                "automatic_retries": 0, "automatic_pagination": False}}
            for item in _definitions(provider, config)]
    except Exception:
        pass
    raise LegacyConfigurationError()


def _wire(pairs):
    # This list is deliberately not sorted/deduplicated. Gmail permits repeated
    # labelIds/metadataHeaders and binds this exact ordered form-query wire.
    raw = urlencode(pairs)
    _require(len(raw) <= 8192 and len(pairs) <= 64)
    return "?" + raw if raw else ""


def _json_bytes(value, maximum=MAX_BODY):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    _require(0 < len(raw) <= maximum)
    return raw


def _prepare(config, operation_id, alias, arguments):
    provider, _scope, headers = _family(config)
    _require(type(arguments) is dict)
    specs = {alias + "." + item["suffix"]: item for item in _definitions(provider, config)}
    _require(type(operation_id) is str and operation_id in specs)
    spec = specs[operation_id]
    schema = spec["input_schema"]
    _require(set(arguments) <= set(schema["properties"]) and set(schema["required"]) <= set(arguments))
    suffix = spec["suffix"]
    target, method, body, pairs = config["upstream_url"], "GET", None, []
    if provider == "github":
        headers.update(Accept="application/vnd.github+json", **{"X-GitHub-Api-Version": "2022-11-28"})
        if suffix in {"github_get_issue", "github_list_comments", "github_create_comment"}:
            target += "/" + str(_integer(arguments["issue_number"]))
        if suffix in {"github_list_comments", "github_create_comment"}:
            target += "/comments"
        if suffix in {"github_list_issues", "github_list_comments"}:
            pairs = [("page", str(_integer(arguments.get("page", 1), 1000000))),
                ("per_page", str(_integer(arguments.get("per_page", 30), 100)))]
        if suffix == "github_list_issues":
            pairs += [("state", _enum(arguments.get("state", "open"), {"open", "closed", "all"})),
                ("sort", _enum(arguments.get("sort", "updated"), {"created", "updated", "comments"})),
                ("direction", _enum(arguments.get("direction", "desc"), {"asc", "desc"}))]
            if "labels" in arguments:
                pairs.append(("labels", _text(arguments["labels"], maximum=1024, query=True)))
        if suffix == "github_create_issue":
            value = {"title": _text(arguments["title"], maximum=1024)}
            if "body" in arguments:
                value["body"] = _text(arguments["body"], minimum=0, maximum=60000)
            method, body = "POST", _json_bytes(value)
        elif suffix == "github_create_comment":
            method, body = "POST", _json_bytes({"body": _text(arguments["body"], maximum=60000)})
    elif provider == "gmail":
        if suffix == "gmail_list_messages":
            maximum = 32 if _gmail_age_policy(config)["mode"] == "recent_internal_date_v1" else 500
            pairs = [("maxResults", str(_integer(arguments.get("max_results", 10), maximum))), ("includeSpamTrash", "false")]
            labels = arguments.get("label_ids", [])
            _require(type(labels) is list and len(labels) <= 32)
            pairs.extend(("labelIds", _text(value, maximum=128, pattern=r"[A-Za-z0-9_-]{1,128}")) for value in labels)
            for arg, key, minimum, maximum in (("q", "q", 0, 2048), ("page_token", "pageToken", 1, 4096)):
                if arg in arguments:
                    pairs.append((key, _text(arguments[arg], minimum, maximum, query=True)))
        else:
            target += "/" + _text(arguments["message_id"], maximum=512, pattern=r"[A-Za-z0-9_-]{1,512}")
            mode = _enum(arguments.get("format", "metadata"), {"metadata", "full"})
            pairs = [("format", mode)]
            fields = arguments.get("metadata_headers", ["From", "Subject", "Date"] if mode == "metadata" else [])
            _require(type(fields) is list and len(fields) <= 32 and (mode == "metadata" or not fields))
            pairs.extend(("metadataHeaders", _text(value, maximum=128,
                pattern=r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")) for value in fields)
    elif provider == "alchemy":
        rpc = "eth_chainId" if suffix == "alchemy_chain_id" else "eth_blockNumber"
        method, body = "POST", _json_bytes({"jsonrpc": "2.0", "id": 1, "method": rpc, "params": []})
    elif provider == "x_post":
        method, body = "POST", _json_bytes({"text": _text(arguments["text"], maximum=16384)}, 32768)
    elif provider == "npm":
        result = deepcopy(config)
        result["_legacy_runner"] = "npm_metadata"
        result["_npm_node_executable"] = NODE_EXECUTABLE
        return result, None, ()
    result = deepcopy(config)
    result.update(upstream_url=target + _wire(pairs), methods=[method], request_headers=headers,
        request_query={}, query_keys=[])
    return result, body, ()


def prepare(config, operation_id, alias, arguments):
    """Compile typed arguments into one exact request; no dispatch or retries."""
    try:
        return _prepare(config, operation_id, alias, arguments)
    except Exception:
        pass
    raise LegacyArgumentError()


def execute_external(config):
    """Only fixed npm metadata view, under the MCP supervisor's owned group.

    Parent-owned scratch and whole-group cleanup on every exit are prerequisites;
    this function cannot be used as an uncontained generic subprocess launcher.
    Neither the executable, script, config path nor subcommand is a tool input.
    """
    try:
        provider, scope, _ = _family(config)
        _require(provider == "npm" and config.get("_legacy_runner") == "npm_metadata")
        # Spawn workers clear ambient environment before lazy imports. Preserve
        # the parent's fixed runtime selection in trusted prepared data instead
        # of resolving PATH again here. The download loader strips this field.
        node = config.get("_npm_node_executable")
        _require(type(node) is str and Path(node).is_absolute() and str(Path(node).resolve()) == node
            and Path(node).is_file() and os.access(node, os.X_OK))
        selected = load_configuration(config["_config_path"])
        _require(all(selected.get(key) == config.get(key) for key in (
            "application_id", "access_rule_id", "operation_bundle", "packages", "client_recipe",
            "proxy_url", "proxy_password", "ca_file", "proxy_ca_file")))
        temporary = os.environ.get("SERVERWARE_MCP_CALL_TEMP", "")
        _require(temporary and Path(temporary).is_absolute() and Path(temporary).is_dir()
            and not Path(temporary).is_symlink() and Path(temporary).stat().st_mode & 0o777 == 0o700)
        _require(os.getsid(0) == os.getpid() and os.getpgrp() == os.getpid())
        result = subprocess.run([node, str(NPM_CLIENT), "--config", selected["_config_path"], "view"],
            cwd=NPM_CLIENT.parent, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                "TMPDIR": temporary, "SERVERWARE_MCP_CONTAINED_WORKER": "1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=25, check=False, start_new_session=False)
        _require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 16384)
        value = _HTTP.strict_json(result.stdout.decode("utf-8"))
        _require(type(value) is dict and set(value) == {"ok", "operation", "package", "version", "tarballFetched"}
            and value["ok"] is True and value["operation"] == "view" and value["package"] == scope["package"]
            and value["tarballFetched"] is False and type(value["version"]) is str
            and len(value["version"]) <= 128 and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value["version"]))
        return {"status": 200, "response": value}
    except Exception:
        pass
    raise NpmMetadataError()
