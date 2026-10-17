"""Explicit, local-only conversion of an ordinary private client download.

This is not a policy, credential, signed-record or managed-enrollment migration.
Only known public replacement markers and Gmail recipe identifiers are renamed.
No network library is used, and private values are never printed.
"""
import argparse
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit
from uuid import UUID


LIMIT = 65536
COMMON = {
    "openai": ("Authorization", "Bearer "), "anthropic": ("x-api-key", ""),
    "gemini": ("x-goog-api-key", ""), "openrouter": ("Authorization", "Bearer "),
    "slack": ("Authorization", "Bearer "), "discord": ("Authorization", "Bot "),
    "notion": ("Authorization", "Bearer "), "stripe": ("Authorization", "Bearer "),
    "resend": ("Authorization", "Bearer "), "gitlab": ("PRIVATE-TOKEN", ""),
    "cloudflare": ("Authorization", "Bearer "), "sentry": ("Authorization", "Bearer "),
}
BUNDLES = {
    "github_issues_read_v1": ("github", "token "),
    "github_issues_write_v1": ("github", "token "),
    "gmail_read_v1": ("gmail", "Bearer "),
    "alchemy_chain_status_read_v1": ("alchemy", "Bearer "),
    "x_username_read_v1": ("x", "Bearer "), "x_text_post_v1": ("x-post", "Bearer "),
    "npm_metadata_read_v1": ("npm", "Bearer "), "npm_install_v1": ("npm", "Bearer "),
    "npm_publish_v1": ("npm", "Bearer "),
}
ENVIRONMENT = {
    "SERVERWARE_PROXY_URL": "CATCHPLATE_PROXY_URL", "SERVERWARE_APP_ID": "CATCHPLATE_APP_ID",
    "SERVERWARE_PROXY_TOKEN": "CATCHPLATE_PROXY_TOKEN", "SERVERWARE_CA_FILE": "CATCHPLATE_CA_FILE",
    "SERVERWARE_PROXY_CA_FILE": "CATCHPLATE_PROXY_CA_FILE",
}
INTENT_ENVIRONMENT = {"SERVERWARE_" + key: "CATCHPLATE_" + key for key in (
    "X_POST_TEXT", "X_POST_CONFIRM", "NPM_PACKAGE", "NPM_VERSION", "NPM_PROJECT", "NPM_OUTPUT")}


def require(condition):
    if not condition:
        raise ValueError("Private client configuration cannot be converted")


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def finite(value):
    number = float(value)
    require(math.isfinite(number))
    return number


def forbidden_constant(_value):
    raise ValueError("Non-finite JSON value")


def read_configuration(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= LIMIT
            and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
        raw = source.read(LIMIT + 1)
        after = os.fstat(source.fileno())
        require(len(raw) == info.st_size and
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_float=finite, parse_constant=forbidden_constant)


def https_origin(value):
    require(type(value) is str and 1 <= len(value) <= 2048 and value.isascii()
        and not any(ord(c) < 33 or ord(c) > 126 or c == "\\" for c in value))
    parts = urlsplit(value)
    require(parts.scheme == "https" and parts.hostname and parts.username is None
        and parts.password is None and parts.path in ("", "/") and not parts.query
        and not parts.fragment and "?" not in value and "#" not in value
        and (parts.port is None or 1 <= parts.port <= 65535))
    return value


def convert(config, source_directory, *, proxy_url=None):
    require(type(config) is dict and "schema" not in config
        and not {"expected_policy_hash", "policy_hash", "signature", "signatures", "enrollment_id"}.intersection(config))
    value = deepcopy(config)
    for field in ("application_id", "access_rule_id"):
        require(type(value.get(field)) is str and str(UUID(value[field])) == value[field])
    require(value.get("proxy_authentication") == "basic_and_bearer_v1"
        and value.get("proxy_username") == value["application_id"]
        and type(value.get("proxy_password")) is str and 1 <= len(value["proxy_password"]) <= 8192
        and all(33 <= ord(c) <= 126 for c in value["proxy_password"])
        and type(value.get("token_expires_at_epoch_ms")) is int
        and 0 < value["token_expires_at_epoch_ms"] <= 2**53 - 1
        and value.get("credential_input") == "replace_exact")
    https_origin(value.get("proxy_url"))
    if "app_preset" in value:
        require(value["app_preset"] in COMMON and "operation_bundle" not in value)
        provider = value["app_preset"]
        header, prefix = COMMON[provider]
    else:
        require(value.get("operation_bundle") in BUNDLES)
        provider, prefix = BUNDLES[value["operation_bundle"]]
        header = "Authorization"
    old = "serverware-" + provider + "-placeholder-v1"
    new = "catchplate-" + provider + "-placeholder-v1"
    headers = value.get("request_headers")
    require(type(headers) is dict and all(type(k) is str for k in headers))
    selected = [key for key in headers if key.lower() == header.lower()]
    require(len(selected) == 1 and headers[selected[0]] in (prefix + old, prefix + new))
    headers[selected[0]] = prefix + new
    if "placeholder" in value:
        require(value["placeholder"] in (prefix + old, prefix + new))
        value["placeholder"] = prefix + new
    recipe = value.get("client_recipe", {})
    require(type(recipe) is dict)
    if "sdk_auth_token" in recipe:
        require(recipe["sdk_auth_token"] in (old, new))
        recipe["sdk_auth_token"] = new
    if "schema" in recipe:
        require(value.get("operation_bundle") == "gmail_read_v1"
            and recipe["schema"] in {brand + ".gmailSdkClient/" + version
                for brand in ("serverware", "catchplate") for version in ("v1", "v2")}
            and recipe.get("clear_environment") is True and type(recipe.get("environment")) is dict)
        recipe["schema"] = "catchplate." + recipe["schema"].split(".", 1)[1]
        environment = recipe["environment"]
        for previous, current in ENVIRONMENT.items():
            if previous in environment:
                require(current not in environment)
                environment[current] = environment.pop(previous)
        bindings = {"CATCHPLATE_PROXY_URL": "proxy_url", "CATCHPLATE_APP_ID": "application_id",
            "CATCHPLATE_PROXY_TOKEN": "proxy_password", "CATCHPLATE_CA_FILE": "ca_file",
            "CATCHPLATE_PROXY_CA_FILE": "proxy_ca_file"}
        required = set(bindings) - {"CATCHPLATE_PROXY_CA_FILE"}
        require(required <= set(environment) <= set(bindings) | {"LANG"}
            and environment.get("LANG", "C.UTF-8") == "C.UTF-8")
        require(all(environment.get(key) == value.get(field) for key, field in bindings.items()))
    for field in ("required_environment", "required_local_environment"):
        if field in recipe:
            require(type(recipe[field]) is list and all(type(key) is str for key in recipe[field]))
            recipe[field] = [INTENT_ENVIRONMENT.get(key, key) for key in recipe[field]]
    # Retain each original CA file, even if its filename contains the former name.
    # Absolute paths keep trust unchanged when output goes in a different folder.
    for container, fields in ((value, ("ca_file", "proxy_ca_file")),
            (recipe, ("proxy_ca_file", "destination_ca_file", "extra_ca_file"))):
        for field in fields:
            if field in container and container[field] is not None:
                path = container[field]
                require(type(path) is str and 0 < len(path) <= 4096
                    and not any(ord(c) < 32 or ord(c) == 127 for c in path))
                container[field] = os.path.abspath(os.path.join(source_directory, path))
    require(type(value.get("ca_file")) is str)
    if proxy_url is not None:
        value["proxy_url"] = https_origin(proxy_url)
    if "schema" in recipe:
        for key, field in bindings.items():
            if key in recipe["environment"]:
                recipe["environment"][key] = value.get(field)
    return value


def migrate(source, destination, *, proxy_url=None):
    source = Path(source).absolute()
    value = convert(read_configuration(source), source.parent, proxy_url=proxy_url)
    encoded = (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    require(len(encoded) <= LIMIT)
    # Never overwrite the original, an existing output, or a symlink.
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert an ordinary private download locally; no network, token rotation or expiry extension.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--proxy-url", help="Explicit new HTTPS proxy origin, only after the operator confirms cutover")
    args = parser.parse_args(argv)
    try:
        migrate(args.input, args.output, proxy_url=args.proxy_url)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        print("Conversion refused. Use a private regular input file (chmod 600), a new output path and a supported ordinary download. Signed, ECR, managed or custom configurations need a new operator handoff. No request was sent or token rotated.", file=sys.stderr)
        return 2
    print("Converted private configuration without changing token, expiry or permissions. No request was sent. Confirm operator cutover and CA trust before use; update the MCP --config path explicitly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
