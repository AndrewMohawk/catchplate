"""Closed, byte-preserving Alchemy chain-status JSON-RPC contract.

Only two fixed read methods are admitted, despite their HTTP POST transport.
HTTP 200 may carry an RPC error; admission is not provider success or account
ownership. Result values, extra response members and error data are preserved,
not projected. This module performs no custody, network or clock operations.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from catchplate.host_trusted_approval_policy import provider_constraints

ADAPTER = "alchemy.rpc_read.v1"
MODE = "alchemyRpcReadJsonV1"
CONTENT_TYPE_POLICY = "alchemyRpcReadJsonUtf8V1"
OPERATION = "alchemy.rpc.read"
OPERATION_FIELDS = frozenset({"operation", "chain", "method", "requestId"})
CHAINS = ("eth-mainnet", "eth-sepolia")
METHODS = ("eth_chainId", "eth_blockNumber")
PLACEHOLDER = "catchplate-alchemy-placeholder-v1"
REPLACEMENT = {"mode": "replaceExact", "expectedValue": "Bearer " + PLACEHOLDER}
REQUEST_HEADERS = ["accept", "accept-language", "alchemy-ethers-sdk-method",
    "alchemy-ethers-sdk-version", "sec-fetch-mode", "user-agent"]
CONTENT_TYPES = ["application/json"]
STATUSES = [200, 400, 401, 403, 404, 429, 500, 502, 503, 504]
MAX_REQUEST_BODY_BYTES = 65536
MAX_RESPONSE_BYTES = 65536
MAX_ERROR_BYTES = 65536
MAX_REQUEST_ID = (1 << 53) - 1


def _require(condition):
    if not condition:
        raise ValueError("Alchemy RPC read contract refused")


def validate_chain(value):
    _require(isinstance(value, str) and value in CHAINS)
    return value


def validate_token(value):
    # Opaque provider material: no decoding, prefix guessing or entitlement call.
    _require(isinstance(value, str) and 1 <= len(value) <= 8192
        and all(33 <= ord(character) <= 126 for character in value))
    return value


def host(chain):
    return validate_chain(chain) + ".g.alchemy.com"


def origin(chain):
    return "https://" + host(chain)


def route_paths(chain):
    validate_chain(chain)
    return ["/v2"]


def request_profile():
    return {"allowedHeaders": list(REQUEST_HEADERS), "discardHeaders": ["accept-encoding"],
        "allowedQueryKeys": [], "allowedMediaTypes": list(CONTENT_TYPES),
        "maxBodyBytes": MAX_REQUEST_BODY_BYTES, "valueRules": []}


def response_profile():
    return {"mode": MODE, "maxBodyBytes": MAX_RESPONSE_BYTES,
        "contentTypes": list(CONTENT_TYPES), "allowedHeaders": [],
        "error": {"mode": MODE, "maxBodyBytes": MAX_ERROR_BYTES,
            "contentTypes": list(CONTENT_TYPES), "allowedHeaders": [], "onInvalid": "block"}}


def response_envelope(identifier):
    return {"id": identifier, "type": "responseEnvelope", "phase": "response",
        "statusCodes": list(STATUSES), "bodyPresence": "required",
        "contentTypes": list(CONTENT_TYPES), "allowedResponseHeaderNames": [],
        "responseHeaderRules": [], "unlistedHeaderPolicy": "discardUnselectedV1",
        "contentTypePolicy": CONTENT_TYPE_POLICY}


def validate_response_profile(response, constraints=None):
    _require(response == response_profile() and type(response["maxBodyBytes"]) is int
        and type(response["error"]["maxBodyBytes"]) is int)
    if constraints is not None:
        constraints = provider_constraints(constraints)
        _require(len(constraints) == 1 and isinstance(constraints[0], dict)
            and isinstance(constraints[0].get("id"), str) and bool(constraints[0]["id"])
            and constraints[0] == response_envelope(constraints[0]["id"])
            and all(type(status) is int for status in constraints[0]["statusCodes"]))


def validate_config(config):
    _require(isinstance(config, dict)
        and set(config) == {"credentialBinding", "chain", "request", "response"})
    validate_chain(config["chain"])
    binding = config["credentialBinding"]
    _require(isinstance(binding, dict)
        and set(binding) == {"credentialType", "provider", "subjects", "secretClass"}
        and binding["credentialType"] == "static" and binding["provider"] == "operator-demo"
        and binding["secretClass"] == "bearerToken" and isinstance(binding["subjects"], list)
        and len(binding["subjects"]) == 1 and isinstance(binding["subjects"][0], str)
        and 1 <= len(binding["subjects"][0].encode("utf-8")) <= 512
        and binding["subjects"][0].strip() == binding["subjects"][0]
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in binding["subjects"][0])
        and config["request"] == request_profile()
        and type(config["request"]["maxBodyBytes"]) is int)
    validate_response_profile(config["response"])


def validate_authority(config, *, adapter, host, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    _require(adapter == ADAPTER and host == config["chain"] + ".g.alchemy.com"
        and bool(credential_ref) and not jit and methods == frozenset({"POST"})
        and tuple(paths) == tuple(route_paths(config["chain"])))
    validate_response_profile(config["response"], constraints)


def validate_route(route):
    _require(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def target_parts(url):
    _require(isinstance(url, str) and any(url == origin(chain) + "/v2" for chain in CHAINS))
    return urlsplit(url)


def is_json_content_type(value):
    return (isinstance(value, str) and value.isascii() and 0 < len(value) <= 8192
        and re.fullmatch(r"application/json(?:;[ \t]*charset=utf-8)?", value, re.I) is not None)


def validate_request_id(value):
    _require((type(value) is int and 0 <= value <= MAX_REQUEST_ID)
        or (type(value) is str and 1 <= len(value) <= 64
            and all(32 <= ord(character) <= 126 for character in value)))
    return value


def _document(body):
    # Local import avoids a contract/compiler import cycle. UTF-8, duplicate
    # keys, non-finite numbers and noncanonical integer zero use the shared guard.
    from catchplate.policy_bundle import strict_json_loads
    _require(isinstance(body, bytes) and 1 <= len(body) <= MAX_REQUEST_BODY_BYTES)
    try:
        return strict_json_loads(body)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("Alchemy RPC read contract refused") from None


def validate_request(method, url, body, *, chain, headers=None):
    validate_chain(chain)
    _require(method == "POST" and target_parts(url).netloc == host(chain))
    document = _document(body)
    _require(isinstance(document, dict) and set(document) == {"jsonrpc", "id", "method", "params"}
        and document["jsonrpc"] == "2.0" and isinstance(document["method"], str)
        and document["method"] in METHODS and document["params"] == [])
    request_id = validate_request_id(document["id"])
    if headers is not None:
        # Singleton, normalized fields follow the common physical framing guard.
        _require(isinstance(headers, dict) and is_json_content_type(headers.get("content-type")))
        if "accept" in headers:
            _require(headers["accept"] in {"application/json", "*/*"})
        for name, expected in (("accept-language", "*"), ("sec-fetch-mode", "cors")):
            _require(name not in headers or headers[name] == expected)
    return {"operation": OPERATION, "chain": chain, "method": document["method"], "requestId": request_id}


def validate_response(payload, *, status, request_id):
    """Inspect a previously bounded strict JSON value without rewriting bytes.

    Extra root fields and arbitrary result values are retained. An RPC error is
    an object with signed-64 integer code and string message; extra fields/data
    remain untouched. Non-200 HTTP errors need only a JSON object, not an ID.
    """
    _require(type(status) is int and status in STATUSES and isinstance(payload, dict))
    if status != 200:
        return
    validate_request_id(request_id)
    _require(payload.get("jsonrpc") == "2.0" and "id" in payload
        and type(payload["id"]) is type(request_id) and payload["id"] == request_id
        and (("result" in payload) != ("error" in payload)))
    if "error" in payload:
        error = payload["error"]
        _require(isinstance(error, dict) and type(error.get("code")) is int
            and -(1 << 63) <= error["code"] < (1 << 63)
            and isinstance(error.get("message"), str))
