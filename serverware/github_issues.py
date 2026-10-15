"""Closed named-repository GitHub issues contract; no transport or credentials.

Only an explicit signed generic.rest bundle opts into githubRestV1. The shared
form parser preserves original query bytes; it does not grant route authority.
"""
from datetime import date, datetime
import re
from urllib.parse import urlsplit

from serverware.host_trusted_approval_policy import provider_constraints
from serverware.request_query_compat import parse_query


QUERY_MODE = "githubRestV1"
CONTENT_TYPE_POLICY = "githubJsonUtf8V1"
READ = "github_issues_read_v1"
WRITE = "github_issues_write_v1"
BUNDLES = frozenset({READ, WRITE})
ORIGIN = "https://api.github.com"
REPLACEMENT = {"mode": "replaceExact", "expectedValue": "token serverware-github-placeholder-v1"}
OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
NAME = r"[A-Za-z0-9_.-]{1,100}"
NUMBER = r"[1-9][0-9]{0,15}"
QUERY_KEYS = ["assignee", "creator", "direction", "labels", "mentioned", "milestone",
    "page", "per_page", "since", "sort", "state"]
RESPONSE_HEADERS = ["link", "retry-after", "x-github-request-id", "x-ratelimit-limit",
    "x-ratelimit-remaining", "x-ratelimit-reset", "x-ratelimit-resource", "x-ratelimit-used"]
STATUSES = [200, 201, 204, 400, 401, 403, 404, 409, 410, 415, 422, 429, 500, 502, 503, 504]


def _require(condition):
    if not condition:
        raise ValueError("GitHub issues contract refused")


def selected(config):
    if not isinstance(config, dict):
        return False
    request = config.get("request")
    return ("githubRepository" in config or "operationBundle" in config
        or isinstance(request, dict) and request.get("queryMode") == QUERY_MODE)


def validate_repository(value):
    _require(isinstance(value, dict) and set(value) == {"owner", "name"}
        and isinstance(value["owner"], str) and re.fullmatch(OWNER, value["owner"]) is not None
        and isinstance(value["name"], str) and re.fullmatch(NAME, value["name"]) is not None
        and value["name"] not in {".", ".."})


def route_paths(repository):
    validate_repository(repository)
    base = "/repos/" + repository["owner"] + "/" + repository["name"] + "/issues"
    return [base, base + "/{issue_number}", base + "/{issue_number}/comments",
        base + "/comments/{comment_id}"]


def request_profile(bundle):
    _require(isinstance(bundle, str) and bundle in BUNDLES)
    return {"allowedHeaders": ["accept", "accept-language", "sec-fetch-mode", "user-agent",
            "x-github-api-version"], "discardHeaders": ["accept-encoding"],
        "allowedQueryKeys": list(QUERY_KEYS), "allowedMediaTypes": ["application/json"],
        "bodyMode": "bufferedJsonPassthroughV1", "maxBodyBytes": 65536,
        "valueRules": [], "operation": {"name": "github.issues.read" if bundle == READ else "github.issues.write"},
        "queryMode": QUERY_MODE}


def response_profile():
    def profile(limit):
        return {"mode": "bufferedJsonOrEmpty204V2", "maxBodyBytes": limit, "bodyFormat": "json",
            "contentTypes": ["application/json"], "allowedHeaders": list(RESPONSE_HEADERS)}
    return {**profile(1048576), "error": {**profile(65536), "onInvalid": "block"}}


def response_envelope(identifier):
    rules = []
    for name in RESPONSE_HEADERS:
        pattern, maximum = ("^[ -~]{1,4096}$", 4096) if name == "link" else (
            ("^[0-9]{1,10}$", 10) if name == "retry-after" else (
            ("^[A-Za-z0-9:_-]{1,128}$", 128) if name == "x-github-request-id" else (
            ("^[A-Za-z0-9_-]{1,64}$", 64) if name == "x-ratelimit-resource" else ("^[0-9]{1,20}$", 20))))
        rules.append({"name": name, "required": False,
            "predicate": {"kind": "pattern", "pattern": pattern, "maxLength": maximum}})
    return {"id": identifier, "type": "responseEnvelope", "phase": "response",
        "bodyPresence": "jsonOrEmpty204V1", "unlistedHeaderPolicy": "discardUnselectedV1",
        "contentTypePolicy": CONTENT_TYPE_POLICY,
        "statusCodes": list(STATUSES), "contentTypes": ["application/json"],
        "allowedResponseHeaderNames": list(RESPONSE_HEADERS), "responseHeaderRules": rules}


def is_json_content_type(value):
    """The explicit GitHub envelope allows only a singleton UTF-8 JSON type."""
    return (isinstance(value, str) and value.isascii() and len(value) <= 8192
        and re.fullmatch(r"application/json(?:;[ \t]*charset=utf-8)?", value,
            flags=re.ASCII | re.IGNORECASE) is not None)


def validate_config(config):
    _require(isinstance(config, dict) and set(config) == {"credentialMode", "credentialBinding",
        "githubRepository", "operationBundle", "request", "response"})
    validate_repository(config["githubRepository"])
    binding = config["credentialBinding"]
    _require(config["credentialMode"] == "required" and isinstance(config["operationBundle"], str)
        and config["operationBundle"] in BUNDLES
        and isinstance(binding, dict) and set(binding) == {"credentialType", "provider", "subjects", "secretClass"}
        and binding["credentialType"] == "static" and binding["provider"] == "operator-demo"
        and binding["secretClass"] == "bearerToken" and isinstance(binding["subjects"], list)
        and len(binding["subjects"]) == 1 and isinstance(binding["subjects"][0], str)
        and 1 <= len(binding["subjects"][0]) <= 512
        and config["request"] == request_profile(config["operationBundle"])
        and config["response"] == response_profile())


def validate_authority(config, *, adapter, host, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    constraints = provider_constraints(constraints)
    _require(adapter == "generic.rest" and host == "api.github.com" and bool(credential_ref)
        and not jit and methods == frozenset({"GET"} if config["operationBundle"] == READ else {"GET", "POST"})
        and tuple(paths) == tuple(route_paths(config["githubRepository"]))
        and len(constraints) == 1 and isinstance(constraints[0], dict)
        and isinstance(constraints[0].get("id"), str) and bool(constraints[0]["id"])
        and constraints[0] == response_envelope(constraints[0]["id"]))


def validate_route(route):
    _require(route.scheme == "https" and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def _positive(value, maximum=9007199254740991):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,15}", value) is not None and int(value) <= maximum


def path_operation(path, repository, method):
    base = route_paths(repository)[0]
    if path == base:
        return "list" if method == "GET" else "create_issue" if method == "POST" else None
    match = re.fullmatch(re.escape(base) + r"/(" + NUMBER + r")(/comments)?", path)
    if match and _positive(match[1]):
        if match[2]:
            return "comments" if method == "GET" else "create_comment" if method == "POST" else None
        return "issue" if method == "GET" else None
    match = re.fullmatch(re.escape(base) + r"/comments/(" + NUMBER + r")", path)
    return "comment" if match and _positive(match[1]) and method == "GET" else None


def target_parts(url):
    _require(isinstance(url, str) and url.isascii() and len(url) <= 16384
        and url.startswith(ORIGIN + "/") and not any(ord(c) < 33 or ord(c) > 126 or c in "\\'" for c in url))
    base, separator, wire = url.partition("?")
    parts = urlsplit(url)
    match = re.fullmatch(r"/repos/(" + OWNER + r")/(" + NAME + r")(/issues(?:/.*)?)", parts.path)
    _require(parts.scheme == "https" and parts.netloc == "api.github.com" and not parts.fragment
        and match is not None and parts.path == base[len(ORIGIN):] and parts.query == wire)
    repository = {"owner": match[1], "name": match[2]}
    validate_repository(repository)
    _require(path_operation(parts.path, repository, "GET") is not None)
    parse_query(wire if separator else None)
    return parts


def _since(value):
    if len(value) > 64 or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})", value) is None:
        return False
    # fromisoformat accepts and normalizes some overflowing UTC offsets.
    # The provider contract instead requires actual RFC3339 field ranges.
    if int(value[17:19]) >= 60 or (value[-1] not in "Zz" and
            (int(value[-5:-3]) >= 24 or int(value[-2:]) >= 60)):
        return False
    try:
        datetime.fromisoformat(value.replace("t", "T").replace("z", "+00:00").replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def query_for(url, repository, method):
    parts = target_parts(url)
    operation = path_operation(parts.path, repository, method)
    _require(operation is not None)
    _, separator, wire = url.partition("?")
    query = parse_query(wire if separator else None)
    allowed = set(QUERY_KEYS) if operation == "list" else {"since", "page", "per_page"} if operation == "comments" else set()
    seen = set()
    for name, value in query.pairs:
        _require(name in allowed and name not in seen)
        seen.add(name)
        valid = {
            "page": lambda: _positive(value, 1000000), "per_page": lambda: _positive(value, 100),
            "state": lambda: value in {"open", "closed", "all"},
            "sort": lambda: value in {"created", "updated", "comments"},
            "direction": lambda: value in {"asc", "desc"}, "since": lambda: _since(value),
            "milestone": lambda: value in {"*", "none"} or _positive(value),
            "assignee": lambda: value in {"*", "none"} or re.fullmatch(OWNER, value) is not None,
            "creator": lambda: re.fullmatch(OWNER, value) is not None,
            "mentioned": lambda: re.fullmatch(OWNER, value) is not None,
            "labels": lambda: 1 <= len(value.encode("utf-8")) <= 1024,
        }[name]()
        _require(valid)
    return query


def validate_request(url, method, config, headers, body, parsed_body=None):
    validate_config(config)
    parts = target_parts(url)
    operation = path_operation(parts.path, config["githubRepository"], method)
    _require(operation is not None and (method == "GET" or config["operationBundle"] == WRITE))
    query_for(url, config["githubRepository"], method)
    _require(isinstance(body, bytes) and len(body) <= 65536)
    if method == "GET":
        _require(not body)
    else:
        field = "title" if operation == "create_issue" else "body"
        _require(isinstance(parsed_body, dict) and isinstance(parsed_body.get(field), str)
            and 1 <= len(parsed_body[field].encode("utf-8")) <= (1024 if field == "title" else 65536))
    if "accept" in headers:
        # go-github v74 Issues.ListByRepo uses this exact reactions preview;
        # it is not a wildcard allowance for other GitHub preview media types.
        _require(headers["accept"] in {"application/vnd.github.v3+json", "application/vnd.github+json",
            "application/vnd.github.squirrel-girl-preview", "application/json", "*/*"})
    for name, expected in (("accept-language", "*"), ("sec-fetch-mode", "cors")):
        _require(name not in headers or headers[name] == expected)
    if "x-github-api-version" in headers:
        value = headers["x-github-api-version"]
        _require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is not None)
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError("GitHub issues contract refused") from None


def normalize_link(value, *, url, method, repository):
    """Return only validated same-list named-repository pagination targets.

    A numeric upstream repository path is not an independently granted target
    or a repository-ID attestation. Client numeric paths remain forbidden.
    """
    _require(isinstance(value, str) and 1 <= len(value) <= 4096 and value.isascii())
    value = value.strip(" ")
    _require(bool(value))
    current = target_parts(url)
    _require(method == "GET" and path_operation(current.path, repository, method) in {"list", "comments"})
    prefix = "/repos/" + repository["owner"] + "/" + repository["name"]
    suffix = current.path[len(prefix):]
    result, relations, offset = [], set(), 0
    while offset < len(value):
        match = re.match(r'<([^<>]+)>; *rel="(next|prev|first|last)"', value[offset:])
        _require(match is not None and match[2] not in relations and len(result) < 4)
        target, relation = match[1], match[2]
        _require(target.startswith(ORIGIN + "/"))
        target_base, separator, wire = target.partition("?")
        target_path = target_base[len(ORIGIN):]
        if target_path != current.path:
            _require(re.fullmatch(r"/repositories/[1-9][0-9]{0,19}" + re.escape(suffix), target_path) is not None)
            target = ORIGIN + current.path + ("?" + wire if separator else "")
        query = query_for(target, repository, "GET")
        _require(any(name == "page" for name, _ in query.pairs))
        result.append('<' + target + '>; rel="' + relation + '"')
        relations.add(relation)
        offset += match.end()
        while offset < len(value) and value[offset] == " ":
            offset += 1
        if offset < len(value):
            separator_match = re.match(r", *", value[offset:])
            _require(separator_match is not None)
            offset += separator_match.end()
            _require(offset < len(value))
    normalized = ", ".join(result)
    _require(len(normalized) <= 4096)
    return normalized
