"""Exact v2 route classifier, shared with the native signed-policy compiler.

This computes public data; it does not assert that a policy signature, native
load, or compiler-analysis permission has been verified. Those owners call it
only after their own admission. No request method/name heuristic is used.
"""
import copy
import hashlib
import math
import struct

PROFILE = "catchplate.compiledRouteAuthority/v1"
BUNDLE = "catchplate.policy/v2"
MAX_ROUTES, MAX_OPERATIONS, MAX_BYTES = 128, 128, 512 * 1024
CLASSES = frozenset({"read", "search", "write", "publish", "delete", "administrative"})
X_READ = frozenset({"accountActivity.read", "activity.read", "analytics.read", "bookmarks.read", "chat.read",
    "communities.read", "compliance.read", "connections.read", "directMessages.read", "insights.read", "lists.read",
    "media.read", "news.read", "notes.read", "schema.read", "search.read", "spaces.read", "streams.read",
    "trends.read", "tweets.read", "usage.read", "users.read", "webhooks.read"})
FIELDS = frozenset({"apiVersion", "genericOperations", "mappingSha256", "routeAuthorityRootSha256", "operationAuthorityRootSha256"})


def require(condition, message="compiled route authority is invalid"):
    if not condition:
        from catchplate.policy_bundle import PolicyBundleError
        raise PolicyBundleError(message)


def canonical(value):
    from catchplate.policy_bundle import canonical_json
    return ("catchplate.policyTypedCanonical/v1\0" + canonical_json(_transcript(value))).encode("ascii")


def _transcript(value):
    if isinstance(value, dict):
        require(all(type(key) is str for key in value))
        return ["object", [[key, _transcript(value[key])] for key in sorted(value)]]
    elif isinstance(value, (list, tuple)):
        return ["array", [_transcript(child) for child in value]]
    elif type(value) is int:
        require(-9_223_372_036_854_775_808 <= value <= 18_446_744_073_709_551_615)
        return ["integer", str(value)]
    elif type(value) is float:
        require(math.isfinite(value), "non-finite v2 policy number")
        return ["binary64", struct.pack(">d", value).hex()]
    elif type(value) is str:
        return ["string", value]
    elif type(value) is bool:
        return ["boolean", value]
    require(value is None)
    return ["null"]


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text_digest(value):
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 256)
    return value


def _declared(route):
    adapter, paths = route["adapter"], route["match"]["paths"]
    kind, config = adapter["type"], adapter["config"]
    if kind == "gmail.v1":
        names = {"gmail.message.get" if "{message_id}" in path else "gmail.messages.list" for path in paths}
    elif kind == "x.v2":
        names = {"tweets.write"} if config.get("mode") == "controlledWrite" else set(config["allowedReadOperations"])
    elif kind == "npm.registry":
        names = {"npm." + name for name in config["operations"]}
    elif kind == "npm.metadata.v1":
        names = {"npm.metadata.read"}
    elif kind == "npm.install.v1":
        from catchplate import npm_install
        try:
            npm_install.validate_authority(config, adapter=kind, host=route["match"].get("host"),
                credential_ref=route.get("credentialRef"), jit=route.get("jit"),
                methods=frozenset(route["match"].get("methods", [])), paths=paths,
                constraints=route.get("constraints", []))
        except (TypeError, ValueError):
            require(False)
        require(route["match"].get("scheme") == "https" and route["match"].get("host") == npm_install.HOST
            and type(route["match"].get("port")) is int and route["match"]["port"] == 443
            and route["match"].get("methods") == (["POST"] if config["mode"] == "audit" else ["GET"])
            and paths == npm_install.route_paths(config["mode"])
            and route.get("credentialHeader") == npm_install.REPLACEMENT
            and "jit" not in route and "responseObservation" not in route)
        names = {npm_install.OPERATIONS[config["mode"]]}
    elif kind == "npm.publish.v1":
        names = {"npm.publish"}
    elif kind == "x.app_read.v1":
        names = {"x.username.read"}
    elif kind == "x.post.v1":
        names = {"tweets.write"}
    elif kind == "alchemy.rpc_read.v1":
        names = {"alchemy.rpc.read"}
    else:
        require(kind == "generic.rest")
        names = {config["request"]["operation"]["name"]}
    require(0 < len(names) <= MAX_OPERATIONS)
    return kind, sorted(_text(name) for name in names)


def _builtin(kind, name):
    if kind == "gmail.v1":
        return {"gmail.message.get": "read", "gmail.messages.list": "search"}.get(name)
    if kind == "x.v2":
        if name == "tweets.write":
            return "write"
        return ("search" if name == "search.read" else "read") if name in X_READ else None
    if kind == "npm.registry":
        return {"npm.read": "read", "npm.publish": "publish", "npm.unpublish": "delete",
            "npm.distTagWrite": "write", "npm.metadataWrite": "write", "npm.tokenWrite": "administrative"}.get(name)
    if kind == "npm.metadata.v1":
        return "read" if name == "npm.metadata.read" else None
    if kind == "npm.install.v1":
        return "read" if name in {"npm.install.metadata.read", "npm.install.tarball.read", "npm.install.audit.read"} else None
    if kind == "npm.publish.v1":
        return "publish" if name == "npm.publish" else None
    if kind == "x.app_read.v1":
        return "read" if name == "x.username.read" else None
    if kind == "x.post.v1":
        return "write" if name == "tweets.write" else None
    if kind == "alchemy.rpc_read.v1":
        return "read" if name == "alchemy.rpc.read" else None
    return None


def compile_mapping(raw, declarations):
    """Pure complete recipe. Callers must separately admit the signed original."""
    require(type(raw) is dict and raw.get("apiVersion") == BUNDLE and type(declarations) is list
        and len(declarations) <= MAX_ROUTES)
    generic, previous = {}, None
    for value in declarations:
        require(type(value) is dict and set(value) == {"routeId", "operationName", "operation"})
        identity = (_text(value["routeId"]), _text(value["operationName"]))
        require((previous is None or previous < identity) and value["operation"] in CLASSES)
        previous, generic[identity] = identity, value["operation"]
    routes = raw.get("routes")
    require(type(routes) is list and 0 < len(routes) <= MAX_ROUTES)
    require(len(canonical(routes)) <= MAX_BYTES)
    principal_ids = [_text(item["id"]) for item in raw["principals"]]
    require(len(principal_ids) == len(set(principal_ids)))
    identity_pins = {"signedPrincipalsSha256": digest(raw["principals"]),
        "signedCredentialsSha256": digest(raw["credentials"]), "signedDefaultsSha256": digest(raw["defaults"])}
    profiles, entries, used, route_ids = [], [], set(), set()
    for route in sorted(routes, key=lambda value: value["id"]):
        route_id = _text(route["id"])
        require(route_id not in route_ids)
        route_ids.add(route_id)
        kind, names = _declared(route)
        operations = []
        for name in names:
            identity = (route_id, name)
            if kind == "generic.rest":
                require(identity in generic, "generic route needs its exact signed authority declaration")
                operation = generic[identity]
                used.add(identity)
            else:
                require(identity not in generic, "generic declaration cannot override a built-in classifier")
                operation = _builtin(kind, name)
                require(operation is not None, "built-in operation lacks a source-fixed classifier")
            operations.append({"operationName": name, "operation": operation,
                "requestAuthorityClass": "read" if operation in {"read", "search"} else "write"})
        members = route["principals"]
        require(type(members) is list and bool(members) and all(member == "*" or member in principal_ids for member in members))
        original = {"apiVersion": PROFILE, "routeSha256": text_digest(route_id), "signedRouteSha256": digest(route),
            "adapterType": kind, "operations": operations, **identity_pins,
            "principalSha256s": sorted(text_digest(member) for member in principal_ids if "*" in members or member in members)}
        profile_sha = digest(original)
        profiles.append({"routeId": route_id, "compiledSemanticProfileSha256": profile_sha, "profile": original})
        entries.extend({"routeSha256": original["routeSha256"], "compiledSemanticProfileSha256": profile_sha, **entry}
            for entry in operations)
    require(used == set(generic), "classification declarations do not exactly cover generic routes")
    require(len(entries) <= MAX_OPERATIONS, "classifier operation capacity exceeded")
    mapping = {"apiVersion": PROFILE, "profiles": profiles}
    require(len(canonical(mapping)) <= MAX_BYTES)
    route_root = digest({"apiVersion": "catchplate.compiledRouteAuthorityRoutes/v1", "profiles": profiles})
    operation_root = digest({"apiVersion": "catchplate.compiledRouteAuthorityOperations/v1", "operations": entries})
    return {"mapping": mapping, "mappingSha256": digest(mapping), "routeAuthorityRootSha256": route_root,
        "operationAuthorityRootSha256": operation_root}


def admit(raw):
    if raw.get("apiVersion") == "catchplate.policy/v1":
        require("routeAuthority" not in raw, "v1 has no route authority declaration profile")
        return None
    require(raw.get("apiVersion") == BUNDLE)
    canonical(raw)
    value = raw.get("routeAuthority")
    require(type(value) is dict and set(value) == FIELDS and value["apiVersion"] == PROFILE)
    compiled = compile_mapping(raw, value["genericOperations"])
    require(all(value[name] == compiled[name] for name in FIELDS - {"apiVersion", "genericOperations"}),
        "signed route classifier pin differs from exact compilation")
    return compiled


def prepare_unsigned(raw, generic_operations):
    """Explicit v2 producer, before the existing authorized policy signer.

    Never silently upgrade a signed v1 bundle or repair signed v2 pins.
    """
    require(type(raw) is dict and raw.get("apiVersion") == BUNDLE
        and "signature" not in raw.get("metadata", {}))
    value = copy.deepcopy(raw)
    compiled = compile_mapping(value, generic_operations)
    value["routeAuthority"] = {"apiVersion": PROFILE, "genericOperations": copy.deepcopy(generic_operations),
        **{name: compiled[name] for name in FIELDS - {"apiVersion", "genericOperations"}}}
    return value


def analysis_roots(active, candidate):
    """Exact pair roots to include in the separately authorized analysis."""
    require(active is not None and candidate is not None)
    return {name: digest({"apiVersion": domain, "active": active[name], "candidate": candidate[name]})
        for name, domain in (("routeAuthorityRootSha256", "catchplate.compiledRouteAuthorityPairRoutes/v1"),
            ("operationAuthorityRootSha256", "catchplate.compiledRouteAuthorityPairOperations/v1"))}


def binding_entry(compiled, binding):
    matches = [entry for entry in compiled["mapping"]["profiles"]
        if entry["profile"]["routeSha256"] == binding["routeSha256"]
        and entry["compiledSemanticProfileSha256"] == binding["compiledSemanticProfileSha256"]]
    require(len(matches) == 1)
    require(any(all(value[field] == binding[field] for field in ("operation", "requestAuthorityClass"))
        for value in matches[0]["profile"]["operations"]), "binding is not a compiled route operation")
    return matches[0]
